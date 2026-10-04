# Cluster sync between auth-lib instances

Every service that embeds auth-lib is an **instance**. Instances know each
other (identity, address, liveness) and **push** every change that affects
tokens already in flight: revocations, key events and catalog changes. Each
instance keeps the replicated state **in memory**, so token verification
never touches the database.

auth-lib ships **no client and no server**. As with storage, the library
defines the models, the DTOs and the methods; the host chooses the wire:

| Side | Provided by | auth-lib API |
|---|---|---|
| Outbound | host: any HTTP / gRPC / bus client | implement `cluster::ClusterTransport` |
| Inbound | host: its own endpoint / handler | call `auth.cluster().receive(envelope)` and return the reply |
| Registry | adapter (e.g. `PgNodeRepository`) | implement `cluster::NodeRepository` |
| Lifecycle | host runtime | `auth.start()`, `auth.tick()` every heartbeat, `auth.shutdown()` |

The harness (`auth-lib-harness/src/cluster_http.rs`) is a complete
reference: a `reqwest` transport plus an Actix controller at
`POST /internal/cluster`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_CLUSTER_SECRET` | — | base64, ≥ 32 bytes, shared by every instance. Required to join. |
| `AUTH_CLUSTER_SERVICE` | `auth-lib` | service name advertised to peers |
| `AUTH_CLUSTER_ADVERTISE_IP` / `_DNS` | — | how peers reach this instance (at least one) |
| `AUTH_CLUSTER_ADVERTISE_PORT` | — | port of the inbound endpoint |
| `AUTH_CLUSTER_HEARTBEAT_MS` | 2000 | heartbeat interval; call `auth.tick()` this often |
| `AUTH_CLUSTER_OFFLINE_AFTER` | 1 | missed heartbeats before a peer is marked `offline` |
| `AUTH_CLUSTER_REMOVE_AFTER` | 1 | further missed heartbeats before an offline peer is deleted |
| `AUTH_CLUSTER_TOMBSTONE_SECS` | 1800 | how long a deleted peer is remembered and probed (so it can rejoin) |
| `AUTH_CLUSTER_MAX_SKEW_SECS` | 30 | accepted clock difference on incoming messages |

Wire it up with `AuthLib::builder(config, repos).cluster(transport, nodes)`; `repos` (`Repositories`) includes the `keys` repository.
Without `.cluster(…)` the instance runs **standalone**: everything below
still works locally, and nothing is sent.

## Lifecycle

```text
start()   register (joining / online) ─ load nodes, active revocations, keys (once)
          ─ send Join to every registered node ─ merge their snapshots ─ joining → active
          ─ publish this instance's verifying key
tick()    enforce revocations whose tokens were presented ─ prune expired entries
          ─ liveness (online → offline → deleted) ─ send heartbeats (+ probe deleted peers)
          ─ retry failed deliveries ─ request snapshots from peers whose digest differs
receive() verify ─ apply ─ reply
leave()   → leaving ─ send Leave to everyone ─ delete own row   (via shutdown())
```

## Messages

Everything travels in a `ClusterEnvelope`:

```json
{
  "message_id": "6f0e…", "from": "1c2b…", "sent_at": "2026-10-03T12:00:00Z",
  "payload": { "type": "event", "data": { "type": "revoked", "data": { …Revocation… } } },
  "mac": "base64url HMAC-SHA256"
}
```

| `payload.type` | Sent | Reply |
|---|---|---|
| `join` (`NodeInfo`) | at start, to every registered node | `snapshot` |
| `heartbeat` (`info`, `members`, `digest`) | every tick, to every peer | — |
| `event` (`DomainEvent`) | immediately, to every current peer (online or offline) | — |
| `snapshot_request` | when a heartbeat digest differs (rate-limited) | `snapshot` |
| `snapshot` (`revocations`, `keys`, `catalog_version`) | as a reply | — |
| `leave` | on graceful shutdown | — |

`DomainEvent` is one of `revoked`, `revocation_enforced`,
`verifying_key_published`, `signing_key_revoked` or `catalog_changed`.

### Authentication

`mac` = base64url(HMAC-SHA256(`AUTH_CLUSTER_SECRET`, JSON of
`{message_id, from, sent_at, payload}`)). `receive()` rejects a message with
`AuthError::ClusterMessageRejected` (401 `cluster_message_rejected`) when:
- the MAC is wrong or missing;
- the message is from this very instance;
- `sent_at` is outside ±`MAX_SKEW_SECS`;
- `message_id` was already seen (replay);
- it comes from an unknown sender. `join` and `heartbeat` introduce senders;
  other types require a known one.

Replies are signed by the peer and verified the same way. The secret proves
cluster membership whatever the transport, so mTLS is optional defence in
depth.

## Revocation procedure

1. **Revoke** (any instance): the session ends in the database immediately,
   so refresh fails everywhere. A **`pending`** revocation is stored and
   added to the in-memory denylist, then pushed (`revoked`) to every peer.
2. **Block**: every instance rejects covered tokens at once (401
   `token_revoked`), using memory only.
3. **Enforce**: an instance that sees a covered token in use records a hit.
   On its next `tick()` it:
   - flips the revocation to **`enforced`** with a compare-and-swap, so
     exactly one instance wins;
   - marks the session **`compromised`** (`revoked_token_used`);
   - pushes `revocation_enforced`.

Logout, logout-all, session-cap eviction, refresh-policy compromises (token
reuse, IP mismatch) and user lifecycle events (password change,
deactivation, deletion) all use this path.

## Keys

- **Distribution**: `start()` publishes the instance's own verifying key.
  `auth.keys().publish_verifying_key(pk)` publishes any other key. Peers add
  it to their `KeyRing`, so tokens signed with the matching private key are
  accepted everywhere without a restart.
- **Revocation**: `auth.keys().revoke_signing_key(kid)`. Every instance
  rejects tokens with that `kid` immediately (`invalid_token: signing key
  revoked`), and the issuing instance refuses to mint with it.
- Only **public** keys are stored (`verifying_keys`) or sent.

## Catalog

Catalog writes (`define`, `add_option`, `delete`) push `catalog_changed {
version }`. A peer whose cached catalog is older reloads it once from the
store.

## Membership and liveness — the registry state machine

`cluster_nodes` keeps two independent dimensions per node. Each one is
changed **only by its events**: steady-state heartbeats never write.

```text
state      (start) ─► joining ─activate─► active ─begin_leave─► leaving ─remove─► (deleted)
heartbeat  online ─missed OFFLINE_AFTER─► offline ─missed REMOVE_AFTER more─► (deleted)
              ▲                               │
              └────────── heard again ────────┘
```

| Event | Change | Who writes |
|---|---|---|
| Instance starts | insert or reset its row: `joining` / `online` | itself |
| Join round finished | `joining → active` | itself |
| A heartbeat missed (`OFFLINE_AFTER`, default 1) | `online → offline` | every observer tries; the guarded update changes the row once |
| Heard again before the next one | `offline → online` | every observer tries; once |
| Still silent (`REMOVE_AFTER` more, default 1) | row deleted | every observer tries; once |
| A deleted or unknown node is heard | re-inserted as `online` | the first observer that hears it (a no-op for the rest) |
| Graceful shutdown | `→ leaving`, Leave sent, row deleted | itself |

Notes on timing and recovery:
- **When a heartbeat counts as missed:** half an interval after it was due.
  With the 2 s default, a crashed node is `offline` about 3 s after its last
  heartbeat and deleted about 5 s after it.
- **Each write is guarded** by the state it starts from (`… WHERE heartbeat =
  'online'`, `… WHERE state = 'joining'`), so concurrent observers can't
  double-apply a change.
- **Deleted peers become in-memory tombstones.** They are still probed every
  few heartbeats for `TOMBSTONE_SECS`, so two instances that lost contact (and
  deleted each other) reconnect by themselves once the network heals.
- **Stale rows clean themselves up.** Rows of crashed processes go offline,
  then get deleted by the first instance that observes them.
- **Gossip:** heartbeats carry the members the sender sees online, so nodes
  the registry missed are discovered.

## Delivery guarantees

- **Push** is immediate and concurrent to all peers.
- **Retry**: failed deliveries go to an in-memory outbox and are retried on
  the next ticks, up to 5 attempts.
- **Repair (anti-entropy)**: every heartbeat carries a digest of the
  revocations, keys and catalog version. A peer with a different digest asks
  for a snapshot and merges it. Revocations take the union, with `enforced`
  winning; keys take the union, with `revoked` winning; the newer catalog
  version wins. This covers anything retries missed, without the database.
- **Restart**: a starting instance loads the active state from the store,
  and its `join` replies add anything newer.

## Database touch points

| Activity | Database |
|---|---|
| Token verification, authorization checks, heartbeats, receiving pushes | **none** |
| `start()` | register; read nodes, active revocations, keys |
| Revoke, enforce, key publish/revoke | the write that records the change |
| Catalog change received | one catalog reload (only if newer) |
| Node state changes (start, joined, missed heartbeat, back online, expired, left) | one guarded registry write per change |
