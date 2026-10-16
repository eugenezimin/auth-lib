# Federation storage

In federation mode (`AUTH_DEPLOYMENT_MODE=federation`) every service runs its own z-auth cluster on its own database, and the clusters replicate sessions, revocations, verifying keys and the authority's account and catalog snapshots to each other. The protocol, the merge rules and the operational settings belong to z-auth-cluster and are described in [replication](../../cluster/docs/replication.md). This page covers the storage side as implemented by `z-auth-postgres` behind the `federation` feature, namely the two kinds of database, the session-store schema, the trigger-driven change feed, and the `PgSyncStore` and `PgNodeRepository` types that z-auth-cluster's `Federation` extension calls.

## Authority and session-store databases

Exactly one service is the authority (`AUTH_AUTHORITY_SERVICE`). It owns identity, which means users, password hashes, roles, grants and the permission catalog, and its database carries the full schema, the core set plus the cluster set, applied with `run_cluster_migrations`. It uses `repositories(&pool)` like any standalone deployment. Every other service only needs what a refresh, a logout or a token check needs. Its database carries the session-store schema from `migrations_session_store/`, applied with `run_session_store_migrations`, and its repositories are assembled by `Federation::session_store_repositories`, which takes the session, revocation and key repositories and fills the user, role and role-assignment slots with stand-ins that answer `AuthError::NotAuthority`, because identity belongs to the authority.

```mermaid
flowchart LR
    subgraph ums["authority service (for example ums)"]
        UA["ZAuth + Federation"]
        UD[("full schema: core + cluster sets")]
        UA --- UD
    end
    subgraph orders["orders service"]
        OA["ZAuth + Federation"]
        OD[("session-store schema in schema auth")]
        OA --- OD
    end
    subgraph billing["billing service"]
        BA["ZAuth + Federation"]
        BD[("session-store schema in schema auth")]
        BA --- BD
    end
    UA <-->|pull feed pages| OA
    UA <-->|pull feed pages| BA
    OA <-->|pull feed pages| BA
```

| Aspect | Authority | Session store |
|---|---|---|
| Migrations | `run_cluster_migrations` (core, then cluster) | `run_session_store_migrations` |
| Repositories | `repositories(&pool)` | `federation.session_store_repositories(SessionRepositories { ... })` |
| Identity, roles, grants, catalog | stored here | none, served by the authority and its snapshots |
| `PgPermissionRepository` | usually registered | not used |
| Account snapshot versions | drawn from `cluster_account_snapshot_version_seq` | received only |
| Sync store and node registry | `PgSyncStore`, `PgNodeRepository` | `PgSyncStore`, `PgNodeRepository` |
| z-auth-mfa tables | here, if mfa is used | never |

## Wiring

Both kinds of service build a `Federation` from the same four arguments, the cluster settings, the host's transport, a `PgNodeRepository` and a `PgSyncStore`, and register it as an extension. The code below follows the end-to-end test in `tests/federation.rs`; the transport is the host's own `ClusterTransport` implementation and appears as a parameter. The authority wires its database as follows.

```rust
use std::sync::Arc;

use z_auth::ZAuth;
use z_auth::conf::config::{ConfigLoader, EnvLoader};
use z_auth_cluster::Federation;
use z_auth_cluster::config::{ClusterConfigLoader, ClusterEnvLoader};
use z_auth_cluster::shared::ClusterTransport;
use z_auth_postgres::{
    PgConfig, PgNodeRepository, PgPermissionRepository, PgSyncStore, build_pg_pool,
    repositories, run_cluster_migrations,
};

async fn authority(
    transport: Arc<dyn ClusterTransport>,
) -> Result<(ZAuth, Arc<Federation>), Box<dyn std::error::Error>> {
    let pool = build_pg_pool(&PgConfig::from_env()?).await?;
    run_cluster_migrations(&pool).await?;
    let federation = Arc::new(Federation::new(
        ClusterEnvLoader.load_settings()?,
        transport,
        Arc::new(PgNodeRepository::new(pool.clone())),
        Arc::new(PgSyncStore::new(pool.clone())),
    ));
    let auth = ZAuth::builder(EnvLoader.load_config()?, repositories(&pool))
        .permissions(Arc::new(PgPermissionRepository::new(pool.clone())))
        .extension(federation.clone())
        .build()?;
    auth.start().await?;
    Ok((auth, federation))
}
```

A session-store service connects to its own schema (see the next section), installs the session-store set, and hands its session, revocation and key repositories to the federation, which returns the `Repositories` for the builder.

```rust
use std::sync::Arc;

use z_auth::ZAuth;
use z_auth::conf::config::{ConfigLoader, EnvLoader};
use z_auth_cluster::config::{ClusterConfigLoader, ClusterEnvLoader};
use z_auth_cluster::shared::ClusterTransport;
use z_auth_cluster::{Federation, SessionRepositories};
use z_auth_postgres::{
    PgKeyRepository, PgNodeRepository, PgRevocationRepository, PgSessionRepository,
    PgSyncStore, run_session_store_migrations,
};

async fn session_store(
    pool: sqlx::PgPool,
    transport: Arc<dyn ClusterTransport>,
) -> Result<(ZAuth, Arc<Federation>), Box<dyn std::error::Error>> {
    run_session_store_migrations(&pool).await?;
    let federation = Arc::new(Federation::new(
        ClusterEnvLoader.load_settings()?,
        transport,
        Arc::new(PgNodeRepository::new(pool.clone())),
        Arc::new(PgSyncStore::new(pool.clone())),
    ));
    let repos = federation.session_store_repositories(SessionRepositories {
        sessions: Arc::new(PgSessionRepository::new(pool.clone())),
        revocations: Arc::new(PgRevocationRepository::new(pool.clone())),
        keys: Arc::new(PgKeyRepository::new(pool.clone())),
    });
    let auth = ZAuth::builder(EnvLoader.load_config()?, repos)
        .extension(federation.clone())
        .build()?;
    auth.start().await?;
    Ok((auth, federation))
}
```

In both cases the host routes inbound envelopes to `federation.receive(envelope)` and calls `auth.tick()` every heartbeat; pulling the other clusters' feeds happens inside those ticks.

## The session-store schema

The session store holds only what a refresh needs. It has `security_sessions` with `security_session_generations` and `security_session_fork_aliases`, `security_token_revocations`, `security_verifying_keys`, the service's own `cluster_nodes`, the account and catalog snapshots published by the authority, and the change-feed tables, functions and triggers. The table and column definitions are copied from the authority's files, so the same repositories and the same `PgSyncStore` work on both, and the `amr` column arrives with the session store's own `0002_session_amr.sql`.

What it lacks is just as deliberate. There are no `identity_` tables, so no users, password hashes, roles or role assignments, and no permission catalog or grant tables. Consequently `security_sessions.user_id` has no foreign key; it names a user of the authority. The ENUM types `permission_kind`, `mfa_method`, `mfa_factor_status` and `mfa_totp_algorithm` do not exist, and neither does `cluster_account_snapshot_version_seq`, because only the authority hands out account versions. Calling `PgSyncStore::next_account_version()` on a session store therefore fails.

| Object | Authority | Session store |
|---|---|---|
| `identity_users`, `identity_roles`, `identity_role_assignments` | yes | no |
| `security_permissions`, options, user and role grants | yes | no |
| `security_sessions` | yes, `user_id` references `identity_users` | yes, `user_id` without a foreign key |
| `security_session_generations`, `security_session_fork_aliases` | yes | yes |
| `security_token_revocations`, `security_verifying_keys` | yes | yes |
| `cluster_nodes`, snapshots, feed, cursors, freshness | yes | yes |
| `cluster_account_snapshot_version_seq` | yes | no |
| `security_permission_position_seq` | yes | no |
| `mfa_` tables | with the mfa set | no |
| `identity_external_identities`, `security_flow_states` | with the external-identity set | no |

### Giving the session store its own schema

The session-store files do not qualify object names, so they create everything in the first schema of the connection's `search_path`, and so does `_sqlx_migrations`. Give the session store a schema of its own, for example `auth`, so its tables never collide with the host application's tables and its migration records never mix with another set's. The schema has to exist before the first connection uses it.

```sql
CREATE SCHEMA IF NOT EXISTS auth;
```

The `search_path` is then set as a startup option on every connection. The integration tests do it in `tests/helpers.rs` (`session_store_pool`) by extending the options from `pool::connect_options` with `.options([("search_path", schema)])`, which keeps the UTC time zone the adapter pins and adds `-c search_path=<schema>` next to it. A host can do the same and size the pool from `PgConfig`.

```rust
use sqlx::postgres::PgPoolOptions;
use z_auth_postgres::PgConfig;
use z_auth_postgres::pool::connect_options;

async fn session_store_pool(cfg: &PgConfig) -> Result<sqlx::PgPool, sqlx::Error> {
    let options = connect_options(&cfg.connection_url())?.options([("search_path", "auth")]);
    PgPoolOptions::new()
        .max_connections(cfg.max_pool_size)
        .acquire_timeout(cfg.connect_timeout)
        .connect_with(options)
        .await
}
```

The same effect can be had from a connection URL, because sqlx accepts the libpq `options` parameter, percent-encoded as `postgres://user:pass@host:5432/db?options=-c%20search_path%3Dauth`. `connect_options` appends its time-zone option to whatever the URL already carries. `build_pg_pool` itself cannot express the parameter, since `PgConfig` renders the URL without a query string.

## The change feed

Replication is pull-based. Each database keeps a feed of what changed in it, and remote clusters page through that feed. The feed is written by triggers in the same transaction as the data, so writes made directly in SQL are captured just like writes made through z-auth, and an entry can never exist for a change that rolled back.

`cluster_change_feed` holds one entry per synced record, not one per change. Its primary key is `(kind, key)`, and every new change of a record overwrites that record's entry with a fresh sequence number and transaction id. Reading the feed from the beginning therefore yields every record that currently exists (or was deleted) exactly once, which makes a full export and an incremental pull the same operation.

| Column | Type | Meaning |
|---|---|---|
| `kind` | `text` | Record kind, part of the wire format and independent of table names |
| `key` | `text` | Record key within its kind |
| `seq` | `bigint` | Value of `cluster_change_feed_seq` at the latest change, ordering entries within a transaction |
| `txid` | `xid8` | `pg_current_xact_id()` of the transaction that made the latest change |
| `changed_at` | `timestamptz` | `now()` at the latest change |

Two functions do the work. `cluster_feed_record(p_kind, p_key)` inserts the entry or, on conflict, updates `seq`, `txid` and `changed_at`. `cluster_feed_capture()` is the row trigger function; it returns at once unless `cluster_sync_site` has a row, otherwise it takes `NEW` (or `OLD` for a delete) and calls `cluster_feed_record` with the kind and key of the changed table. A trigger named `trg_feed_<table>` runs it after every insert, update and delete on each synced table.

| Trigger | Table | Kind | Key |
|---|---|---|---|
| `trg_feed_security_sessions` | `security_sessions` | `session` | `id` |
| `trg_feed_security_session_generations` | `security_session_generations` | `session` | `session_id` |
| `trg_feed_security_session_fork_aliases` | `security_session_fork_aliases` | `session` | `session_id` |
| `trg_feed_security_token_revocations` | `security_token_revocations` | `revocation` | `id` |
| `trg_feed_security_verifying_keys` | `security_verifying_keys` | `verifying_key` | `kid` |
| `trg_feed_cluster_account_snapshots` | `cluster_account_snapshots` | `account` | `user_id` |
| `trg_feed_cluster_catalog_snapshot` | `cluster_catalog_snapshot` | `catalog` | the constant `catalog` |

A session, its generations and its aliases all map to the same `session` entry, so a refresh rotation that touches three tables produces a single feed entry, and the reader ships the whole session aggregate. Identity tables and mfa tables have no trigger; account state reaches other clusters only through the authority's snapshots.

### Switching capture on

Capture is off until the database is first used in federation mode, so standalone and shared deployments pay only one `EXISTS` check per write on a tiny table. The switch is the row in `cluster_sync_site`. `PgSyncStore::site_id()` inserts it with a fresh random `site_id` (`INSERT ... ON CONFLICT (singleton) DO NOTHING RETURNING site_id`), and in the same transaction, only when the row was just created, runs `SEED_FEED`. That query enters every record that already exists into the feed, namely all sessions, the revocations that have not expired, all verifying keys, all account snapshots and the catalog snapshot, so a cluster that reads the feed from the start receives the complete state even though the data predates capture. Later calls just read the existing id. `changes_since` calls `site_id()` itself, so the first pull also switches capture on.

The site id identifies the database, not a process or a service, and it is what remote cursors are keyed by. It survives restarts and is shared by every instance on that database. Deleting the row switches capture off again, which is never needed in normal operation.

The sequence below follows one write from a service's repository to a remote cluster that pulls it.

```mermaid
sequenceDiagram
    participant Repo as PgSessionRepository
    participant DB as orders database
    participant Trg as trg_feed_security_sessions
    participant Feed as cluster_change_feed
    participant Store as PgSyncStore (orders)
    participant Remote as Federation at ums
    Repo->>DB: BEGIN, UPDATE security_sessions (rotate)
    DB->>Trg: AFTER UPDATE row trigger
    Trg->>Feed: cluster_feed_record('session', id) with seq and txid
    Repo->>DB: INSERT generation, trims (same entry updated)
    Repo->>DB: COMMIT
    Remote->>Store: changes_since(cursor, limit)
    Store->>Feed: entries after (txid, seq) with txid below the snapshot xmin
    Feed-->>Store: ('session', id), seq, txid
    Store->>DB: load_session(id) in REPEATABLE READ
    Store-->>Remote: ChangePage with the session aggregate and next cursor
    Remote->>Remote: merge, then store_session with the expected revision
    Remote->>Remote: advance_cursor(orders site, next)
```

## Reading the feed

A reader positions itself with a cursor, the pair `(txid, seq)` of the last entry it has processed. `CHANGES_SINCE` returns the entries strictly after the cursor in `(txid, seq)` order, up to a limit. `PgSyncStore::changes_since` asks for one row more than the limit to learn whether another page exists (`more`), and loads the current state of each returned record by kind and key. A record whose row no longer exists, such as a purged session, yields no record and is skipped, while the cursor still moves past it.

```sql
SELECT kind, key, seq, txid::text AS txid
FROM cluster_change_feed
WHERE (txid, seq) > ($1::text::xid8, $2)
  AND txid < pg_snapshot_xmin(pg_current_snapshot())
ORDER BY cluster_change_feed.txid, seq
LIMIT $3
```

The second condition is the safety bound that makes the feed correct under concurrency. Transaction ids are assigned when a transaction starts writing, but transactions commit in a different order. Without the bound, a reader could see the entry of a later transaction that already committed, advance its cursor past it, and never see the entry of an earlier transaction that commits a moment later with a smaller id. `pg_snapshot_xmin(pg_current_snapshot())` is the oldest transaction still running, so only entries from transactions older than every running one are served, and nothing that is still committing can be skipped. The integration test `test_a_change_still_committing_is_never_skipped` holds a transaction open and checks exactly this. `HEAD` applies the same bound to report the newest safe position.

The bound has an operational consequence. A long-running transaction anywhere in the database, even one that never touches z-auth tables, holds the feed back for as long as it stays open, and remote clusters see the database as lagging until it ends. Idle-in-transaction sessions are the usual culprit.

Two details of the query are deliberate. `txid` travels as text and is cast to `xid8` on the way in, because sqlx has no `xid8` codec; the cursor is parsed back into a `u64`. And `ORDER BY` names `cluster_change_feed.txid` explicitly, because a bare `txid` would refer to the text alias in the select list and sort `'999'` after `'1000'`; `test_feed_orders_transaction_ids_numerically` guards it.

## Cursors

`cluster_feed_cursors` stores how far this database has read each other site's feed, one row per remote `site_id` with `txid` (as `bigint`), `seq` and `updated_at`. Cursors live in the database rather than in a process, so every instance of a cluster shares them and a restart resumes where the cluster left off. A missing row means the default cursor, which reads the remote feed from the start.

Cursors only move forward. `ADVANCE_CURSOR` is an upsert whose update branch only fires when the stored pair is smaller than the new one, so a slow instance that finishes an old page after a faster one cannot move the cursor back and cause records to be skipped or reprocessed out of order.

```sql
INSERT INTO cluster_feed_cursors (site_id, txid, seq) VALUES ($1, $2, $3)
ON CONFLICT (site_id) DO UPDATE
SET txid = EXCLUDED.txid, seq = EXCLUDED.seq, updated_at = now()
WHERE (cluster_feed_cursors.txid, cluster_feed_cursors.seq) < (EXCLUDED.txid, EXCLUDED.seq)
```

`reset_cursor` deletes the row, so the next pull reads the whole remote feed again. It is part of the `SyncStore` port for resynchronising from scratch; the current z-auth-cluster code does not call it on its own, so it serves operators and tools.

## Applying remote changes

Applying a record must write nothing when nothing changes. That rule is what stops a change from bouncing between clusters forever, because every write fires the capture trigger and would put the record back into the local feed. Each apply method therefore either compares before writing or makes the write conditional, and reports `ApplyOutcome::Unchanged` when it did nothing.

Sessions are replaced as whole aggregates under a revision check. `load_session` reads the session, its generations and its aliases in one `REPEATABLE READ` transaction so the parts are consistent, and returns `merge_rev` as the revision. z-auth-cluster merges the local and remote aggregates and calls `store_session` with the revision it read. That method locks the row with `SELECT merge_rev ... FOR UPDATE`, returns `ApplyOutcome::Conflict` if the revision moved (a local refresh happened meanwhile, and the merge is retried), and otherwise updates or inserts the session, deletes its generations and aliases, and inserts the merged ones. On the authority, inserting a session whose user has been deleted violates the foreign key, and the method returns `ApplyOutcome::Dropped` rather than an error. The details are in [internals](internals.md#federation-merges).

Revocations and verifying keys are merged field by field under a row lock. `merge_revocation` locks the existing row, computes the merge (`enforced` wins, the earliest `enforced_at` with its `enforced_by`, the earliest `revoked_at`, the latest `expires_at`) with z-auth-cluster's `merge_revocation`, and writes only if the result differs. `merge_key` does the same with `merge_key`, where `revoked` wins. A concurrent insert of the same id is handled by retrying once.

Snapshots are applied by version. `APPLY_ACCOUNT` and `APPLY_CATALOG` are upserts whose update branch requires the stored version to be smaller than the incoming one, so an older snapshot never overwrites a newer one, and replaying a snapshot is a no-op.

## Snapshot versioning

Account snapshots carry a version that only the authority hands out. `PgSyncStore::next_account_version()`, which also backs the `SyncStore::next_version` port method, draws it from `cluster_account_snapshot_version_seq`. One sequence serves all users, so versions are monotonic per user as well as globally, and the version comparison in `APPLY_ACCOUNT` decides which snapshot is newer. The catalog snapshot is a single row whose version is the catalog's own version, which `PgPermissionRepository` computes as the highest permission or option position in use; since positions are never reused, adding a permission or an option always raises it. Deleting the entry that holds the highest position lowers it, and because `APPLY_CATALOG` only accepts a higher version, such a catalog is not stored as a new snapshot until a later addition raises the version again. Snapshots carry the account state and authorization claims (`authz` as `jsonb`) and the permission catalog (`catalog` as `jsonb`) that session stores need to issue tokens without an identity database.

## Freshness

`cluster_sync_freshness` records, per remote service, the moment this database last held everything that service had committed. The instance that owns the link to a service writes it with `record_caught_up`, and every instance's staleness guard reads it back with `caught_up_at`, which is how `AUTH_FEDERATION_MAX_STALENESS_SECS` can be enforced consistently across a cluster. The upsert keeps the later of the stored and the new time (`GREATEST`), so a report that arrives late cannot make the database look staler than it is.

## Node registry

Each cluster keeps its own instance registry in `cluster_nodes`, in its own database. `PgNodeRepository` implements z-auth-cluster's `NodeRepository` as a guarded state machine. Every transition is a single `UPDATE` or `DELETE` whose `WHERE` clause names the state it starts from, so when several instances observe the same event, exactly one changes the row and the others see zero rows affected. Steady-state heartbeats never write. In federation mode a missing instance is evicted, which sets `heartbeat` to `missing` and stamps `retired_at`, and the row is kept until `AUTH_CLUSTER_RETIRED_TTL_SECS` has passed so that the retired id cannot come back. Shared mode never uses `missing`. The queries, including the lock order that serialises two instances evicting each other, are listed in [internals](internals.md#node-registry-queries).

```mermaid
stateDiagram-v2
    state "lifecycle (state)" as L {
        [*] --> joining: register
        joining --> active: Activate
        joining --> leaving: BeginLeave
        active --> leaving: BeginLeave
        leaving --> [*]: Remove
    }
    state "liveness (heartbeat)" as H {
        [*] --> online
        online --> offline: MarkOffline
        offline --> online: MarkOnline or restore
        offline --> [*]: Expire
        online --> missing: evict
        offline --> missing: evict
        missing --> [*]: purge_retired
    }
```

## Cluster tables

The cluster tables have no foreign keys, neither among themselves nor to the core tables, because their rows describe processes and remote databases rather than local entities, and because snapshots may refer to users that exist only at the authority. The diagram therefore shows the tables side by side, with dotted lines for the logical links inside one database. `cluster_feed_cursors.site_id` refers to the `cluster_sync_site` row of a remote database, so it has no counterpart here.

```mermaid
erDiagram
    cluster_sync_site ||..o{ cluster_change_feed : "captures into"
    cluster_account_snapshots ||..o| cluster_change_feed : "kind account"
    cluster_catalog_snapshot ||..o| cluster_change_feed : "kind catalog"

    cluster_nodes {
        uuid id PK "node id per process start"
        varchar(100) service
        inet ip "ip or dns_name required"
        varchar(253) dns_name
        integer port "1 to 65535"
        varchar(32) version
        timestamptz started_at
        timestamptz created_at "now()"
        node_state state "default joining"
        heartbeat_status heartbeat "default online"
        timestamptz state_changed_at "now()"
        timestamptz heartbeat_changed_at "now()"
        timestamptz retired_at "evicted ids, federation"
    }

    cluster_account_snapshots {
        uuid user_id PK
        bigint version
        boolean is_active
        boolean deleted "default false"
        jsonb authz
        timestamptz created_at "now()"
        timestamptz updated_at "now()"
    }

    cluster_catalog_snapshot {
        boolean singleton PK "always true"
        bigint version
        jsonb catalog
        timestamptz created_at "now()"
        timestamptz updated_at "now()"
    }

    cluster_sync_site {
        boolean singleton PK "always true"
        uuid site_id "gen_random_uuid()"
        timestamptz created_at "now()"
    }

    cluster_change_feed {
        text kind PK
        text key PK
        bigint seq "cluster_change_feed_seq"
        xid8 txid "pg_current_xact_id()"
        timestamptz changed_at "now()"
    }

    cluster_feed_cursors {
        uuid site_id PK "a remote site"
        bigint txid
        bigint seq
        timestamptz updated_at "now()"
    }

    cluster_sync_freshness {
        varchar(100) service PK
        timestamptz caught_up_at
    }
```

## Housekeeping

The feed holds one entry per record that ever changed while capture was on, including deleted records, and the adapter contains no query that removes feed entries. Purged sessions and expired revocations therefore leave their entries behind, and readers skip them because the record no longer loads. The table grows with the number of distinct records rather than the number of changes, so it stays manageable, but on a long-lived database with heavy login traffic it is worth watching. Removing entries by hand is only safe for entries every remote cursor has already passed, since a reader that has not yet seen an entry would otherwise miss the deletion it stands for.
