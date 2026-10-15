# z-auth-cluster — optional clustering for z-auth

`z-auth` covers registration, login, logout, sessions, token issuing, verification, refresh and revocation through an in-memory denylist, and knows nothing about clusters. This crate adds them. The service application imports it and plugs a cluster into `ZAuth` through z-auth's `Extension` port.

Feature `shared` provides shared mode through `SharedCluster`. Every instance of every service uses one z-auth database, and the cluster pushes revocations (denylist changes), key events and catalog changes to all peers, repairing drift with digests and snapshots.

Feature `federation` (the default, implies `shared`) provides federation mode through `Federation`. Each service has its own database, the authority owns identity, every other service keeps a session store, and sessions, revocations and keys are synced between them.

`Cluster::new(settings, adapters)` picks the mode from `AUTH_DEPLOYMENT_MODE` instead of in code.

## Wiring

```rust
use std::sync::Arc;
use z_auth::{ZAuth, conf::config::{ConfigLoader, EnvLoader}};
use z_auth_cluster::{SharedCluster, config::{ClusterConfigLoader, ClusterEnvLoader}};

let cluster = Arc::new(SharedCluster::new(
    ClusterEnvLoader.load_settings()?,   // AUTH_CLUSTER_*, separate from z-auth's config
    transport,                           // your ClusterTransport (HTTP, gRPC, bus …)
    nodes,                               // NodeRepository, e.g. z_auth_postgres::PgNodeRepository
));
let auth = ZAuth::builder(EnvLoader.load_config()?, repos)
    .extension(cluster.clone())
    .build()?;

auth.start().await?;                 // joins the cluster
// every AUTH_CLUSTER_HEARTBEAT_MS:  auth.tick().await?;
// inbound cluster endpoint:         cluster.receive(envelope).await?;
// on shutdown:                      auth.shutdown().await?;   // leaves the cluster
```

Federation mode is wired the same way. Every service except the authority builds its repositories with the extension, which refuses identity writes with `AuthError::NotAuthority`.

```rust
use z_auth_cluster::{Federation, SessionRepositories};

let federation = Arc::new(
    Federation::new(settings, transport, nodes, sync_store).on_fenced(Arc::new(restart)),
);
let repos = if federation.is_authority() {
    z_auth_postgres::repositories(&pool)
} else {
    federation.session_store_repositories(SessionRepositories { sessions, revocations, keys })
};
let auth = ZAuth::builder(config, repos).extension(federation.clone()).build()?;
```

## What the extension uses in z-auth

The extension subscribes to z-auth's domain events, so new and enforced revocations (the denylist changes), published verifying keys, revoked signing keys and catalog changes are pushed to peers as they happen.

Changes from peers go straight into the shared in-memory denylist, key ring and catalog, so token verification stays I/O-free on every instance.

In federation mode it also wraps services. Session stores refuse logins and identity writes, read accounts from the authority's snapshots, and install a refresh gate that catches up on sessions not synced yet and refuses refreshes when the store is too stale. The authority republishes snapshots after every identity write. A fenced instance refuses to serve through z-auth's serving fence.

Each start and tick returns the cluster's report, read with `report.cluster()` from `ClusterReportExt`.

## Storage

The crate ships no database code. `z-auth-postgres` implements `NodeRepository` (feature `shared`) and `SyncStore` (feature `federation`), and keeps the `cluster_` tables in a separate migration set applied by `run_cluster_migrations` or `setup_db --cluster`.
