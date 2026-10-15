//! Cluster ports for z-auth-cluster (features `shared` / `federation`):
//! the node registry ([`PgNodeRepository`]) and, in federation mode, the
//! change feed, snapshots and cursors ([`PgSyncStore`]).  Their tables are
//! created by [`CLUSTER_MIGRATOR`](crate::CLUSTER_MIGRATOR).

mod node_queries;
mod node_repository;
mod node_row;
#[cfg(feature = "federation")]
mod sync_queries;
#[cfg(feature = "federation")]
mod sync_store;

pub use node_repository::PgNodeRepository;
#[cfg(feature = "federation")]
pub use sync_store::PgSyncStore;
