//! Federation-mode membership: one cluster per service (instances sharing
//! that service's database), a full mesh inside each cluster, and a single
//! link per pair of clusters with retry, circuit breaker and failover.
//! Protocol: `docs/replication.md`.

mod breaker;
mod service;
mod state;

pub(crate) use service::FederationPublisher;
pub use service::{FederationClusterService, FenceHook};
pub(crate) use state::MeshState;

/// What the federation engine plugs into membership.
#[async_trait::async_trait]
pub(crate) trait SyncHooks: Send + Sync {
    /// This cluster's feed head, advertised in link heartbeats.
    async fn head(&self) -> Option<crate::shared::model::SyncHead>;
    /// The link owner learned another cluster's head: pull if behind.
    async fn on_remote(&self, cluster: &str, head: &crate::shared::model::SyncHead);
    /// A federation message from another cluster (or relayed by a sibling).
    async fn handle(
        &self,
        message: crate::sync::SyncMessage,
    ) -> Result<Option<crate::sync::SyncMessage>, z_auth::utils::error::AuthError>;
}
