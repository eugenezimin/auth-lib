//! Cluster service interface — what the host drives and what its inbound
//! controller calls.

use async_trait::async_trait;

use crate::shared::model::{ClusterEnvelope, ClusterReport, NodeInfo, PeerState};
use z_auth::utils::error::AuthError;

/// Membership, push delivery and repair between z-auth instances.
///
/// ```text
/// host startup ──► ZAuth::start ──► ClusterService::start   (registry + Join)
/// every heartbeat ► ZAuth::tick ──► ClusterService::tick    (heartbeats, liveness, retries)
/// inbound request ──────────────────► ClusterService::receive (verify, apply, reply)
/// host shutdown ──► ZAuth::shutdown ► ClusterService::leave
/// ```
#[async_trait]
pub trait ClusterService: Send + Sync {
    /// This instance.
    fn local(&self) -> NodeInfo;

    /// Known peers and their liveness.  No I/O.
    fn peers(&self) -> Vec<PeerState>;

    /// Register in the node registry, load the other nodes, announce
    /// ourselves (`Join`) and merge their snapshots.
    async fn start(&self) -> Result<ClusterReport, AuthError>;

    /// One heartbeat round: liveness, heartbeats, retries, snapshot repair.
    async fn tick(&self) -> Result<ClusterReport, AuthError>;

    /// Handle an envelope the host's controller received; return the reply
    /// to send back, if any.  Rejects forged, stale, replayed and
    /// unknown-sender messages with [`AuthError::ClusterMessageRejected`].
    async fn receive(
        &self,
        envelope: ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError>;

    /// Tell the peers we are leaving and mark ourselves `left`.
    async fn leave(&self) -> Result<(), AuthError>;
}
