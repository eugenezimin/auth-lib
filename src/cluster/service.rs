//! Cluster service interface — what the host drives and what its inbound
//! controller calls.

use async_trait::async_trait;

use crate::cluster::model::{ClusterEnvelope, ClusterReport, NodeInfo, PeerState};
use crate::error::AuthError;

/// Membership, push delivery and repair between auth-lib instances.
///
/// ```text
/// host startup ──► AuthLib::start ──► ClusterService::start   (registry + Join)
/// every heartbeat ► AuthLib::tick ──► ClusterService::tick    (heartbeats, liveness, retries)
/// inbound request ──────────────────► ClusterService::receive (verify, apply, reply)
/// host shutdown ──► AuthLib::shutdown ► ClusterService::leave
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
