//! Cluster transport port — implemented by the host with any client
//! (HTTP, gRPC, a message bus …).  auth-lib never opens a connection itself.
//!
//! The matching inbound side is the host's own endpoint, which passes what
//! it receives to [`ClusterService::receive`](crate::cluster::ClusterService::receive)
//! and returns its reply.

use async_trait::async_trait;

use crate::cluster::model::{ClusterEnvelope, NodeInfo};
use crate::error::AuthError;

#[async_trait]
pub trait ClusterTransport: Send + Sync {
    /// Deliver `envelope` to `to` (reach it at `to.host()`:`to.port`) and
    /// return the peer's reply, if any.  Use a short timeout; return
    /// [`AuthError::ClusterUnreachable`] on failure — auth-lib retries and
    /// repairs on its own.
    async fn send(
        &self,
        to: &NodeInfo,
        envelope: &ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError>;
}
