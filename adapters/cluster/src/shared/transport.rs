//! Cluster transport port — implemented by the host with any client
//! (HTTP, gRPC, a message bus …).  z-auth never opens a connection itself.
//!
//! The matching inbound side is the host's own endpoint, which passes what
//! it receives to [`ClusterService::receive`](crate::shared::ClusterService::receive)
//! and returns its reply.

use async_trait::async_trait;

use std::time::Duration;

use crate::shared::model::{ClusterEnvelope, NodeInfo};
use z_auth::utils::error::AuthError;

#[async_trait]
pub trait ClusterTransport: Send + Sync {
    /// Deliver `envelope` to `to` (reach it at `to.host()`:`to.port`) and
    /// return the peer's reply, if any.  Use a short timeout; return
    /// [`AuthError::ClusterUnreachable`] on failure — z-auth retries and
    /// repairs on its own.
    ///
    /// In federation mode `to.node_id` is nil when a seed is probed by
    /// address: only `to.host()` and `to.port` are meaningful then.
    async fn send(
        &self,
        to: &NodeInfo,
        envelope: &ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError>;
}

/// Waits between retries of an inter-cluster request (federation mode).
/// z-auth has no runtime of its own: the host passes one, e.g.
/// `tokio::time::sleep`.  Without it retries follow each other at once.
#[async_trait]
pub trait Delay: Send + Sync {
    async fn sleep(&self, duration: Duration);
}

/// Retries without waiting.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDelay;

#[async_trait]
impl Delay for NoDelay {
    async fn sleep(&self, _duration: Duration) {}
}
