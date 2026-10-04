//! Node registry port — the persisted state machine of cluster members.
//!
//! The registry is read once at startup and written **only when a node's
//! state changes** (see [`NodeTransition`]): a node registers, finishes
//! joining, leaves, misses a heartbeat, comes back, or expires.  Steady-state
//! heartbeats never touch it, and neither does token verification.

use async_trait::async_trait;
use uuid::Uuid;

use crate::cluster::model::{NodeInfo, NodeRecord, NodeState, NodeTransition};
use crate::error::AuthError;

#[async_trait]
pub trait NodeRepository: Send + Sync {
    /// A node starts: insert it (or reset its row) as `joining` / `online`.
    async fn register(&self, node: &NodeInfo) -> Result<(), AuthError>;

    /// A node heard again after being expired (or first heard through
    /// gossip): insert it as `state` / `online` unless it is already present
    /// and online.  Returns `true` if the row changed.
    async fn restore(&self, node: &NodeInfo, state: NodeState) -> Result<bool, AuthError>;

    /// Apply a guarded transition.  Returns `true` if this call changed the
    /// row, `false` if the guard did not match (already applied by another
    /// instance, or the node is gone).
    async fn transition(
        &self,
        node_id: Uuid,
        transition: NodeTransition,
    ) -> Result<bool, AuthError>;

    /// Every registered node.
    async fn list(&self) -> Result<Vec<NodeRecord>, AuthError>;
}
