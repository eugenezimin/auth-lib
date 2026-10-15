//! Node registry port — the persisted state machine of cluster members.
//!
//! The registry is read once at startup and written **only when a node's
//! state changes** (see [`NodeTransition`]): a node registers, finishes
//! joining, leaves, misses a heartbeat, comes back, or expires.  Steady-state
//! heartbeats never touch it, and neither does token verification.

use async_trait::async_trait;
use uuid::Uuid;

use crate::shared::model::{EvictOutcome, NodeInfo, NodeRecord, NodeState, NodeTransition};
use z_auth::utils::error::AuthError;

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

    // ── federation mode (one registry per cluster) ──────────────────────

    /// Mark `target` missing (heartbeat `missing`, id retired) unless it
    /// already is — but only while `observer` itself is not missing, in
    /// one atomic step.  The registry is the witness that decides which
    /// side of a split survives.
    async fn evict(&self, target: Uuid, observer: Uuid) -> Result<EvictOutcome, AuthError> {
        let _ = (target, observer);
        Err(unsupported("evict"))
    }

    /// A running node's advertised address changed.  Returns `true` if the
    /// row changed.
    async fn update_address(&self, node: &NodeInfo) -> Result<bool, AuthError> {
        let _ = node;
        Err(unsupported("update_address"))
    }

    /// Delete `missing` rows retired longer than `older_than`.
    async fn purge_retired(&self, older_than: std::time::Duration) -> Result<u64, AuthError> {
        let _ = older_than;
        Ok(0)
    }
}

fn unsupported(method: &str) -> AuthError {
    AuthError::Config(format!(
        "node repository does not support `{method}` (required in federation mode)"
    ))
}
