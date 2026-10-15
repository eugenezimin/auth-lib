//! PostgreSQL implementation of the cluster's [`NodeRepository`]: the
//! registry instances read at startup.  All SQL lives in
//! [`node_queries`](super::node_queries).

use async_trait::async_trait;
use z_auth::AuthError;
use z_auth_cluster::shared::{
    EvictOutcome, NodeInfo, NodeRecord, NodeRepository, NodeState, NodeTransition,
};
use sqlx::PgPool;
use uuid::Uuid;

use super::node_queries as q;
use super::node_row::{NodeRow, PgHeartbeatStatus, PgNodeState};
use crate::errors::map_sqlx_error;

/// PostgreSQL-backed node registry — a guarded state machine (see
/// `migrations_cluster/1001_cluster_schema.sql`).
pub struct PgNodeRepository {
    pool: PgPool,
}

impl PgNodeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NodeRepository for PgNodeRepository {
    async fn register(&self, node: &NodeInfo) -> Result<(), AuthError> {
        sqlx::query(q::REGISTER_NODE)
            .bind(node.node_id)
            .bind(&node.service)
            .bind(node.ip)
            .bind(&node.dns_name)
            .bind(i32::from(node.port))
            .bind(&node.version)
            .bind(node.started_at)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn restore(&self, node: &NodeInfo, state: NodeState) -> Result<bool, AuthError> {
        let result = sqlx::query(q::RESTORE_NODE)
            .bind(node.node_id)
            .bind(&node.service)
            .bind(node.ip)
            .bind(&node.dns_name)
            .bind(i32::from(node.port))
            .bind(&node.version)
            .bind(PgNodeState::from(state))
            .bind(node.started_at)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn transition(
        &self,
        node_id: Uuid,
        transition: NodeTransition,
    ) -> Result<bool, AuthError> {
        let query = match transition {
            NodeTransition::Activate => q::ACTIVATE_NODE,
            NodeTransition::BeginLeave => q::BEGIN_LEAVE_NODE,
            NodeTransition::Remove => q::REMOVE_NODE,
            NodeTransition::MarkOffline => q::MARK_NODE_OFFLINE,
            NodeTransition::MarkOnline => q::MARK_NODE_ONLINE,
            NodeTransition::Expire => q::EXPIRE_NODE,
        };
        let result = sqlx::query(query)
            .bind(node_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list(&self) -> Result<Vec<NodeRecord>, AuthError> {
        let rows: Vec<NodeRow> = sqlx::query_as(q::LIST_NODES)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn evict(&self, target: Uuid, observer: Uuid) -> Result<EvictOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let rows: Vec<(Uuid, PgHeartbeatStatus)> = sqlx::query_as(q::LOCK_NODES_FOR_EVICTION)
            .bind(vec![target, observer])
            .fetch_all(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let status = |id| rows.iter().find(|(row, _)| *row == id).map(|(_, hb)| *hb);
        let outcome = match (status(observer), status(target)) {
            // Not registered (purged) or evicted: we lost.
            (None | Some(PgHeartbeatStatus::Missing), _) => EvictOutcome::ObserverMissing,
            (_, None | Some(PgHeartbeatStatus::Missing)) => EvictOutcome::AlreadyMissing,
            _ => {
                sqlx::query(q::EVICT_NODE)
                    .bind(target)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
                EvictOutcome::Evicted
            }
        };
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(outcome)
    }

    async fn update_address(&self, node: &NodeInfo) -> Result<bool, AuthError> {
        let result = sqlx::query(q::UPDATE_NODE_ADDRESS)
            .bind(node.node_id)
            .bind(node.ip)
            .bind(&node.dns_name)
            .bind(i32::from(node.port))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn purge_retired(&self, older_than: std::time::Duration) -> Result<u64, AuthError> {
        let result = sqlx::query(q::PURGE_RETIRED_NODES)
            .bind(older_than.as_secs_f64())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }
}
