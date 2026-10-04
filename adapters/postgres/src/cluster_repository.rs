//! PostgreSQL implementations of the cluster ports: [`PgNodeRepository`]
//! (the registry instances read at startup) and [`PgKeyRepository`]
//! (published verifying keys).  All SQL lives in
//! [`crate::queries::cluster_queries`].

use async_trait::async_trait;
use auth_lib::AuthError;
use auth_lib::cluster::{NodeInfo, NodeRecord, NodeRepository, NodeState, NodeTransition};
use auth_lib::token::{KeyRepository, NewVerifyingKey, VerifyingKeyRecord};
use sqlx::PgPool;
use uuid::Uuid;

use crate::enums::PgNodeState;
use crate::errors::map_sqlx_error;
use crate::queries::cluster_queries as q;
use crate::rows::{KeyRow, NodeRow};

/// PostgreSQL-backed node registry — a guarded state machine (see
/// `migrations/0004_node_state_machine.sql`).
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
}

/// PostgreSQL-backed store of published verifying keys.
pub struct PgKeyRepository {
    pool: PgPool,
}

impl PgKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KeyRepository for PgKeyRepository {
    async fn publish(&self, key: &NewVerifyingKey) -> Result<VerifyingKeyRecord, AuthError> {
        let row: KeyRow = sqlx::query_as(q::PUBLISH_KEY)
            .bind(&key.kid)
            .bind(key.public_key.as_slice())
            .bind(key.published_by)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.try_into()
    }

    async fn revoke(&self, kid: &str) -> Result<Option<VerifyingKeyRecord>, AuthError> {
        let row: Option<KeyRow> = sqlx::query_as(q::REVOKE_KEY)
            .bind(kid)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list(&self) -> Result<Vec<VerifyingKeyRecord>, AuthError> {
        let rows: Vec<KeyRow> = sqlx::query_as(q::LIST_KEYS)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}
