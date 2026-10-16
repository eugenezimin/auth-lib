//! PostgreSQL implementations of z-auth's [`ExternalIdentityRepository`]
//! and [`FlowStateRepository`].  All SQL lives in
//! [`external_queries`](super::external_queries).

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use z_auth::AuthError;
use z_auth::identity::external::{
    ExternalIdentity, ExternalIdentityRepository, NewExternalIdentity,
};
use z_auth::security::authentication::FlowStateRepository;

use super::external_queries as q;
use crate::errors::map_sqlx_error;

/// PostgreSQL-backed linked identities (see
/// `migrations_external/3001_external_identity_schema.sql`).
pub struct PgExternalIdentityRepository {
    pool: PgPool,
}

impl PgExternalIdentityRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct IdentityRow {
    id: Uuid,
    user_id: Uuid,
    provider: String,
    issuer: String,
    subject: String,
    email: Option<String>,
    created_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
}

impl From<IdentityRow> for ExternalIdentity {
    fn from(r: IdentityRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            provider: r.provider,
            issuer: r.issuer,
            subject: r.subject,
            email: r.email,
            created_at: r.created_at,
            last_login_at: r.last_login_at,
        }
    }
}

#[async_trait]
impl ExternalIdentityRepository for PgExternalIdentityRepository {
    async fn find_by_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<ExternalIdentity>, AuthError> {
        let row: Option<IdentityRow> = sqlx::query_as(q::FIND_BY_SUBJECT)
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(Into::into))
    }

    async fn find(&self, id: Uuid) -> Result<Option<ExternalIdentity>, AuthError> {
        let row: Option<IdentityRow> = sqlx::query_as(q::FIND)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(Into::into))
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>, AuthError> {
        let rows: Vec<IdentityRow> = sqlx::query_as(q::LIST_FOR_USER)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn create(&self, new: NewExternalIdentity) -> Result<ExternalIdentity, AuthError> {
        let row: IdentityRow = sqlx::query_as(q::INSERT)
            .bind(new.user_id)
            .bind(&new.provider)
            .bind(&new.issuer)
            .bind(&new.subject)
            .bind(&new.email)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.into())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, AuthError> {
        let result = sqlx::query(q::DELETE)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn record_login(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query(q::RECORD_LOGIN)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }
}

/// PostgreSQL-backed flow states (`security_flow_states`).
pub struct PgFlowStateRepository {
    pool: PgPool,
}

impl PgFlowStateRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FlowStateRepository for PgFlowStateRepository {
    async fn put(&self, key: &str, value: &str, ttl: Duration) -> Result<(), AuthError> {
        sqlx::query(q::FLOW_PUT)
            .bind(key)
            .bind(value)
            .bind(ttl)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn take(&self, key: &str) -> Result<Option<String>, AuthError> {
        let row: Option<(String, bool)> = sqlx::query_as(q::FLOW_TAKE)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.and_then(|(value, live)| live.then_some(value)))
    }

    async fn purge_expired(&self) -> Result<u64, AuthError> {
        let result = sqlx::query(q::FLOW_PURGE)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }
}
