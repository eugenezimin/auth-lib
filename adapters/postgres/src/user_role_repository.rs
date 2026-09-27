//! PostgreSQL implementation of [`UserRoleRepository`] using `sqlx`.
//!
//! All SQL lives in [`crate::queries::user_role_queries`].

use async_trait::async_trait;
use auth_lib::AuthError;
use auth_lib::access::{UserRole, UserRoleRepository};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::map_sqlx_error;
use crate::queries::user_role_queries;
use crate::rows::UserRoleRow;

/// PostgreSQL-backed user → role assignment repository.
pub struct PgUserRoleRepository {
    pool: PgPool,
}

impl PgUserRoleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn list(&self, sql: &str, user_id: Uuid) -> Result<Vec<UserRole>, AuthError> {
        let rows: Vec<UserRoleRow> = sqlx::query_as(sql)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

#[async_trait]
impl UserRoleRepository for PgUserRoleRepository {
    async fn assign(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        // `ON CONFLICT DO NOTHING` → no row returned when the user already
        // holds the role actively (partial unique index).
        let row: Option<UserRoleRow> = sqlx::query_as(user_role_queries::INSERT_USER_ROLE)
            .bind(user_id)
            .bind(role_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.is_some())
    }

    async fn revoke(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        let row: Option<UserRoleRow> = sqlx::query_as(user_role_queries::REVOKE_USER_ROLE)
            .bind(user_id)
            .bind(role_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.is_some())
    }

    async fn is_role_active(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        let (exists,): (bool,) = sqlx::query_as(user_role_queries::IS_ROLE_ACTIVE)
            .bind(user_id)
            .bind(role_id)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(exists)
    }

    async fn list_active_for_user(&self, user_id: Uuid) -> Result<Vec<UserRole>, AuthError> {
        self.list(user_role_queries::LIST_ACTIVE_FOR_USER, user_id)
            .await
    }

    async fn list_all_for_user(&self, user_id: Uuid) -> Result<Vec<UserRole>, AuthError> {
        self.list(user_role_queries::LIST_ALL_FOR_USER, user_id)
            .await
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64, AuthError> {
        let result = sqlx::query(user_role_queries::REVOKE_ALL_FOR_USER)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }
}
