/// PostgreSQL implementation of [`UserRoleRepo`] using `sqlx`.
///
/// All SQL lives in [`crate::storage::queries::user_role_queries`].
use async_trait::async_trait;

use crate::interfaces::db::user_role_repo::UserRoleRepo;
use crate::model::user_role::UserRole;
use crate::storage::postgres::pg_pool::PgUserRoleRepo;
use crate::storage::queries::user_role_queries;
use crate::utils::errors::AuthError;

impl PgUserRoleRepo {
    pub(crate) fn new(pg_pool: sqlx::PgPool) -> Self {
        Self { pg_pool }
    }
}

#[async_trait]
impl UserRoleRepo for PgUserRoleRepo {
    async fn assign(&self, user_id: uuid::Uuid, role_id: uuid::Uuid) -> Result<bool, AuthError> {
        let row: Option<UserRole> = sqlx::query_as(user_role_queries::INSERT_USER_ROLE)
            .bind(user_id)
            .bind(role_id)
            .fetch_optional(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.is_some())
    }

    async fn revoke(&self, user_id: uuid::Uuid, role_id: uuid::Uuid) -> Result<bool, AuthError> {
        let row: Option<UserRole> = sqlx::query_as(user_role_queries::REVOKE_USER_ROLE)
            .bind(user_id)
            .bind(role_id)
            .fetch_optional(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.is_some())
    }

    async fn list_active_for_user(&self, user_id: uuid::Uuid) -> Result<Vec<UserRole>, AuthError> {
        let rows: Vec<UserRole> = sqlx::query_as(user_role_queries::LIST_ACTIVE_FOR_USER)
            .bind(user_id)
            .fetch_all(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(rows)
    }

    async fn list_all_for_user(&self, user_id: uuid::Uuid) -> Result<Vec<UserRole>, AuthError> {
        let rows: Vec<UserRole> = sqlx::query_as(user_role_queries::LIST_ALL_FOR_USER)
            .bind(user_id)
            .fetch_all(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(rows)
    }

    async fn is_role_active(
        &self,
        user_id: uuid::Uuid,
        role_id: uuid::Uuid,
    ) -> Result<bool, AuthError> {
        let (exists,): (bool,) = sqlx::query_as(user_role_queries::IS_ROLE_ACTIVE)
            .bind(user_id)
            .bind(role_id)
            .fetch_one(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(exists)
    }

    async fn revoke_all_for_user(&self, user_id: uuid::Uuid) -> Result<u64, AuthError> {
        let result = sqlx::query(user_role_queries::REVOKE_ALL_FOR_USER)
            .bind(user_id)
            .execute(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected())
    }
}

/// Map sqlx errors to domain [`AuthError`].
///
/// The `unique_user_role_active` partial index raises `23505` when a caller
/// tries to assign a role the user already holds actively.
fn map_sqlx_error(e: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.code().as_deref() == Some("23505") {
            let constraint = db_err.constraint().unwrap_or("");
            if constraint == "unique_user_role_active" {
                return AuthError::RoleAlreadyAssigned;
            }
        }
    }
    AuthError::DatabaseError(e.to_string())
}
