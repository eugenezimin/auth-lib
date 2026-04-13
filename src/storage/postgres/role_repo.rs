/// PostgreSQL implementation of [`RoleRepo`] using `sqlx`.
///
/// All SQL lives in [`crate::storage::queries::role_queries`].
use async_trait::async_trait;

use crate::interfaces::db::role_repo::RoleRepo;
use crate::model::role::{NewRole, Role};
use crate::storage::postgres::pg_pool::PgRoleRepo;
use crate::storage::queries::role_queries;
use crate::utils::errors::AuthError;

impl PgRoleRepo {
    pub fn new(pg_pool: sqlx::PgPool) -> Self {
        Self { pg_pool }
    }
}

#[async_trait]
impl RoleRepo for PgRoleRepo {
    async fn create(&self, new_role: NewRole) -> Result<Role, AuthError> {
        let role = sqlx::query_as(role_queries::INSERT_ROLE)
            .bind(&new_role.name)
            .bind(&new_role.description)
            .fetch_one(&self.pg_pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(role)
    }

    async fn find_by_id(&self, id: uuid::Uuid) -> Result<Option<Role>, AuthError> {
        let role: Option<Role> = sqlx::query_as(role_queries::FIND_ROLE_BY_ID)
            .bind(id)
            .fetch_optional(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(role)
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<Role>, AuthError> {
        let role: Option<Role> = sqlx::query_as(role_queries::FIND_ROLE_BY_NAME)
            .bind(name)
            .fetch_optional(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(role)
    }

    async fn list_all(&self) -> Result<Vec<Role>, AuthError> {
        let roles: Vec<Role> = sqlx::query_as(role_queries::LIST_ALL_ROLES)
            .fetch_all(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(roles)
    }

    async fn delete(&self, id: uuid::Uuid) -> Result<bool, AuthError> {
        let result = sqlx::query(role_queries::DELETE_ROLE)
            .bind(id)
            .execute(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    async fn exists_by_name(&self, name: &str) -> Result<bool, AuthError> {
        let (exists,): (bool,) = sqlx::query_as(role_queries::EXISTS_BY_NAME)
            .bind(name)
            .fetch_one(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(exists)
    }
}

/// Map sqlx errors to domain [`AuthError`], translating the `roles_name_key`
/// unique constraint violation into a specific variant.
fn map_sqlx_error(e: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.code().as_deref() == Some("23505") {
            let constraint = db_err.constraint().unwrap_or("");
            return match constraint {
                "roles_name_key" => AuthError::DatabaseError(format!("role name already exists")),
                _ => AuthError::DatabaseError(e.to_string()),
            };
        }
    }
    AuthError::DatabaseError(e.to_string())
}
