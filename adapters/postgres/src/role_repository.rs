//! PostgreSQL implementation of [`RoleRepository`] using `sqlx`.
//!
//! All SQL lives in [`crate::queries::role_queries`].

use async_trait::async_trait;
use auth_lib::AuthError;
use auth_lib::access::{NewRole, Role, RoleRepository};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::map_sqlx_error;
use crate::queries::role_queries;
use crate::rows::RoleRow;

/// PostgreSQL-backed role repository.
pub struct PgRoleRepository {
    pool: PgPool,
}

impl PgRoleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepository for PgRoleRepository {
    async fn create(&self, new_role: &NewRole) -> Result<Role, AuthError> {
        let row: RoleRow = sqlx::query_as(role_queries::INSERT_ROLE)
            .bind(&new_role.name)
            .bind(&new_role.description)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.into())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Role>, AuthError> {
        let row: Option<RoleRow> = sqlx::query_as(role_queries::FIND_ROLE_BY_ID)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(Into::into))
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<Role>, AuthError> {
        let row: Option<RoleRow> = sqlx::query_as(role_queries::FIND_ROLE_BY_NAME)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(Into::into))
    }

    async fn list_all(&self) -> Result<Vec<Role>, AuthError> {
        let rows: Vec<RoleRow> = sqlx::query_as(role_queries::LIST_ALL_ROLES)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete(&self, id: Uuid) -> Result<Option<Uuid>, AuthError> {
        let row: Option<(Uuid,)> = sqlx::query_as(role_queries::DELETE_ROLE)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(|(id,)| id))
    }

    async fn exists_by_name(&self, name: &str) -> Result<bool, AuthError> {
        let (exists,): (bool,) = sqlx::query_as(role_queries::EXISTS_BY_NAME)
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(exists)
    }
}
