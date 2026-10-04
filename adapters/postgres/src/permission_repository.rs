//! PostgreSQL implementation of [`PermissionRepository`] — the permission
//! catalog and user / role grants.  All SQL lives in
//! [`crate::queries::permission_queries`].
//!
//! Called by auth-lib only for admin operations, at startup (catalog load)
//! and at login / refresh (`effective_grants`) — never on token verification.

use async_trait::async_trait;
use auth_lib::AuthError;
use auth_lib::authorization::{
    EffectiveGrants, NewPermission, Permission, PermissionAssignment, PermissionCatalog,
    PermissionGrant, PermissionKind, PermissionRepository,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::enums::PgPermissionKind;
use crate::errors::map_sqlx_error;
use crate::queries::permission_queries as q;
use crate::rows::{GrantRow, OptionRow, PermissionRow};

/// PostgreSQL-backed permission repository.
pub struct PgPermissionRepository {
    pool: PgPool,
}

impl PgPermissionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Attach the options to a permission row.
    async fn with_options(
        &self,
        row: Option<PermissionRow>,
    ) -> Result<Option<Permission>, AuthError> {
        let Some(row) = row else {
            return Ok(None);
        };
        let options: Vec<OptionRow> = sqlx::query_as(q::LIST_OPTIONS_OF)
            .bind(row.id())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.assemble(&options).map(Some)
    }

    async fn require(&self, id: Uuid) -> Result<Permission, AuthError> {
        let row: Option<PermissionRow> = sqlx::query_as(q::FIND_PERMISSION_BY_ID)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        self.with_options(row)
            .await?
            .ok_or(AuthError::PermissionNotFound)
    }
}

/// Delete the owner's grant of a permission, then insert the new rows.
async fn replace_grant(
    tx: &mut Transaction<'_, Postgres>,
    delete: &str,
    insert: &str,
    owner: Uuid,
    assignment: &PermissionAssignment,
) -> Result<(), AuthError> {
    sqlx::query(delete)
        .bind(owner)
        .bind(assignment.permission_id)
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx_error)?;
    let option_ids: Vec<Option<Uuid>> = if assignment.option_ids.is_empty() {
        vec![None]
    } else {
        assignment.option_ids.iter().copied().map(Some).collect()
    };
    for option_id in option_ids {
        sqlx::query(insert)
            .bind(owner)
            .bind(assignment.permission_id)
            .bind(option_id)
            .bind(&assignment.text)
            .execute(&mut **tx)
            .await
            .map_err(map_sqlx_error)?;
    }
    Ok(())
}

#[async_trait]
impl PermissionRepository for PgPermissionRepository {
    async fn create(&self, permission: &NewPermission) -> Result<Permission, AuthError> {
        let (has_position, max_length) = match permission.kind {
            PermissionKind::Bool => (true, None),
            PermissionKind::Text { max_length } => (
                true,
                Some(i32::try_from(max_length).map_err(|_| {
                    AuthError::InvalidPermissionValue("max_length too large".into())
                })?),
            ),
            PermissionKind::Single | PermissionKind::Multi => (false, None),
        };

        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let (id,): (Uuid,) = sqlx::query_as(q::INSERT_PERMISSION)
            .bind(&permission.code)
            .bind(PgPermissionKind::from(permission.kind))
            .bind(&permission.description)
            .bind(has_position)
            .bind(max_length)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        for option in &permission.options {
            sqlx::query(q::INSERT_OPTION)
                .bind(id)
                .bind(option)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
        }
        tx.commit().await.map_err(map_sqlx_error)?;
        self.require(id).await
    }

    async fn add_option(
        &self,
        permission_id: Uuid,
        option_code: &str,
    ) -> Result<Permission, AuthError> {
        sqlx::query(q::INSERT_OPTION)
            .bind(permission_id)
            .bind(option_code)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        self.require(permission_id).await
    }

    async fn delete(&self, permission_id: Uuid) -> Result<bool, AuthError> {
        let result = sqlx::query(q::DELETE_PERMISSION)
            .bind(permission_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn find_by_code(&self, code: &str) -> Result<Option<Permission>, AuthError> {
        let row: Option<PermissionRow> = sqlx::query_as(q::FIND_PERMISSION_BY_CODE)
            .bind(code)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        self.with_options(row).await
    }

    async fn load_catalog(&self) -> Result<PermissionCatalog, AuthError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let rows: Vec<PermissionRow> = sqlx::query_as(q::LIST_PERMISSIONS)
            .fetch_all(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let options: Vec<OptionRow> = sqlx::query_as(q::LIST_OPTIONS)
            .fetch_all(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let (version,): (i64,) = sqlx::query_as(q::CATALOG_VERSION)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(PermissionCatalog {
            version: version as u64,
            permissions: rows
                .into_iter()
                .map(|r| r.assemble(&options))
                .collect::<Result<_, _>>()?,
        })
    }

    async fn replace_user_grant(
        &self,
        user_id: Uuid,
        assignment: &PermissionAssignment,
    ) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        replace_grant(
            &mut tx,
            q::DELETE_USER_GRANT,
            q::INSERT_USER_GRANT,
            user_id,
            assignment,
        )
        .await?;
        tx.commit().await.map_err(map_sqlx_error)
    }

    async fn clear_user_grant(
        &self,
        user_id: Uuid,
        permission_id: Uuid,
    ) -> Result<bool, AuthError> {
        let result = sqlx::query(q::DELETE_USER_GRANT)
            .bind(user_id)
            .bind(permission_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn replace_role_grant(
        &self,
        role_id: Uuid,
        assignment: &PermissionAssignment,
    ) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        replace_grant(
            &mut tx,
            q::DELETE_ROLE_GRANT,
            q::INSERT_ROLE_GRANT,
            role_id,
            assignment,
        )
        .await?;
        tx.commit().await.map_err(map_sqlx_error)
    }

    async fn clear_role_grant(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> Result<bool, AuthError> {
        let result = sqlx::query(q::DELETE_ROLE_GRANT)
            .bind(role_id)
            .bind(permission_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn effective_grants(
        &self,
        user_id: Uuid,
        include_role_grants: bool,
    ) -> Result<EffectiveGrants, AuthError> {
        let rows: Vec<GrantRow> = sqlx::query_as(q::EFFECTIVE_GRANTS)
            .bind(user_id)
            .bind(include_role_grants)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        let (version,): (i64,) = sqlx::query_as(q::CATALOG_VERSION)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(EffectiveGrants {
            catalog_version: version as u64,
            grants: rows
                .into_iter()
                .map(PermissionGrant::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}
