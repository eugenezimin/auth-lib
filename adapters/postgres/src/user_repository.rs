//! PostgreSQL implementation of [`UserRepository`] using `sqlx`.
//!
//! All SQL lives in [`crate::queries::user_queries`].  Uses the non-macro
//! `sqlx::query_as` API so no `DATABASE_URL` is required at compile time.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;
use z_auth::AuthError;
use z_auth::identity::user::{
    NewUser, User, UserPage, UserQuery, UserRepository, UserUpdate, UserWithRoles,
};

use crate::errors::map_sqlx_error;
use crate::queries::user_queries;
use crate::rows::{UserRow, UserWithRoleRow, fold_user_with_roles};

/// PostgreSQL-backed user repository.
pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn exists(&self, sql: &str, value: &str) -> Result<bool, AuthError> {
        let (exists,): (bool,) = sqlx::query_as(sql)
            .bind(value)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(exists)
    }

    async fn set_flag(&self, sql: &str, user_id: Uuid) -> Result<bool, AuthError> {
        let result = sqlx::query(sql)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_flag(&self, sql: &str, user_id: Uuid) -> Result<Option<bool>, AuthError> {
        let row: Option<(bool,)> = sqlx::query_as(sql)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(|(v,)| v))
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, AuthError> {
        let row: Option<UserRow> = sqlx::query_as(user_queries::FIND_USER_BY_ID)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(Into::into))
    }
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row: Option<UserRow> = sqlx::query_as(user_queries::FIND_USER_BY_EMAIL)
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(Into::into))
    }
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError> {
        let row: Option<UserRow> = sqlx::query_as(user_queries::FIND_USER_BY_USERNAME)
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(Into::into))
    }

    async fn find_with_roles_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        let rows: Vec<UserWithRoleRow> = sqlx::query_as(user_queries::FIND_USER_WITH_ROLES_BY_ID)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(fold_user_with_roles(rows))
    }
    async fn find_with_roles_by_email(
        &self,
        email: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        let rows: Vec<UserWithRoleRow> =
            sqlx::query_as(user_queries::FIND_USER_WITH_ROLES_BY_EMAIL)
                .bind(email)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
        Ok(fold_user_with_roles(rows))
    }
    async fn find_with_roles_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        let rows: Vec<UserWithRoleRow> =
            sqlx::query_as(user_queries::FIND_USER_WITH_ROLES_BY_USERNAME)
                .bind(username)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
        Ok(fold_user_with_roles(rows))
    }

    async fn list(&self, query: &UserQuery) -> Result<UserPage, AuthError> {
        let rows: Vec<UserRow> = sqlx::query_as(user_queries::LIST_USERS)
            .bind(&query.search)
            .bind(i64::from(query.limit))
            .bind(i64::from(query.offset))
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        let (total,): (i64,) = sqlx::query_as(user_queries::COUNT_USERS)
            .bind(&query.search)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(UserPage {
            items: rows.into_iter().map(Into::into).collect(),
            total: total as u64,
        })
    }

    async fn exists_by_email(&self, email: &str) -> Result<bool, AuthError> {
        self.exists(user_queries::EXISTS_BY_EMAIL, email).await
    }
    async fn exists_by_username(&self, username: &str) -> Result<bool, AuthError> {
        self.exists(user_queries::EXISTS_BY_USERNAME, username)
            .await
    }

    async fn create(&self, new_user: NewUser) -> Result<User, AuthError> {
        let row: UserRow = sqlx::query_as(user_queries::INSERT_USER)
            .bind(&new_user.email)
            .bind(&new_user.password_hash)
            .bind(&new_user.username)
            .bind(&new_user.first_name)
            .bind(&new_user.last_name)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.into())
    }

    async fn update(&self, user_id: Uuid, update: UserUpdate) -> Result<Option<User>, AuthError> {
        let row: Option<UserRow> = sqlx::query_as(user_queries::UPDATE_USER)
            .bind(&update.email)
            .bind(&update.password_hash)
            .bind(&update.username)
            .bind(&update.first_name)
            .bind(&update.last_name)
            .bind(&update.avatar_url)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(Into::into))
    }

    async fn delete(&self, user_id: Uuid) -> Result<Option<Uuid>, AuthError> {
        let row: Option<(Uuid,)> = sqlx::query_as(user_queries::DELETE_USER)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(|(id,)| id))
    }

    async fn activate(&self, user_id: Uuid) -> Result<bool, AuthError> {
        self.set_flag(user_queries::ACTIVATE_USER, user_id).await
    }
    async fn deactivate(&self, user_id: Uuid) -> Result<bool, AuthError> {
        self.set_flag(user_queries::DEACTIVATE_USER, user_id).await
    }
    async fn is_active(&self, user_id: Uuid) -> Result<Option<bool>, AuthError> {
        self.get_flag(user_queries::GET_IS_ACTIVE, user_id).await
    }
    async fn is_verified(&self, user_id: Uuid) -> Result<Option<bool>, AuthError> {
        self.get_flag(user_queries::GET_IS_VERIFIED, user_id).await
    }
}
