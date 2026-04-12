/// PostgreSQL implementation of [`UserRepo`] using `sqlx`.
///
/// All SQL lives in [`crate::storage::queries::user_queries`].
/// Each method uses the shared `PgPool` — sqlx handles connection
/// borrowing internally, no manual acquire/release needed.
///
/// Uses the non-macro `sqlx::query_as` API so no `DATABASE_URL` is
/// required at compile time.
use crate::interfaces::db::user_repo::UserRepo;
use crate::model::user::{NewUser, User};
use crate::storage::postgres::pg_pool::PgUserRepo;
use crate::storage::queries::user_queries;
use crate::utils::errors::AuthError;

impl PgUserRepo {
    pub fn new(pg_pool: sqlx::PgPool) -> Self {
        Self { pg_pool }
    }
}

#[async_trait::async_trait]
impl UserRepo for PgUserRepo {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let user: Option<User> = sqlx::query_as(user_queries::FIND_USER_BY_EMAIL)
            .bind(email)
            .fetch_optional(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(user)
    }

    async fn exists_by_email(&self, email: &str) -> Result<bool, AuthError> {
        let (exists,): (bool,) = sqlx::query_as(user_queries::EXISTS_BY_EMAIL)
            .bind(email)
            .fetch_one(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(exists)
    }

    async fn exists_by_username(&self, username: &str) -> Result<bool, AuthError> {
        let (exists,): (bool,) = sqlx::query_as(user_queries::EXISTS_BY_USERNAME)
            .bind(username)
            .fetch_one(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(exists)
    }

    async fn create(&self, new_user: NewUser) -> Result<User, AuthError> {
        let user = sqlx::query_as(user_queries::INSERT_USER)
            .bind(&new_user.email)
            .bind(&new_user.password_hash)
            .bind(&new_user.jwt_secret)
            .bind(&new_user.username)
            .bind(&new_user.first_name)
            .bind(&new_user.last_name)
            .fetch_one(&self.pg_pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(user)
    }
}

/// Map a sqlx error to a domain [`AuthError`].
///
/// For unique constraint violations (`23505`) we inspect the constraint name
/// to return a specific variant rather than a generic database error.
fn map_sqlx_error(e: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.code().as_deref() == Some("23505") {
            let constraint = db_err.constraint().unwrap_or("");
            return match constraint {
                "users_email" => AuthError::EmailAlreadyTaken,
                "users_username_key" => AuthError::UsernameAlreadyTaken,
                _ => AuthError::DatabaseError(e.to_string()),
            };
        }
    }
    AuthError::DatabaseError(e.to_string())
}
