/// PostgreSQL implementation of [`UserRepo`].
///
/// All SQL lives here — the service layer never sees a query string.
/// Each method borrows one connection from the pool, executes a single
/// prepared statement, and releases the connection back to the pool.
use async_trait::async_trait;
use deadpool_postgres::Pool;
use tokio_postgres::Row;

use crate::interfaces::storage::user_repo::UserRepo;
use crate::model::storage::postgres::PgUserRepo;
use crate::model::user::{NewUser, User};
use crate::utils::errors::AuthError;

impl PgUserRepo {
    pub fn new(pg_pool: Pool) -> Self {
        Self { pg_pool }
    }
}

#[async_trait]
impl UserRepo for PgUserRepo {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let client = get_client(&self.pg_pool).await?;

        let row = client
            .query_opt(
                "SELECT id, email, password_hash, jwt_secret, username,
                        first_name, last_name, avatar_url,
                        is_active, is_verified, created_at, updated_at
                   FROM users
                  WHERE email = $1",
                &[&email],
            )
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(row_to_user))
    }

    async fn exists_by_email(&self, email: &str) -> Result<bool, AuthError> {
        let client = get_client(&self.pg_pool).await?;

        let row = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
                &[&email],
            )
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.get(0))
    }

    async fn exists_by_username(&self, username: &str) -> Result<bool, AuthError> {
        let client = get_client(&self.pg_pool).await?;

        let row = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
                &[&username],
            )
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.get(0))
    }

    async fn create(&self, new_user: NewUser) -> Result<User, AuthError> {
        let client = get_client(&self.pg_pool).await?;

        // Pass Option<String> directly — tokio-postgres maps None to NULL.
        let row = client
            .query_one(
                "INSERT INTO users
                    (email, password_hash, jwt_secret, username,
                     first_name, last_name)
                 VALUES
                    ($1, $2, $3, $4, $5, $6)
                 RETURNING
                    id, email, password_hash, jwt_secret, username,
                    first_name, last_name, avatar_url,
                    is_active, is_verified, created_at, updated_at",
                &[
                    &new_user.email,
                    &new_user.password_hash,
                    &new_user.jwt_secret,
                    &new_user.username,
                    &new_user.first_name,
                    &new_user.last_name,
                ],
            )
            .await
            .map_err(pg_insert_error)?;

        Ok(row_to_user(row))
    }
}

/// Borrow a connection from the pool, converting pool errors to [`AuthError`].
async fn get_client(pool: &Pool) -> Result<deadpool_postgres::Client, AuthError> {
    pool.get()
        .await
        .map_err(|e| AuthError::DatabaseError(format!("connection pool error: {e}")))
}

/// Convert a `tokio-postgres` INSERT error into the appropriate [`AuthError`].
///
/// `tokio-postgres` wraps the underlying `DbError` as the error's *source*,
/// so `e.to_string()` only ever yields the generic `"db error"` string.
/// We must walk the `std::error::Error::source()` chain to reach the
/// `tokio_postgres::error::DbError` which carries the constraint name and
/// `SqlState` code (23505 = unique_violation).
fn pg_insert_error(e: tokio_postgres::Error) -> AuthError {
    use std::error::Error as StdError;

    // Collect every message in the source chain into one string to search.
    let mut full = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        full.push(' ');
        full.push_str(&s.to_string());
        source = s.source();
    }
    let lower = full.to_lowercase();

    if lower.contains("users_email") || (lower.contains("unique") && lower.contains("email")) {
        AuthError::EmailAlreadyTaken
    } else if lower.contains("users_username_key")
        || (lower.contains("unique") && lower.contains("username"))
    {
        AuthError::UsernameAlreadyTaken
    } else {
        // Preserve the full chained message so callers (including tests) can
        // inspect it rather than receiving the opaque "db error" string.
        AuthError::DatabaseError(full)
    }
}

/// Map a `tokio-postgres` [`Row`] to a [`User`].
fn row_to_user(row: Row) -> User {
    User {
        id: row.get::<_, uuid::Uuid>("id"),
        email: row.get::<_, String>("email"),
        password_hash: row.get::<_, Option<String>>("password_hash"),
        jwt_secret: row.get::<_, Option<String>>("jwt_secret"),
        username: row.get::<_, Option<String>>("username"),
        first_name: row.get::<_, Option<String>>("first_name"),
        last_name: row.get::<_, Option<String>>("last_name"),
        avatar_url: row.get::<_, Option<String>>("avatar_url"),
        is_active: row.get::<_, bool>("is_active"),
        is_verified: row.get::<_, bool>("is_verified"),
        created_at: row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
        updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at"),
    }
}
