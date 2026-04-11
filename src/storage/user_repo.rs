use std::u128;

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

// ── UserRepo impl ─────────────────────────────────────────────────────────────

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

        // INSERT … RETURNING gives us the full row (including DB-generated
        // id, is_active, is_verified, created_at, updated_at) in one round-trip.
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
            .map_err(|e| {
                // Distinguish unique-constraint violations so the service can
                // surface a user-facing error rather than a generic DB error.
                let msg = e.to_string();
                if msg.contains("users_email") {
                    AuthError::EmailAlreadyTaken
                } else if msg.contains("users_username_key") {
                    AuthError::UsernameAlreadyTaken
                } else {
                    AuthError::DatabaseError(msg)
                }
            })?;

        Ok(row_to_user(row))
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Borrow a connection from the pool, converting pool errors to [`AuthError`].
async fn get_client(pool: &Pool) -> Result<deadpool_postgres::Client, AuthError> {
    pool.get()
        .await
        .map_err(|e| AuthError::DatabaseError(format!("connection pool error: {e}")))
}

/// Map a `tokio-postgres` [`Row`] to a [`User`].
///
/// Column order must match every `SELECT` / `RETURNING` clause in this file.
fn row_to_user(row: Row) -> User {
    let id: u32 = row.get("id");
    let created_at: String = row.get("created_at");
    let updated_at: String = row.get("updated_at");
    User {
        id: uuid::Uuid::from_u128(id as u128),
        email: row.get("email"),
        password_hash: row.get("password_hash"),
        jwt_secret: row.get("jwt_secret"),
        username: row.get("username"),
        first_name: row.get("first_name"),
        last_name: row.get("last_name"),
        avatar_url: row.get("avatar_url"),
        is_active: row.get("is_active"),
        is_verified: row.get("is_verified"),
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
            .unwrap()
            .with_timezone(&chrono::Utc),
        updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at)
            .unwrap()
            .with_timezone(&chrono::Utc),
    }
}
