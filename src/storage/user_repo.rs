/// PostgreSQL implementation of [`UserRepo`] using `sqlx`.
///
/// All SQL lives in [`crate::storage::queries::user_queries`].
/// Each method uses the shared `PgPool` — sqlx handles connection
/// borrowing internally, no manual acquire/release needed.
///
/// Uses the non-macro `sqlx::query_as` API so no `DATABASE_URL` is
/// required at compile time.
use sqlx::FromRow;

use crate::interfaces::user_repo::UserRepo;
use crate::model::user::{NewUser, User};
use crate::storage::pg_pool::PgUserRepo;
use crate::storage::queries::user_queries;
use crate::utils::errors::AuthError;

impl PgUserRepo {
    pub fn new(pg_pool: sqlx::PgPool) -> Self {
        Self { pg_pool }
    }
}

// ── UserRepo impl ─────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl UserRepo for PgUserRepo {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query_as::<_, UserRow>(user_queries::FIND_USER_BY_EMAIL)
            .bind(email)
            .fetch_optional(&self.pg_pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(UserRow::into_user))
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
        let row = sqlx::query_as::<_, UserRow>(user_queries::INSERT_USER)
            .bind(&new_user.email)
            .bind(&new_user.password_hash)
            .bind(&new_user.jwt_secret)
            .bind(&new_user.username)
            .bind(&new_user.first_name)
            .bind(&new_user.last_name)
            .fetch_one(&self.pg_pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(row.into_user())
    }
}

// ── Error mapping ─────────────────────────────────────────────────────────────

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

// ── Row type ──────────────────────────────────────────────────────────────────

/// Intermediate struct that sqlx maps query results into.
///
/// `FromRow` is derived so sqlx maps column names to fields automatically.
/// We then convert to the domain [`User`] type via `into_user` to keep
/// the domain model free of sqlx dependencies.
#[derive(FromRow)]
struct UserRow {
    id: uuid::Uuid,
    email: String,
    password_hash: Option<String>,
    jwt_secret: Option<String>,
    username: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    avatar_url: Option<String>,
    is_active: bool,
    is_verified: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl UserRow {
    fn into_user(self) -> User {
        User {
            id: self.id,
            email: self.email,
            password_hash: self.password_hash,
            jwt_secret: self.jwt_secret,
            username: self.username,
            first_name: self.first_name,
            last_name: self.last_name,
            avatar_url: self.avatar_url,
            is_active: self.is_active,
            is_verified: self.is_verified,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}
