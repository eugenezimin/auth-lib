/// User domain models.
///
/// Contains **only** plain data structures used across the auth-lib.
/// - Parsing / validation logic → [`crate::utils`]
/// - Persistence logic         → [`crate::storage::user_repo`]
/// - Business logic            → [`crate::auth::service`]
// ── Persisted entity ──────────────────────────────────────────────────────────
use crate::model::role::Role;

/// A fully hydrated user row as returned from the database.
///
/// Field names and types map 1-to-1 to the `users` table in
/// `src/model/migrations/postgres.sql`:
///
/// ```sql
/// CREATE TABLE "users" (
///     "id"            uuid         NOT NULL DEFAULT gen_random_uuid(),
///     "email"         varchar(255) NOT NULL,
///     "password_hash" text,
///     "jwt_secret"    text,
///     "username"      varchar(100),
///     "first_name"    varchar(255),
///     "last_name"     varchar(255),
///     "avatar_url"    text,
///     "is_active"     bool         NOT NULL DEFAULT true,
///     "is_verified"   bool         NOT NULL DEFAULT false,
///     "created_at"    timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
///     "updated_at"    timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
///     PRIMARY KEY ("id")
/// );
/// ```
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: uuid::Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub jwt_secret: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
    pub is_active: bool,
    pub is_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
pub struct UserWithRoles {
    pub id: uuid::Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub jwt_secret: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
    pub is_active: bool,
    pub is_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub roles: Option<Vec<Role>>,
}

impl UserWithRoles {
    pub fn new(user: User, roles: Vec<Role>) -> Self {
        Self {
            id: user.id,
            email: user.email,
            password_hash: user.password_hash,
            jwt_secret: user.jwt_secret,
            username: user.username,
            first_name: user.first_name,
            last_name: user.last_name,
            avatar_url: user.avatar_url,
            is_active: user.is_active,
            is_verified: user.is_verified,
            created_at: user.created_at,
            updated_at: user.updated_at,
            roles: Some(roles),
        }
    }
}

/// Ready-to-insert user data, produced by the service layer and consumed by
/// [`crate::interfaces::user_repo::UserRepo::create`].
///
/// Unlike [`RegisterRequest`], every sensitive field here is already processed:
/// `password_hash` holds the Argon2 output and `jwt_secret` is a freshly
/// generated random secret — the repository just writes them verbatim.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub email: String,
    pub password_hash: String,
    pub jwt_secret: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Inbound data required to register a new user.
///
/// Constructed by the caller (e.g. an HTTP handler) and passed to
/// [`crate::interfaces::auth::AuthService::register`].
///
/// The `password` field holds the **raw** plaintext password; the service
/// layer is responsible for hashing it before persistence.
#[derive(Debug, Clone)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Returned to the caller after a successful registration.
///
/// Intentionally omits sensitive fields (`password_hash`, `jwt_secret`).
#[derive(Debug, Clone)]
pub struct RegisterResponse {
    pub user_id: uuid::Uuid,
    pub email: String,
    pub username: Option<String>,
}
impl RegisterResponse {
    pub fn from_user(user: User) -> Self {
        Self {
            user_id: user.id,
            email: user.email,
            username: user.username,
        }
    }
}
