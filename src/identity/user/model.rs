//! User domain models.
//!
//! Contains **only** plain data structures.
//! - Persistence contract → [`crate::identity::user::repository`]
//! - Service contract     → [`crate::identity::user::service`]
//! - Business logic       → [`crate::identity::user::service_impl`]

use crate::identity::access::model::Role;

// ── Persisted entity ──────────────────────────────────────────────────────────

/// A fully hydrated user as returned by a [`UserRepository`](crate::identity::user::UserRepository).
///
/// `Debug` is implemented by hand so `password_hash` never ends up in logs.
#[derive(Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
    pub is_active: bool,
    pub is_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// A user together with their currently active roles.
#[derive(Debug, Clone)]
pub struct UserWithRoles {
    pub user: User,
    pub roles: Vec<Role>,
}

// ── Repository inputs ─────────────────────────────────────────────────────────

/// Ready-to-insert user data, produced by the service layer and consumed by
/// [`UserRepository::create`](crate::identity::user::UserRepository::create).
///
/// `password_hash` already holds the hasher output — the repository just
/// writes it verbatim.
#[derive(Clone)]
pub struct NewUser {
    pub email: String,
    pub password_hash: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Partial update consumed by
/// [`UserRepository::update`](crate::identity::user::UserRepository::update).
///
/// `None` means "leave unchanged".  `password_hash` is already hashed.
#[derive(Clone, Default)]
pub struct UserUpdate {
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// Page size used when a [`UserQuery`] asks for `limit = 0`.
pub const DEFAULT_USER_PAGE: u32 = 50;
/// Largest page [`UserService::list`](crate::identity::user::UserService::list) returns.
pub const MAX_USER_PAGE: u32 = 200;

/// Page request consumed by
/// [`UserRepository::list`](crate::identity::user::UserRepository::list).
///
/// `search`, when set, is matched case-insensitively as a substring of the
/// email or the username.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserQuery {
    pub search: Option<String>,
    pub limit: u32,
    pub offset: u32,
}

/// One page of users, newest first, plus the total matching `search`.
#[derive(Debug, Clone)]
pub struct UserPage {
    pub items: Vec<User>,
    pub total: u64,
}

// ── Service inputs ────────────────────────────────────────────────────────────

/// Data required to register a new user.
///
/// `password` holds the **raw** plaintext password; the service validates
/// and hashes it before persistence.
#[derive(Clone)]
pub struct RegisterUser {
    pub email: String,
    pub password: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Partial profile update.  `None` means "leave unchanged".
///
/// `password` is the raw plaintext; the service validates and hashes it.
#[derive(Clone, Default)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub password: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("email", &self.email)
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| REDACTED),
            )
            .field("username", &self.username)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("avatar_url", &self.avatar_url)
            .field("is_active", &self.is_active)
            .field("is_verified", &self.is_verified)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl std::fmt::Debug for NewUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewUser")
            .field("email", &self.email)
            .field("password_hash", &REDACTED)
            .field("username", &self.username)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

impl std::fmt::Debug for UserUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserUpdate")
            .field("email", &self.email)
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| REDACTED),
            )
            .field("username", &self.username)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("avatar_url", &self.avatar_url)
            .finish()
    }
}

impl std::fmt::Debug for RegisterUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterUser")
            .field("email", &self.email)
            .field("password", &REDACTED)
            .field("username", &self.username)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

impl std::fmt::Debug for UpdateUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateUser")
            .field("email", &self.email)
            .field("password", &self.password.as_ref().map(|_| REDACTED))
            .field("username", &self.username)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("avatar_url", &self.avatar_url)
            .finish()
    }
}
