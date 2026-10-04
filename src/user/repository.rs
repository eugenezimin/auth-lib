//! User repository port.
//!
//! Defines the [`UserRepository`] trait — the persistence contract for users.
//! auth-lib ships **no implementation**; the host application provides one
//! backed by whatever storage it uses (see `adapters/postgres` for a
//! reference implementation).

use async_trait::async_trait;

use crate::error::AuthError;
use crate::user::model::{NewUser, User, UserUpdate, UserWithRoles};

/// Persistence contract for users.
///
/// Implementations must be `Send + Sync` so they can be held behind `Arc`
/// and shared across async tasks.  Map driver errors to
/// [`AuthError::Storage`], and unique-constraint violations on email /
/// username to [`AuthError::EmailAlreadyTaken`] /
/// [`AuthError::UsernameAlreadyTaken`].
///
/// Identity matching:
/// - **email** — callers pass addresses already normalized with
///   [`normalize_email`](crate::user::normalize_email) (trimmed, lowercased).
/// - **username** — stored with its display case, but lookups and uniqueness
///   **must be case-insensitive** (`JohnDoe` and `johndoe` are the same user).
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Fetch a user by UUID.  `Ok(None)` means "does not exist".
    async fn find_by_id(&self, user_id: uuid::Uuid) -> Result<Option<User>, AuthError>;

    /// Fetch a user by email.  `Ok(None)` means "does not exist".
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;

    /// Fetch a user by username.  `Ok(None)` means "does not exist".
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError>;

    /// Fetch a user together with their **active** roles.
    async fn find_with_roles_by_id(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Option<UserWithRoles>, AuthError>;

    /// Fetch a user by email together with their **active** roles.
    async fn find_with_roles_by_email(
        &self,
        email: &str,
    ) -> Result<Option<UserWithRoles>, AuthError>;

    /// Fetch a user by username together with their **active** roles.
    async fn find_with_roles_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserWithRoles>, AuthError>;

    /// Returns `true` if a user with the given email already exists.
    ///
    /// Prefer this over `find_by_email` when the full `User` is not needed.
    async fn exists_by_email(&self, email: &str) -> Result<bool, AuthError>;

    /// Returns `true` if a user with the given username already exists.
    async fn exists_by_username(&self, username: &str) -> Result<bool, AuthError>;

    /// Insert a new user and return the fully hydrated [`User`].
    ///
    /// New users are active and unverified.
    async fn create(&self, new_user: NewUser) -> Result<User, AuthError>;

    /// Apply a partial update; `None` fields are left unchanged.
    ///
    /// Returns `Ok(None)` if no user with that UUID exists.
    async fn update(
        &self,
        user_id: uuid::Uuid,
        update: UserUpdate,
    ) -> Result<Option<User>, AuthError>;

    /// Permanently delete a user.
    ///
    /// Implementations must also remove dependent data (sessions, role
    /// assignments).  Returns `Ok(Some(id))` if a user was deleted,
    /// `Ok(None)` if not found.
    async fn delete(&self, user_id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError>;

    /// Set `is_active = true`.  Returns `Ok(false)` if the user does not exist.
    async fn activate(&self, user_id: uuid::Uuid) -> Result<bool, AuthError>;

    /// Set `is_active = false` (soft delete).  Only the flag — ending the
    /// user's sessions is done by [`UserService::deactivate`](crate::user::UserService::deactivate).
    /// Returns `Ok(false)` if the user does not exist.
    async fn deactivate(&self, user_id: uuid::Uuid) -> Result<bool, AuthError>;

    /// Current `is_active` flag; `Ok(None)` if the user does not exist.
    async fn is_active(&self, user_id: uuid::Uuid) -> Result<Option<bool>, AuthError>;

    /// Current `is_verified` flag; `Ok(None)` if the user does not exist.
    async fn is_verified(&self, user_id: uuid::Uuid) -> Result<Option<bool>, AuthError>;
}
