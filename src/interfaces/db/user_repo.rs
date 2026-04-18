/// User repository interface.
///
/// Defines the [`UserRepo`] trait — the persistence contract for the `users`
/// table.  This module contains **only the trait definition**; the concrete
/// Postgres implementation lives in [`crate::storage::user_repo`].
///
/// Keeping the trait here (in `interfaces`) means the service layer depends
/// only on an abstraction, making it straightforward to swap the storage
/// backend or supply a mock in tests.
///
/// # Example — using a mock in tests
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use auth_lib::interfaces::user_repo::UserRepo;
/// use auth_lib::model::user::User;
/// use auth_lib::utils::errors::AuthError;
///
/// struct MockUserRepo;
///
/// #[async_trait]
/// impl UserRepo for MockUserRepo {
///     async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
///         Ok(None) // always "not found"
///     }
///     async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError> {
///         Ok(None) // always "not found"
///     }
///     async fn exists_by_email(&self, email: &str) -> Result<bool, AuthError> {
///         Ok(false)
///     }
///     async fn exists_by_username(&self, username: &str) -> Result<bool, AuthError> {
///         Ok(false)
///     }
///     async fn create(&self, new_user: NewUser) -> Result<User, AuthError> {
///         todo!()
///     }
///     async fn delete(&self, user_id: uuid::Uuid) -> Result<bool, AuthError> {
///         Ok(true)
///     }
///     async fn activate(&self, user_id: uuid::Uuid) -> Result<bool, AuthError> {
///         Ok(true)
///     }
///     async fn deactivate(&self, user_id: uuid::Uuid) -> Result<bool, AuthError> {
///         Ok(true)
///     }
///     async fn is_active(&self, user_id: uuid::Uuid) -> Result<Option<bool>, AuthError> {
///         Ok(Some(true))
///     }
///     async fn is_verified(&self, user_id: uuid::Uuid) -> Result<Option<bool>, AuthError> {
///         Ok(Some(false))
///     }
/// }
/// ```
use async_trait::async_trait;

use crate::model::user::{NewUser, RegisterRequest, User};
use crate::utils::errors::AuthError;

/// Persistence contract for the `users` table.
///
/// All methods map to discrete, single-responsibility database operations.
/// Implementations must be `Send + Sync` so they can be held behind `Arc`
/// and shared across async tasks.
#[async_trait]
pub(crate) trait UserRepo: Send + Sync {
    /// Fetch a user by their UUID.
    /// Returns `Ok(None)` when no matching row is found — callers should treat
    /// this as "user does not exist" rather than an error.
    async fn find_by_id(&self, user_id: uuid::Uuid) -> Result<Option<User>, AuthError>;

    /// Fetch a user by their email address.
    ///
    /// Returns `Ok(None)` when no matching row is found — callers should treat
    /// this as "user does not exist" rather than an error.
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;

    /// Fetch a user by their username.
    ///
    /// Returns `Ok(None)` when no matching row is found — callers should treat
    /// this as "user does not exist" rather than an error.
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError>;

    /// Returns `true` if a row with the given email already exists.
    ///
    /// Prefer this over `find_by_email` in registration flows where the full
    /// `User` struct is not needed — it maps to a lightweight `SELECT EXISTS`
    /// query that avoids fetching all columns.
    async fn exists_by_email(&self, email: &str) -> Result<bool, AuthError>;

    /// Returns `true` if a row with the given username already exists.
    ///
    /// Used during registration to enforce the unique-username constraint
    /// before hitting the database unique index.
    async fn exists_by_username(&self, username: &str) -> Result<bool, AuthError>;

    /// Insert a new user row and return the fully hydrated [`User`].
    ///
    /// The implementation is responsible for mapping [`NewUser`] onto the
    /// correct columns, including the already-hashed `password_hash` and
    /// a freshly generated `jwt_secret`.
    async fn create(&self, new_user: NewUser) -> Result<User, AuthError>;

    /// Update user fields based on a [`RegisterRequest`].
    ///
    /// This is a convenience method for the service layer to update all mutable
    /// fields in one shot, including re-hashing the password and validating the email format.
    /// Returns `Ok(())` if the update was successful, or an appropriate `AuthError` if the user
    /// does not exist or if validation fails.
    async fn update(
        &self,
        user_id: uuid::Uuid,
        update: RegisterRequest,
    ) -> Result<Option<User>, AuthError>;

    /// Permanently delete a user row by their UUID.
    ///
    /// This is a hard delete — the row is gone, and any foreign-keyed rows
    /// (sessions, user_roles) will be removed via `ON DELETE CASCADE`.
    /// Prefer [`deactivate`](Self::deactivate) when soft-deletion is sufficient.
    ///
    /// Returns `Ok(true)` if a row was deleted, `Ok(false)` if no matching
    /// row was found (idempotent — callers need not treat this as an error).
    async fn delete(&self, user_id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError>;

    /// Set `is_active = true` for the given user.
    ///
    /// Re-enables an account that was previously deactivated.
    /// Returns `Ok(true)` if the row was found and updated, `Ok(false)` if
    /// no user with that UUID exists.
    async fn activate(&self, user_id: uuid::Uuid) -> Result<bool, AuthError>;

    /// Set `is_active = false` for the given user (soft delete).
    ///
    /// The user row is retained in the database but the account is treated as
    /// inactive by the auth layer.  Sessions are not invalidated automatically;
    /// callers should purge sessions separately if immediate lock-out is needed.
    ///
    /// Returns `Ok(true)` if the row was found and updated, `Ok(false)` if
    /// no user with that UUID exists.
    async fn deactivate(&self, user_id: uuid::Uuid) -> Result<bool, AuthError>;

    /// Return the current `is_active` flag for the given user.
    ///
    /// Returns `Ok(None)` if no user with that UUID exists.
    async fn is_active(&self, user_id: uuid::Uuid) -> Result<Option<bool>, AuthError>;

    /// Return the current `is_verified` flag for the given user.
    ///
    /// Returns `Ok(None)` if no user with that UUID exists.
    async fn is_verified(&self, user_id: uuid::Uuid) -> Result<Option<bool>, AuthError>;
}
