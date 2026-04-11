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
///
///     async fn exists_by_email(&self, email: &str) -> Result<bool, AuthError> {
///         Ok(false)
///     }
///
///     async fn exists_by_username(&self, username: &str) -> Result<bool, AuthError> {
///         Ok(false)
///     }
///
///     async fn create(&self, new_user: NewUser) -> Result<User, AuthError> {
///         todo!()
///     }
/// }
/// ```
use async_trait::async_trait;

use crate::model::user::{NewUser, User};
use crate::utils::errors::AuthError;

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Persistence contract for the `users` table.
///
/// All methods map to discrete, single-responsibility database operations.
/// Implementations must be `Send + Sync` so they can be held behind `Arc`
/// and shared across async tasks.
#[async_trait]
pub trait UserRepo: Send + Sync {
    /// Fetch a user by their email address.
    ///
    /// Returns `Ok(None)` when no matching row is found — callers should treat
    /// this as "user does not exist" rather than an error.
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;

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
}
