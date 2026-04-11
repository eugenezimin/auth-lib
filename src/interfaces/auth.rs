/// Auth service interface.
///
/// Defines the [`AuthService`] trait — the contract every auth implementation
/// must satisfy.  This module contains **only trait definitions**; all
/// implementations live in [`crate::auth::service`].
///
/// # Implementing a custom auth service
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use auth_lib::interfaces::auth::AuthService;
/// use auth_lib::model::user::{RegisterRequest, RegisterResponse};
/// use auth_lib::utils::errors::AuthError;
///
/// struct MyAuthService { /* db pool, config, … */ }
///
/// #[async_trait]
/// impl AuthService for MyAuthService {
///     async fn register(&self, req: RegisterRequest) -> Result<RegisterResponse, AuthError> {
///         // 1. validate input
///         // 2. check for conflicts
///         // 3. hash the password
///         // 4. persist the user
///         // 5. return RegisterResponse
///         todo!()
///     }
/// }
/// ```
use async_trait::async_trait;

use crate::model::user::{RegisterRequest, RegisterResponse};
use crate::utils::errors::AuthError;

// ── Trait ─────────────────────────────────────────────────────────────────────

/// The top-level contract for all authentication operations.
///
/// Each method maps to a discrete auth action.  Implementations are free to
/// compose any combination of password hashing, JWT minting, database access,
/// or external identity providers as needed.
///
/// All methods are `async` and take `&self` so the implementing struct can
/// hold shared state (e.g. a connection pool) without interior mutability.
#[async_trait]
pub trait AuthService: Send + Sync {
    /// Register a new user account.
    ///
    /// # Steps an implementation should perform
    ///
    /// 1. **Validate** `req.email` and `req.password` (format, strength).
    /// 2. **Check uniqueness** — return [`AuthError::EmailAlreadyTaken`] or
    ///    [`AuthError::UsernameAlreadyTaken`] if a conflict is found.
    /// 3. **Hash** the plaintext password before storage.
    /// 4. **Persist** the new user row.
    /// 5. **Return** a [`RegisterResponse`] with non-sensitive fields.
    ///
    /// # Errors
    /// |-------------------------------------|-------------------------------------------|
    /// | Variant                             | When                                      |
    /// |-------------------------------------|-------------------------------------------|
    /// | [`AuthError::EmailAlreadyTaken`]    | Another user already has this email       |
    /// | [`AuthError::UsernameAlreadyTaken`] | Another user already has this username    |
    /// | [`AuthError::InvalidEmail`]         | Email does not pass format validation     |
    /// | [`AuthError::WeakPassword`]         | Password does not meet requirements       |
    /// | [`AuthError::HashingError`]         | bcrypt / argon2 failure                   |
    /// | [`AuthError::DatabaseError`]        | Persistence layer returned an error       |
    /// |-------------------------------------|-------------------------------------------|
    async fn register(&self, req: RegisterRequest) -> Result<RegisterResponse, AuthError>;
}
