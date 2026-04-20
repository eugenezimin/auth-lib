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

use crate::model::role::{NewRole, Role};
use crate::model::user::{RegisterRequest, User, UserWithRoles};
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
    /// Section 1: User registration and management
    async fn register(&self, req: RegisterRequest) -> Result<User, AuthError>;
    async fn find_user_by_id(&self, user_id: uuid::Uuid) -> Result<Option<User>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, AuthError>;
    async fn find_user_with_roles_by_id(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Option<UserWithRoles>, AuthError>;
    async fn find_user_with_roles_by_email(
        &self,
        email: &str,
    ) -> Result<Option<UserWithRoles>, AuthError>;
    async fn find_user_with_roles_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserWithRoles>, AuthError>;
    async fn update_user(
        &self,
        user_id: uuid::Uuid,
        update: RegisterRequest,
    ) -> Result<Option<User>, AuthError>;
    async fn delete_user(&self, user_id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError>;
    async fn activate_user(&self, user_id: uuid::Uuid) -> Result<bool, AuthError>;
    async fn deactivate_user(&self, user_id: uuid::Uuid) -> Result<bool, AuthError>;

    /// Section 2: Role management
    async fn create_role(&self, name: &NewRole) -> Result<Role, AuthError>;
    async fn find_role_by_id(&self, role_id: uuid::Uuid) -> Result<Option<Role>, AuthError>;
    async fn find_role_by_name(&self, name: &str) -> Result<Option<Role>, AuthError>;
    async fn exists_role_by_name(&self, name: &str) -> Result<bool, AuthError>;
    async fn list_roles(&self) -> Result<Vec<Role>, AuthError>;
    async fn delete_role(&self, role_id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError>;

    /// Section 3: User-role assignments
    async fn assign_role(
        &self,
        user_id: uuid::Uuid,
        role_id: uuid::Uuid,
    ) -> Result<bool, AuthError>;
    async fn revoke_role(
        &self,
        user_id: uuid::Uuid,
        role_id: uuid::Uuid,
    ) -> Result<bool, AuthError>;
}
