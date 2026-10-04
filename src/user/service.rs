//! User service interface.
//!
//! Defines the [`UserService`] trait — registration and profile management.
//! The default implementation is [`UserServiceImpl`](crate::user::UserServiceImpl).

use async_trait::async_trait;

use crate::error::AuthError;
use crate::user::model::{RegisterUser, UpdateUser, User, UserWithRoles};

/// Registration and management of user accounts.
#[async_trait]
pub trait UserService: Send + Sync {
    /// Validate, hash and persist a new user.
    async fn register(&self, req: RegisterUser) -> Result<User, AuthError>;

    async fn find_by_id(&self, user_id: uuid::Uuid) -> Result<Option<User>, AuthError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError>;

    async fn find_with_roles_by_id(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Option<UserWithRoles>, AuthError>;
    async fn find_with_roles_by_email(
        &self,
        email: &str,
    ) -> Result<Option<UserWithRoles>, AuthError>;
    async fn find_with_roles_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserWithRoles>, AuthError>;

    /// Validate and apply a partial update.  Returns `Ok(None)` if the user
    /// does not exist.
    ///
    /// Changing the password ends every session of the user
    /// ([`RevocationReason::PasswordChanged`](crate::token::RevocationReason)),
    /// including the caller's.
    async fn update(
        &self,
        user_id: uuid::Uuid,
        update: UpdateUser,
    ) -> Result<Option<User>, AuthError>;

    /// Hard-delete a user and deny every token issued to them so far.
    /// Returns `Ok(Some(id))` if deleted, `Ok(None)` if not found.
    async fn delete(&self, user_id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError>;

    async fn activate(&self, user_id: uuid::Uuid) -> Result<bool, AuthError>;
    /// Disable the account and end every session of the user.  Returns
    /// `Ok(false)` if the user does not exist.
    async fn deactivate(&self, user_id: uuid::Uuid) -> Result<bool, AuthError>;
}
