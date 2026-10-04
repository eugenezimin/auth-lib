//! Access-control repository ports.
//!
//! Defines [`RoleRepository`] (roles) and [`UserRoleRepository`] (user → role
//! assignments).  auth-lib ships **no implementation**; the host application
//! provides one (see `adapters/postgres` for a reference implementation).

use async_trait::async_trait;

use crate::access::model::{NewRole, Role, UserRole};
use crate::error::AuthError;

/// Persistence contract for roles.
#[async_trait]
pub trait RoleRepository: Send + Sync {
    /// Insert a new role and return the fully hydrated [`Role`].
    ///
    /// Returns [`AuthError::RoleAlreadyExists`] on a code or name uniqueness
    /// violation.
    async fn create(&self, new_role: &NewRole) -> Result<Role, AuthError>;

    /// Fetch a role by UUID.  `Ok(None)` means "does not exist".
    async fn find_by_id(&self, id: uuid::Uuid) -> Result<Option<Role>, AuthError>;

    /// Fetch a role by its unique name.  `Ok(None)` means "does not exist".
    async fn find_by_name(&self, name: &str) -> Result<Option<Role>, AuthError>;

    /// Fetch a role by its unique code.  `Ok(None)` means "does not exist".
    async fn find_by_code(&self, code: &str) -> Result<Option<Role>, AuthError>;

    /// Return all roles, ordered by name ascending.
    async fn list_all(&self) -> Result<Vec<Role>, AuthError>;

    /// Delete a role.  Implementations must also remove its assignments.
    ///
    /// Returns `Ok(Some(id))` if deleted, `Ok(None)` if not found.
    async fn delete(&self, id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError>;

    /// Returns `true` if a role with the given name already exists.
    async fn exists_by_name(&self, name: &str) -> Result<bool, AuthError>;
}

/// Persistence contract for user → role assignments.
///
/// Assignments keep full history: revoking stamps `revoked_at` rather than
/// deleting the row.
#[async_trait]
pub trait UserRoleRepository: Send + Sync {
    /// Create an active assignment.
    ///
    /// Returns `Ok(true)` if a new assignment was created, `Ok(false)` if the
    /// user already holds the role actively.
    async fn assign(&self, user_id: uuid::Uuid, role_id: uuid::Uuid) -> Result<bool, AuthError>;

    /// Revoke the active assignment by stamping `revoked_at`.
    ///
    /// Returns `Ok(true)` if an active assignment was revoked, `Ok(false)` if
    /// none existed — callers need not treat the latter as an error.
    async fn revoke(&self, user_id: uuid::Uuid, role_id: uuid::Uuid) -> Result<bool, AuthError>;

    /// Returns `true` if the user currently holds the role.
    async fn is_role_active(
        &self,
        user_id: uuid::Uuid,
        role_id: uuid::Uuid,
    ) -> Result<bool, AuthError>;

    /// All **active** assignments for a user, newest first.
    async fn list_active_for_user(&self, user_id: uuid::Uuid) -> Result<Vec<UserRole>, AuthError>;

    /// Full assignment history (active + revoked) for a user, newest first.
    async fn list_all_for_user(&self, user_id: uuid::Uuid) -> Result<Vec<UserRole>, AuthError>;

    /// Revoke **all** active assignments for a user.  Returns the count revoked.
    async fn revoke_all_for_user(&self, user_id: uuid::Uuid) -> Result<u64, AuthError>;
}
