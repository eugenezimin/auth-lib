//! Access-control service interface.
//!
//! Defines the [`RoleService`] trait — role management and assignments.
//! The default implementation is [`RoleServiceImpl`](crate::access::RoleServiceImpl).

use async_trait::async_trait;

use crate::access::model::{NewRole, Role, UserRole};
use crate::error::AuthError;

/// Role management and user → role assignments.  Requires a mode with roles
/// (`rbac` / `combined`); assignment changes take effect at the user's next
/// refresh.
#[async_trait]
pub trait RoleService: Send + Sync {
    // ── Roles ─────────────────────────────────────────────────────────────────
    async fn create(&self, role: &NewRole) -> Result<Role, AuthError>;
    async fn find_by_id(&self, role_id: uuid::Uuid) -> Result<Option<Role>, AuthError>;
    async fn find_by_name(&self, name: &str) -> Result<Option<Role>, AuthError>;
    async fn find_by_code(&self, code: &str) -> Result<Option<Role>, AuthError>;
    async fn exists_by_name(&self, name: &str) -> Result<bool, AuthError>;
    async fn list(&self) -> Result<Vec<Role>, AuthError>;
    async fn delete(&self, role_id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError>;

    // ── Assignments ───────────────────────────────────────────────────────────
    async fn assign(&self, user_id: uuid::Uuid, role_id: uuid::Uuid) -> Result<bool, AuthError>;
    async fn revoke(&self, user_id: uuid::Uuid, role_id: uuid::Uuid) -> Result<bool, AuthError>;
    async fn has_role(&self, user_id: uuid::Uuid, role_id: uuid::Uuid) -> Result<bool, AuthError>;
    async fn list_user_assignments(&self, user_id: uuid::Uuid) -> Result<Vec<UserRole>, AuthError>;
    async fn list_user_assignment_history(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Vec<UserRole>, AuthError>;
    async fn revoke_all_for_user(&self, user_id: uuid::Uuid) -> Result<u64, AuthError>;
}
