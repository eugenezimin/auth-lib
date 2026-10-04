//! Permission repository port — catalog and grants.
//!
//! auth-lib ships **no implementation**; the host provides one (see
//! `adapters/postgres`).  Only admin operations, startup and login / refresh
//! call it — never token verification.

use async_trait::async_trait;
use uuid::Uuid;

use crate::authorization::model::{
    EffectiveGrants, NewPermission, Permission, PermissionAssignment, PermissionCatalog,
};
use crate::error::AuthError;

#[async_trait]
pub trait PermissionRepository: Send + Sync {
    /// Insert a catalog entry, assigning permanent positions from a
    /// never-reused sequence: one for a `bool` / `text` permission, one per
    /// option otherwise.  [`AuthError::PermissionAlreadyExists`] on a
    /// duplicate code.
    async fn create(&self, permission: &NewPermission) -> Result<Permission, AuthError>;

    /// Add an option (with a new position) to a `single` / `multi`
    /// permission and return the updated entry.
    async fn add_option(
        &self,
        permission_id: Uuid,
        option_code: &str,
    ) -> Result<Permission, AuthError>;

    /// Delete an entry and every grant of it.  Returns `false` if missing.
    async fn delete(&self, permission_id: Uuid) -> Result<bool, AuthError>;

    async fn find_by_code(&self, code: &str) -> Result<Option<Permission>, AuthError>;

    /// The whole catalog; `version` = highest position in use (0 if empty).
    async fn load_catalog(&self) -> Result<PermissionCatalog, AuthError>;

    /// Replace the user's grant of `assignment.permission_id` (atomically).
    async fn replace_user_grant(
        &self,
        user_id: Uuid,
        assignment: &PermissionAssignment,
    ) -> Result<(), AuthError>;

    /// Remove the user's grant of a permission.  `false` if none existed.
    async fn clear_user_grant(&self, user_id: Uuid, permission_id: Uuid)
    -> Result<bool, AuthError>;

    /// Replace a role's grant of `assignment.permission_id` (atomically).
    async fn replace_role_grant(
        &self,
        role_id: Uuid,
        assignment: &PermissionAssignment,
    ) -> Result<(), AuthError>;

    /// Remove a role's grant of a permission.  `false` if none existed.
    async fn clear_role_grant(&self, role_id: Uuid, permission_id: Uuid)
    -> Result<bool, AuthError>;

    /// The user's effective grants plus the catalog version, merged from
    /// direct grants and — when `include_role_grants` — the grants of the
    /// user's **active** roles:
    ///
    /// - `bool`: granted if any source grants it;
    /// - `multi`: union of the chosen options;
    /// - `single` / `text`: the direct grant wins, otherwise the role with
    ///   the lexicographically lowest code.
    async fn effective_grants(
        &self,
        user_id: Uuid,
        include_role_grants: bool,
    ) -> Result<EffectiveGrants, AuthError>;
}
