/// User-role repository interface.
///
/// Defines the [`UserRoleRepo`] trait — the persistence contract for the
/// `users_roles` join table.  Concrete implementations live in
/// [`crate::storage::postgres::user_role_repo`].
///
/// The table tracks the **full assignment history**: an active assignment has
/// `revoked_at = NULL`; a revoked one has `revoked_at` set to the revocation
/// timestamp.  The DB-level uniqueness constraint (`unique_user_role_active`)
/// guarantees at most one active `(user_id, role_id)` pair at any time.
///
/// # Example — using a mock in tests
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use auth_lib::interfaces::db::user_role_repo::UserRoleRepo;
/// use auth_lib::model::user_role::{NewUserRole, UserRole};
/// use auth_lib::utils::errors::AuthError;
///
/// struct MockUserRoleRepo;
///
/// #[async_trait]
/// impl UserRoleRepo for MockUserRoleRepo {
///     async fn assign(&self, new: NewUserRole) -> Result<UserRole, AuthError> {
///         todo!()
///     }
///     async fn revoke(
///         &self,
///         user_id: uuid::Uuid,
///         role_id: uuid::Uuid,
///     ) -> Result<bool, AuthError> {
///         Ok(true)
///     }
///     async fn list_active_for_user(
///         &self,
///         user_id: uuid::Uuid,
///     ) -> Result<Vec<UserRole>, AuthError> {
///         Ok(vec![])
///     }
///     async fn list_all_for_user(
///         &self,
///         user_id: uuid::Uuid,
///     ) -> Result<Vec<UserRole>, AuthError> {
///         Ok(vec![])
///     }
///     async fn is_role_active(
///         &self,
///         user_id: uuid::Uuid,
///         role_id: uuid::Uuid,
///     ) -> Result<bool, AuthError> {
///         Ok(false)
///     }
///     async fn revoke_all_for_user(
///         &self,
///         user_id: uuid::Uuid,
///     ) -> Result<u64, AuthError> {
///         Ok(0)
///     }
/// }
/// ```
use async_trait::async_trait;

use crate::model::user_role::{NewUserRole, UserRole};
use crate::utils::errors::AuthError;

/// Persistence contract for the `users_roles` join table.
///
/// All methods are `Send + Sync` so implementations can be held behind `Arc`
/// and shared across async tasks.
#[async_trait]
pub trait UserRoleRepo: Send + Sync {
    /// Assign a role to a user (insert a new active row).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::RoleAlreadyAssigned`] if an active `(user_id,
    /// role_id)` pair already exists (DB constraint `unique_user_role_active`).
    /// Returns [`AuthError::DatabaseError`] for any other persistence failure.
    async fn assign(&self, new: NewUserRole) -> Result<UserRole, AuthError>;

    /// Revoke a role from a user by stamping `revoked_at = NOW()`.
    ///
    /// Only affects the active assignment (`revoked_at IS NULL`).
    /// Returns `Ok(true)` if a row was updated, `Ok(false)` if no active
    /// assignment was found — callers need not treat the latter as an error.
    async fn revoke(&self, user_id: uuid::Uuid, role_id: uuid::Uuid) -> Result<bool, AuthError>;

    /// Return all **active** assignments for a user, ordered by `assigned_at DESC`.
    ///
    /// An empty `Vec` means the user currently holds no roles.
    async fn list_active_for_user(&self, user_id: uuid::Uuid) -> Result<Vec<UserRole>, AuthError>;

    /// Return the **complete history** (active + revoked) for a user, ordered
    /// by `assigned_at DESC`.
    ///
    /// Useful for audit logs and admin views.
    async fn list_all_for_user(&self, user_id: uuid::Uuid) -> Result<Vec<UserRole>, AuthError>;

    /// Returns `true` if the user currently holds the given role (active assignment).
    async fn is_role_active(
        &self,
        user_id: uuid::Uuid,
        role_id: uuid::Uuid,
    ) -> Result<bool, AuthError>;

    /// Revoke **all** active role assignments for a user in a single statement.
    ///
    /// Intended for account suspension / deletion workflows.
    /// Returns the number of rows updated.
    async fn revoke_all_for_user(&self, user_id: uuid::Uuid) -> Result<u64, AuthError>;
}
