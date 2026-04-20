/// Role repository interface.
///
/// Defines the [`RoleRepo`] trait — the persistence contract for the `roles`
/// table.  Concrete implementations live in [`crate::storage::postgres::role_repo`]
/// (and future MySQL/Mongo equivalents).
use async_trait::async_trait;

use crate::model::role::{NewRole, Role};
use crate::utils::errors::AuthError;

/// Persistence contract for the `roles` table.
///
/// All methods are `Send + Sync` so implementations can be held behind `Arc`
/// and shared across async tasks.
#[async_trait]
pub(crate) trait RoleRepo: Send + Sync {
    /// Insert a new role row and return the fully hydrated [`Role`].
    ///
    /// Returns [`AuthError::DatabaseError`] on a name uniqueness violation or
    /// any other persistence failure.
    async fn create(&self, new_role: &NewRole) -> Result<Role, AuthError>;

    /// Fetch a role by its UUID.
    ///
    /// Returns `Ok(None)` if no matching row is found.
    async fn find_by_id(&self, id: uuid::Uuid) -> Result<Option<Role>, AuthError>;

    /// Fetch a role by its unique name.
    ///
    /// Returns `Ok(None)` if no matching row is found.
    async fn find_by_name(&self, name: &str) -> Result<Option<Role>, AuthError>;

    /// Return all roles in the table, ordered by name ascending.
    async fn list_all(&self) -> Result<Vec<Role>, AuthError>;

    /// Delete a role row by UUID.
    ///
    /// Cascades to `user_roles` via `ON DELETE CASCADE`.
    /// Returns `Ok(Some(id))` if a row was deleted, `Ok(None)` if not found.
    async fn delete(&self, id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError>;

    /// Returns `true` if a role with the given name already exists.
    async fn exists_by_name(&self, name: &str) -> Result<bool, AuthError>;
}
