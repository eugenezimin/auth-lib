//! Access-control (RBAC) domain models.
//!
//! Contains **only** plain data structures.
//! - Persistence contract → [`crate::identity::access::repository`]
//! - Service contract     → [`crate::identity::access::service`]
//! - Business logic       → [`crate::identity::access::service_impl`]

/// A persisted role.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Role {
    pub id: uuid::Uuid,
    /// Immutable identifier carried in access tokens (`rol`) and used in
    /// application checks, e.g. `billing_admin`.
    pub code: String,
    /// Display name; unique.
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Ready-to-insert role data, consumed by
/// [`RoleRepository::create`](crate::identity::access::RoleRepository::create).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NewRole {
    /// Unique, immutable; must match `^[a-z][a-z0-9_.:-]*$`.
    pub code: String,
    /// Must be unique across all roles.
    pub name: String,
    pub description: Option<String>,
}

/// Partial role update consumed by
/// [`RoleRepository::update`](crate::identity::access::RoleRepository::update).
///
/// The `code` is immutable (it is carried in access tokens), so only the
/// display fields can change.  `None` means "leave unchanged";
/// `description: Some(None)` clears the description.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleUpdate {
    /// Must stay unique across all roles.
    pub name: Option<String>,
    pub description: Option<Option<String>>,
}

/// A single user → role assignment, including its history.
///
/// An active assignment has `revoked_at = None`; a revoked one keeps the
/// revocation timestamp for audit.  At most one active `(user_id, role_id)`
/// pair may exist at any time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserRole {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub role_id: uuid::Uuid,
    pub assigned_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}
