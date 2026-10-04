//! Access-control (RBAC) domain models.
//!
//! Contains **only** plain data structures.
//! - Persistence contract → [`crate::access::repository`]
//! - Service contract     → [`crate::access::service`]
//! - Business logic       → [`crate::access::service_impl`]

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
/// [`RoleRepository::create`](crate::access::RoleRepository::create).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NewRole {
    /// Unique, immutable; must match `^[a-z][a-z0-9_.:-]*$`.
    pub code: String,
    /// Must be unique across all roles.
    pub name: String,
    pub description: Option<String>,
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
