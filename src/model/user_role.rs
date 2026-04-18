/// UserRole domain models.
///
/// Contains **only** plain data structures used across auth-lib.
/// - Persistence logic  → [`crate::storage::postgres::user_role_repo`]
/// - Business logic     → future `crate::auth::roles`

/// A fully hydrated `users_roles` row as returned from the database.
///
/// Maps 1-to-1 to the `users_roles` table:
///
/// ```sql
/// CREATE TABLE "users_roles" (
///     "id"          uuid        NOT NULL DEFAULT gen_random_uuid(),
///     "user_id"     uuid        NOT NULL,
///     "role_id"     uuid        NOT NULL,
///     "assigned_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
///     "revoked_at"  timestamptz,
///     PRIMARY KEY ("id"),
///     …
/// );
/// ```
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRole {
    pub id: uuid::Uuid,

    /// FK → `users.id`
    pub user_id: uuid::Uuid,

    /// FK → `roles.id`
    pub role_id: uuid::Uuid,

    /// When the role was granted.
    pub assigned_at: chrono::DateTime<chrono::Utc>,

    /// `None` while the assignment is active; `Some(ts)` once revoked.
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Input required to assign a role to a user.
///
/// Consumed by [`crate::interfaces::db::user_role_repo::UserRoleRepo::assign`].
/// The caller does **not** set `assigned_at` — the database default
/// (`CURRENT_TIMESTAMP`) handles it.
#[derive(Debug, Clone)]
pub(crate) struct NewUserRole {
    pub(crate) user_id: uuid::Uuid,
    pub(crate) role_id: uuid::Uuid,
}
