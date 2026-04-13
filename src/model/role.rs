/// Role domain models.
///
/// Contains **only** plain data structures used across auth-lib.
/// - Persistence logic  → [`crate::storage::postgres::role_repo`]
/// - Business logic     → future `crate::auth::roles`

/// A fully hydrated role row as returned from the database.
///
/// Maps 1-to-1 to the `roles` table:
///
/// ```sql
/// CREATE TABLE "roles" (
///     "id"          uuid        NOT NULL DEFAULT gen_random_uuid(),
///     "name"        varchar(50) NOT NULL,
///     "description" text,
///     "created_at"  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
///     PRIMARY KEY ("id")
/// );
/// ```
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Role {
    pub id: uuid::Uuid,

    /// Unique role name — `varchar(50) NOT NULL`.
    /// Enforced at DB level via `CREATE UNIQUE INDEX roles_name_key`.
    pub name: String,

    /// Optional human-readable description — `text`, nullable.
    pub description: Option<String>,

    /// Row creation timestamp — `timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP`.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Ready-to-insert role data, produced by the service/caller and consumed by
/// [`crate::interfaces::db::role_repo::RoleRepo::create`].
#[derive(Debug, Clone)]
pub struct NewRole {
    /// Must be unique across the `roles` table.
    pub name: String,
    pub description: Option<String>,
}
