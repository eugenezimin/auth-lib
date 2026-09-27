//! Adapter-level constants: connection defaults, env-var names and the
//! database constraint names mapped to domain errors.

// ── Connection defaults ───────────────────────────────────────────────────────

pub const DEFAULT_PORT: u16 = 5432;
pub const DEFAULT_DB_NAME: &str = "auth";
pub const DEFAULT_MAX_POOL_SIZE: u32 = 10;
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Session `TimeZone` pinned on every pooled connection.
pub const SESSION_TIME_ZONE: &str = "UTC";

/// Maintenance database used by `setup_db` to create the target database.
pub const ADMIN_DB_NAME: &str = "postgres";

// ── Environment variables (read by `PgConfig::from_env`) ─────────────────────

pub const ENV_DB_HOST: &str = "DB_HOST";
pub const ENV_DB_PORT: &str = "DB_PORT";
pub const ENV_DB_USER: &str = "DB_USER";
pub const ENV_DB_PASSWORD: &str = "DB_PASSWORD";
pub const ENV_DB_NAME: &str = "DB_NAME";
pub const ENV_DB_MAX_POOL_SIZE: &str = "DB_MAX_POOL_SIZE";
pub const ENV_DB_CONNECT_TIMEOUT_SECS: &str = "DB_CONNECT_TIMEOUT_SECS";

// ── Constraint names (see migrations/0001_initial_schema.sql) ────────────────

pub const PG_UNIQUE_VIOLATION: &str = "23505";
pub const CONSTRAINT_USERS_EMAIL: &str = "users_email";
pub const CONSTRAINT_USERS_USERNAME: &str = "users_username_key";
pub const CONSTRAINT_ROLES_NAME: &str = "roles_name_key";
pub const CONSTRAINT_USER_ROLE_ACTIVE: &str = "unique_user_role_active";
