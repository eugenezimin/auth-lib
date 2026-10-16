//! Adapter-level constants: connection defaults, env-var names, their paths
//! in the configuration file and the database constraint names mapped to
//! domain errors.

use z_auth::conf::config::Key;

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

// ── Configuration file (read by `PgConfig::from_source`) ─────────────────────

/// The adapter's top-level section in the configuration file.
pub const SECTION: &str = "database";

/// Every connection setting: its environment variable and its path in the
/// file.
pub const KEYS: &[Key] = &[
    Key::new(ENV_DB_HOST, "database.host"),
    Key::new(ENV_DB_PORT, "database.port"),
    Key::new(ENV_DB_USER, "database.user"),
    Key::new(ENV_DB_PASSWORD, "database.password"),
    Key::new(ENV_DB_NAME, "database.name"),
    Key::new(ENV_DB_MAX_POOL_SIZE, "database.max_pool_size"),
    Key::new(ENV_DB_CONNECT_TIMEOUT_SECS, "database.connect_timeout_secs"),
];

// ── Constraint names (see migrations/0001_initial_schema.sql) ────────────────

pub const PG_UNIQUE_VIOLATION: &str = "23505";
pub const CONSTRAINT_IDENTITY_USERS_EMAIL: &str = "identity_users_email";
pub const CONSTRAINT_IDENTITY_USERS_USERNAME: &str = "identity_users_username_key";
pub const CONSTRAINT_IDENTITY_ROLES_NAME: &str = "identity_roles_name_key";
pub const CONSTRAINT_IDENTITY_ROLES_CODE: &str = "identity_roles_code_key";
pub const CONSTRAINT_SECURITY_PERMISSIONS_CODE: &str = "security_permissions_code_key";
pub const CONSTRAINT_USER_ROLE_ACTIVE: &str = "unique_user_role_active";
/// See migrations_mfa/2001_mfa_schema.sql.
pub const CONSTRAINT_MFA_FACTORS_ACTIVE: &str = "uq_mfa_factors_user_method_active";
/// See migrations_external/3001_external_identity_schema.sql.
pub const CONSTRAINT_EXTERNAL_IDENTITIES_SUBJECT: &str = "uq_identity_external_identities_subject";
