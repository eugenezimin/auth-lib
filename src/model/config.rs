/// Configuration data models.
///
/// This module contains **only** plain data structures and the error type.
/// All parsing logic lives in [`crate::utils::config`];
/// all loader traits and loader structs live in [`crate::interfaces::config`].
use std::time::Duration;

// ── Root config ───────────────────────────────────────────────────────────────

/// Root configuration object available application-wide.
///
/// Obtain via [`Config::init`] or [`Config::init_with`], then read anywhere
/// via [`Config::global`].
#[derive(Debug, Clone)]
pub struct Config {
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub server: ServerConfig,
}

// ── Sub-configs ───────────────────────────────────────────────────────────────

/// PostgreSQL connection settings.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub name: String,
    /// Maximum number of connections kept in the pool.
    pub max_pool_size: u32,
    /// How long to wait for a connection before giving up.
    pub connect_timeout: Duration,
}

/// JWT signing / verification settings.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// HMAC-SHA256 secret used to sign tokens.
    pub secret: String,
    /// How long an access token is valid.
    pub access_token_expiry: Duration,
    /// How long a refresh token is valid.
    pub refresh_token_expiry: Duration,
    /// Token issuer claim (`iss`).
    pub issuer: String,
}

/// HTTP server settings.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Maximum body size accepted by the server (bytes).
    pub max_body_bytes: usize,
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ConfigError {
    /// A required field / environment variable was not set.
    Missing(String),
    /// A value was present but could not be parsed into the expected type.
    Parse { key: String, reason: String },
}

// ── Raw (unvalidated) config ──────────────────────────────────────────────────

/// A flat, fully optional snapshot of every configuration knob.
///
/// Fields are `Option<T>` so callers only need to fill in what they care about;
/// the builder falls back to the same defaults used by [`EnvLoader`] for any
/// field left as `None`.
///
/// Construct via [`RawConfig::default()`] and override the fields you need,
/// or use the chainable builder helpers on this struct.
#[derive(Debug, Clone, Default)]
pub struct RawConfig {
    // ── Database ──────────────────────────────────────────────────────────────
    pub db_host: Option<String>,
    pub db_port: Option<u16>,
    pub db_user: Option<String>,
    pub db_password: Option<String>,
    pub db_name: Option<String>,
    pub db_max_pool_size: Option<u32>,
    pub db_connect_timeout_secs: Option<u64>,

    // ── JWT ───────────────────────────────────────────────────────────────────
    pub jwt_secret: Option<String>,
    pub jwt_access_expiry_secs: Option<u64>,
    pub jwt_refresh_expiry_secs: Option<u64>,
    pub jwt_issuer: Option<String>,

    // ── Server ────────────────────────────────────────────────────────────────
    pub server_host: Option<String>,
    pub server_port: Option<u16>,
    pub server_max_body_bytes: Option<usize>,
}
