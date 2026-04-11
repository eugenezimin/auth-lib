//! Configuration implementation.
//!
//! Provides the [`OnceLock`]-backed singleton and all `impl` blocks for the
//! types declared in [`crate::model::config`].
//!
//! # Initialization paths
//!
//! |-----------------------|----------------------------------------------------------|
//! |      Method           |                         Source                           |
//! |-----------------------|----------------------------------------------------------|
//! | [`Config::init`]      | Environment variables / `.env` file (uses [`EnvLoader`]) |
//! | [`Config::init_with`] | Any [`ConfigLoader`] implementation                      |
//! |-----------------------|----------------------------------------------------------|

//! # Example — environment variables (default)
//!
//! ```rust,no_run
//! use crate::utils::config::Config;
//!
//! Config::init().expect("failed to load config");
//!
//! let addr = Config::global().server.bind_address();
//! ```
//!
//! # Example — pre-filled struct (no env)
//!
//! ```rust,no_run
//! use crate::interfaces::config::{DirectLoader, RawConfig};
//! use crate::model::config::Config;
//!
//! Config::init_with(DirectLoader::new(
//!     RawConfig::default()
//!         .db_host("localhost")
//!         .db_user("postgres")
//!         .db_password("secret")
//!         .jwt_secret("super-secret-key"),
//! ))
//! .expect("failed to load config");
//! ```

use std::sync::OnceLock;
use std::time::Duration;

use crate::interfaces::config::ConfigLoader;
use crate::model::config::{
    Config, ConfigError, DatabaseConfig, DirectLoader, EnvLoader, JwtConfig, RawConfig,
    ServerConfig,
};

// ── Global singleton ──────────────────────────────────────────────────────────

static CONFIG: OnceLock<Config> = OnceLock::new();

// ── Config impls ──────────────────────────────────────────────────────────────

impl Config {
    /// Initialise from environment variables / `.env` file.
    ///
    /// Shorthand for `Config::init_with(EnvLoader)`.
    pub fn init() -> Result<&'static Self, ConfigError> {
        Self::init_with(EnvLoader)
    }

    /// Initialise from any [`ConfigLoader`].
    ///
    /// Call this **once** at startup.  Pass a [`DirectLoader`] (or your own
    /// implementation) to bypass environment variables entirely.
    ///
    /// [`DirectLoader`]: crate::interfaces::config::DirectLoader
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the loader fails or a required field is absent.
    ///
    /// # Panics
    /// Panics if called more than once.
    pub fn init_with(loader: impl ConfigLoader) -> Result<&'static Self, ConfigError> {
        let raw = loader.load()?;
        let (database, jwt, server) = raw.into_parts()?;

        let cfg = Self {
            database,
            jwt,
            server,
        };

        CONFIG
            .set(cfg)
            .expect("Config::init / Config::init_with called more than once");

        Ok(CONFIG.get().unwrap())
    }

    /// Return a reference to the global [`Config`].
    ///
    /// # Panics
    /// Panics if neither [`init`](Self::init) nor [`init_with`](Self::init_with)
    /// has been called yet.
    pub fn global() -> &'static Self {
        CONFIG
            .get()
            .expect("Config not initialised – call Config::init() or Config::init_with() first")
    }

    /// Returns `true` if the global config has already been initialised.
    ///
    /// Useful in tests or conditional startup paths.
    pub fn is_initialised() -> bool {
        CONFIG.get().is_some()
    }
}

// ── DatabaseConfig impls ──────────────────────────────────────────────────────

impl DatabaseConfig {
    /// Build a `tokio-postgres`-compatible connection string.
    pub fn connection_string(&self) -> String {
        format!(
            "host={} port={} user={} password={} dbname={} connect_timeout={}",
            self.host,
            self.port,
            self.user,
            self.password,
            self.name,
            self.connect_timeout.as_secs(),
        )
    }

    /// Build a URL-style connection string (`postgres://…`).
    ///
    /// Some connection-pool crates (e.g. `deadpool-postgres`) prefer this form.
    pub fn connection_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, self.name,
        )
    }
}

// ── JwtConfig impls ───────────────────────────────────────────────────────────

impl JwtConfig {
    /// Return the access-token expiry as whole seconds (`exp` claim offset).
    pub fn access_expiry_secs(&self) -> u64 {
        self.access_token_expiry.as_secs()
    }

    /// Return the refresh-token expiry as whole seconds.
    pub fn refresh_expiry_secs(&self) -> u64 {
        self.refresh_token_expiry.as_secs()
    }
}

// ── ServerConfig impls ────────────────────────────────────────────────────────

impl ServerConfig {
    /// `"host:port"` string ready to pass to a TCP listener.
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// ── ConfigError impls ─────────────────────────────────────────────────────────

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(key) => {
                write!(f, "missing required configuration field: {key}")
            }
            Self::Parse { key, reason } => {
                write!(f, "failed to parse configuration field '{key}': {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ── load_dotenv (pub(crate) so EnvLoader can call it) ────────────────────────

/// Best-effort `.env` loader; does **not** override already-set env vars.
pub(crate) fn load_dotenv() {
    let path = std::path::Path::new(".env");
    if !path.exists() {
        return;
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"').trim_matches('\'');
            if std::env::var(key).is_err() {
                // SAFETY: called before any other threads are spawned.
                unsafe { std::env::set_var(key, value) };
            }
        }
    }
}

impl RawConfig {
    // ── Chainable builder helpers ─────────────────────────────────────────────

    pub fn db_host(mut self, v: impl Into<String>) -> Self {
        self.db_host = Some(v.into());
        self
    }
    pub fn db_port(mut self, v: u16) -> Self {
        self.db_port = Some(v);
        self
    }
    pub fn db_user(mut self, v: impl Into<String>) -> Self {
        self.db_user = Some(v.into());
        self
    }
    pub fn db_password(mut self, v: impl Into<String>) -> Self {
        self.db_password = Some(v.into());
        self
    }
    pub fn db_name(mut self, v: impl Into<String>) -> Self {
        self.db_name = Some(v.into());
        self
    }
    pub fn db_max_pool_size(mut self, v: u32) -> Self {
        self.db_max_pool_size = Some(v);
        self
    }
    pub fn db_connect_timeout_secs(mut self, v: u64) -> Self {
        self.db_connect_timeout_secs = Some(v);
        self
    }
    pub fn jwt_secret(mut self, v: impl Into<String>) -> Self {
        self.jwt_secret = Some(v.into());
        self
    }
    pub fn jwt_access_expiry_secs(mut self, v: u64) -> Self {
        self.jwt_access_expiry_secs = Some(v);
        self
    }
    pub fn jwt_refresh_expiry_secs(mut self, v: u64) -> Self {
        self.jwt_refresh_expiry_secs = Some(v);
        self
    }
    pub fn jwt_issuer(mut self, v: impl Into<String>) -> Self {
        self.jwt_issuer = Some(v.into());
        self
    }
    pub fn server_host(mut self, v: impl Into<String>) -> Self {
        self.server_host = Some(v.into());
        self
    }
    pub fn server_port(mut self, v: u16) -> Self {
        self.server_port = Some(v);
        self
    }
    pub fn server_max_body_bytes(mut self, v: usize) -> Self {
        self.server_max_body_bytes = Some(v);
        self
    }

    // ── Conversion ────────────────────────────────────────────────────────────

    /// Validate and convert into the typed sub-configs.
    /// Returns `ConfigError::Missing` for any required field that is `None`.
    pub(crate) fn into_parts(
        self,
    ) -> Result<(DatabaseConfig, JwtConfig, ServerConfig), ConfigError> {
        let database = DatabaseConfig {
            host: self
                .db_host
                .ok_or_else(|| ConfigError::Missing("db_host".into()))?,
            port: self.db_port.unwrap_or(5432),
            user: self
                .db_user
                .ok_or_else(|| ConfigError::Missing("db_user".into()))?,
            password: self
                .db_password
                .ok_or_else(|| ConfigError::Missing("db_password".into()))?,
            name: self.db_name.unwrap_or_else(|| "auth".into()),
            max_pool_size: self.db_max_pool_size.unwrap_or(10),
            connect_timeout: Duration::from_secs(self.db_connect_timeout_secs.unwrap_or(5)),
        };

        let jwt = JwtConfig {
            secret: self
                .jwt_secret
                .ok_or_else(|| ConfigError::Missing("jwt_secret".into()))?,
            access_token_expiry: Duration::from_secs(self.jwt_access_expiry_secs.unwrap_or(900)),
            refresh_token_expiry: Duration::from_secs(
                self.jwt_refresh_expiry_secs.unwrap_or(604_800),
            ),
            issuer: self.jwt_issuer.unwrap_or_else(|| "auth-lib".into()),
        };

        let server = ServerConfig {
            host: self.server_host.unwrap_or_else(|| "127.0.0.1".into()),
            port: self.server_port.unwrap_or(8080),
            max_body_bytes: self.server_max_body_bytes.unwrap_or(1_048_576),
        };

        Ok((database, jwt, server))
    }
}

impl ConfigLoader for EnvLoader {
    fn load(&self) -> Result<RawConfig, ConfigError> {
        crate::utils::config::load_dotenv();

        Ok(RawConfig {
            db_host: env_str("DB_HOST"),
            db_port: parse_opt("DB_PORT")?,
            db_user: env_str("DB_USER"),
            db_password: env_str("DB_PASSWORD"),
            db_name: env_str("DB_NAME"),
            db_max_pool_size: parse_opt("DB_MAX_POOL_SIZE")?,
            db_connect_timeout_secs: parse_opt("DB_CONNECT_TIMEOUT_SECS")?,
            jwt_secret: env_str("JWT_SECRET"),
            jwt_access_expiry_secs: parse_opt("JWT_ACCESS_EXPIRY_SECS")?,
            jwt_refresh_expiry_secs: parse_opt("JWT_REFRESH_EXPIRY_SECS")?,
            jwt_issuer: env_str("JWT_ISSUER"),
            server_host: env_str("SERVER_HOST"),
            server_port: parse_opt("SERVER_PORT")?,
            server_max_body_bytes: parse_opt("SERVER_MAX_BODY_BYTES")?,
        })
    }
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn parse_opt<T>(key: &str) -> Result<Option<T>, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Err(_) => Ok(None),
        Ok(raw) => raw.parse::<T>().map(Some).map_err(|e| ConfigError::Parse {
            key: key.into(),
            reason: e.to_string(),
        }),
    }
}

impl DirectLoader {
    pub fn new(raw: RawConfig) -> Self {
        Self { raw }
    }
}

impl ConfigLoader for DirectLoader {
    fn load(&self) -> Result<RawConfig, ConfigError> {
        Ok(self.raw.clone())
    }
}
