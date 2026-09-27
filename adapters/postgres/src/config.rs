//! PostgreSQL connection settings.
//!
//! Database configuration belongs to the adapter / host application, not to
//! auth-lib itself.

use std::time::Duration;

use crate::constants::*;

#[derive(Clone)]
pub struct PgConfig {
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

impl PgConfig {
    /// Read `DB_*` environment variables.  `DB_HOST`, `DB_USER` and
    /// `DB_PASSWORD` are required; everything else has a default.
    pub fn from_env() -> Result<Self, String> {
        let required = |key: &str| std::env::var(key).map_err(|_| format!("missing env var {key}"));
        let parsed = |key: &str| -> Result<Option<u64>, String> {
            std::env::var(key)
                .ok()
                .map(|v| v.parse::<u64>().map_err(|e| format!("invalid {key}: {e}")))
                .transpose()
        };

        Ok(Self {
            host: required(ENV_DB_HOST)?,
            port: std::env::var(ENV_DB_PORT)
                .ok()
                .map(|v| v.parse().map_err(|e| format!("invalid {ENV_DB_PORT}: {e}")))
                .transpose()?
                .unwrap_or(DEFAULT_PORT),
            user: required(ENV_DB_USER)?,
            password: required(ENV_DB_PASSWORD)?,
            name: std::env::var(ENV_DB_NAME).unwrap_or_else(|_| DEFAULT_DB_NAME.into()),
            max_pool_size: parsed(ENV_DB_MAX_POOL_SIZE)?
                .map(|v| v as u32)
                .unwrap_or(DEFAULT_MAX_POOL_SIZE),
            connect_timeout: Duration::from_secs(
                parsed(ENV_DB_CONNECT_TIMEOUT_SECS)?.unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS),
            ),
        })
    }

    /// `postgres://user:password@host:port/name`
    pub fn connection_url(&self) -> String {
        self.connection_url_for(&self.name)
    }

    /// Same as [`connection_url`](Self::connection_url) but for another
    /// database on the same server (e.g. the `postgres` maintenance DB).
    pub fn connection_url_for(&self, db_name: &str) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, db_name,
        )
    }
}

/// Redacts `password` so configs can be logged safely.
impl std::fmt::Debug for PgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("name", &self.name)
            .field("max_pool_size", &self.max_pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}
