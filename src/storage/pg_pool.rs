/// PostgreSQL connection pool.
///
/// Wraps `deadpool-postgres` and exposes a single `build_pool` function.
/// The pool is constructed from a [`DatabaseConfig`] and should be created
/// once at startup, then shared across the application via `Arc`.
///
/// All storage implementations receive a `Pool` and call `.get().await`
/// to borrow a connection for the duration of a single query.
use deadpool_postgres::{Config as PoolConfig, Pool};
use tokio_postgres::NoTls;

use crate::model::config::DatabaseConfig;

#[derive(Debug)]
pub enum PoolBuildError {
    /// `deadpool-postgres` rejected the configuration.
    Config(String),
}

impl std::fmt::Display for PoolBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "failed to build connection pool: {msg}"),
        }
    }
}

impl std::error::Error for PoolBuildError {}

/// Build a `deadpool-postgres` connection pool from a [`DatabaseConfig`].
///
/// Call this **once** at startup and store the resulting `Pool` in an `Arc`
/// to share it across all storage implementations.
///
/// # Errors
///
/// Returns [`PoolBuildError::Config`] if `deadpool-postgres` cannot construct
/// a valid pool from the supplied configuration (e.g. an invalid host string).
///
/// Note: the pool is **lazy** — no actual TCP connection is made until the
/// first `.get()` call.  Connection errors surface there, not here.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use auth_lib::storage::pool::build_pool;
/// use auth_lib::model::config::Config;
///
/// Config::init().expect("config failed");
/// let pool = Arc::new(build_pool(&Config::global().database).expect("pool failed"));
/// ```
pub fn build_pool(cfg: &DatabaseConfig) -> Result<Pool, PoolBuildError> {
    let mut pool_cfg = PoolConfig::new();

    pool_cfg.host = Some(cfg.host.clone());
    pool_cfg.port = Some(cfg.port);
    pool_cfg.user = Some(cfg.user.clone());
    pool_cfg.password = Some(cfg.password.clone());
    pool_cfg.dbname = Some(cfg.name.clone());
    pool_cfg.connect_timeout = Some(cfg.connect_timeout);

    pool_cfg
        .builder(NoTls)
        .map_err(|e| PoolBuildError::Config(e.to_string()))?
        .max_size(cfg.max_pool_size as usize)
        .build()
        .map_err(|e| PoolBuildError::Config(e.to_string()))
}
