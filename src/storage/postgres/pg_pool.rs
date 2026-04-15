use sqlx::PgPool;
/// PostgreSQL connection pool.
///
/// Wraps `sqlx::PgPool` and exposes a single `build_pool` function.
/// The pool is constructed from a [`DatabaseConfig`] and should be created
/// once at startup, then shared across the application via `Arc` or cloned
/// freely — `PgPool` is already `Clone + Send + Sync`.
///
/// All storage implementations receive a `PgPool` and sqlx handles
/// connection borrowing internally per query.
use sqlx::postgres::PgPoolOptions;

use crate::model::config::DatabaseConfig;

#[derive(Debug)]
pub enum PoolBuildError {
    /// sqlx rejected the configuration or could not connect.
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

/// PostgreSQL-backed user repository.
///
/// Construct with a shared [`PgPool`] and pass it (behind an `Arc`) to the
/// service layer, or clone the pool freely — sqlx pools are cheap to clone:
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use auth_lib::storage::pg_pool::PgUserRepo;
///
/// let repo = Arc::new(PgUserRepo::new(pool.clone()));
/// ```
pub struct PgUserRepo {
    pub pg_pool: PgPool,
}
/// PostgreSQL-backed role repository.
pub struct PgRoleRepo {
    pub pg_pool: sqlx::PgPool,
}
pub struct PgUserRoleRepo {
    pub pg_pool: sqlx::PgPool,
}

/// Build a `sqlx` connection pool from a [`DatabaseConfig`].
///
/// Call this **once** at startup and store the resulting `PgPool`.
/// `PgPool` is `Clone`, so pass it around by cloning — no `Arc` needed.
///
/// # Errors
///
/// Returns [`PoolBuildError::Config`] if sqlx cannot construct a valid pool
/// (e.g. invalid connection URL or connection refused).
///
/// # Example
///
/// ```rust,ignore
/// use auth_lib::storage::postgres::pg_pool::build_pool;
/// use auth_lib::model::config::Config;
///
/// Config::init().expect("config failed");
/// let pool = build_pool(&Config::global().database).await.expect("pool failed");
/// ```
pub async fn build_pool(cfg: &DatabaseConfig) -> Result<PgPool, PoolBuildError> {
    PgPoolOptions::new()
        .max_connections(cfg.max_pool_size)
        .acquire_timeout(cfg.connect_timeout)
        .connect(&cfg.connection_url())
        .await
        .map_err(|e| PoolBuildError::Config(e.to_string()))
}
