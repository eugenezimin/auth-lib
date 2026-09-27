//! PostgreSQL connection pool.
//!
//! Build the pool **once** at startup and clone it into each repository —
//! `PgPool` is `Clone + Send + Sync` and sqlx handles connection borrowing
//! internally per query.

use std::str::FromStr;

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::config::PgConfig;
use crate::constants::SESSION_TIME_ZONE;

/// Connection options for `url` with the session `TimeZone` pinned to UTC.
///
/// `timestamptz` values are stored as UTC instants regardless; pinning the
/// session zone also makes anything rendered or truncated server-side
/// (`now()::date`, text output, `date_trunc`) UTC, independent of the
/// server's or database's default.
pub fn connect_options(url: &str) -> Result<PgConnectOptions, sqlx::Error> {
    Ok(PgConnectOptions::from_str(url)?.options([("timezone", SESSION_TIME_ZONE)]))
}

/// Build a `sqlx` connection pool from a [`PgConfig`].
///
/// ```rust,ignore
/// let pool = build_pg_pool(&PgConfig::from_env()?).await?;
/// ```
pub async fn build_pg_pool(cfg: &PgConfig) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(cfg.max_pool_size)
        .acquire_timeout(cfg.connect_timeout)
        .connect_with(connect_options(&cfg.connection_url())?)
        .await
}
