//! # auth-lib-postgres
//!
//! Reference PostgreSQL adapter for [`auth_lib`], built on `sqlx`.
//!
//! Implements every auth-lib repository port.  The core crate never depends
//! on this one — host applications pick it (or write their own adapter).
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use auth_lib::{AuthLib, config::{ConfigLoader, EnvLoader}};
//! use auth_lib_postgres::*;
//!
//! let pool = build_pg_pool(&PgConfig::from_env()?).await?;
//! run_migrations(&pool).await?;       // apply pending schema migrations
//! let auth = AuthLib::builder(EnvLoader.load_config()?)
//!     .users(Arc::new(PgUserRepository::new(pool.clone())))
//!     .roles(Arc::new(PgRoleRepository::new(pool.clone())))
//!     .user_roles(Arc::new(PgUserRoleRepository::new(pool.clone())))
//!     .sessions(Arc::new(PgSessionRepository::new(pool.clone())))
//!     .revocations(Arc::new(PgRevocationRepository::new(pool)))
//!     .build()?;
//!
//! auth.denylist_sync().sync().await?; // at startup, then every few seconds
//! ```

mod codes;
pub mod config;
pub mod constants;
mod enums;
mod errors;
pub mod pool;
mod queries;
mod revocation_repository;
mod role_repository;
mod rows;
mod session_repository;
mod user_repository;
mod user_role_repository;

pub use config::PgConfig;
pub use pool::build_pg_pool;
pub use revocation_repository::PgRevocationRepository;
pub use role_repository::PgRoleRepository;
pub use session_repository::PgSessionRepository;
pub use user_repository::PgUserRepository;
pub use user_role_repository::PgUserRoleRepository;

/// Versioned schema migrations (`migrations/NNNN_*.sql`), embedded at
/// compile time.  Applied migrations are recorded, with checksums, in the
/// `_sqlx_migrations` table; running the migrator only applies new files.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Apply every pending migration.  Idempotent, and safe to call from several
/// processes at once (sqlx serialises runs with an advisory lock).
///
/// ```rust,ignore
/// let pool = build_pg_pool(&PgConfig::from_env()?).await?;
/// run_migrations(&pool).await?;
/// ```
pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}
