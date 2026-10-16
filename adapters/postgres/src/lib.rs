//! # z-auth-postgres
//!
//! Reference PostgreSQL adapter for [`z_auth`], built on `sqlx`.
//!
//! Implements every z-auth repository port.  The core crate never depends
//! on this one — host applications pick it (or write their own adapter).
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use z_auth::{ZAuth, conf::config::{ConfigLoader, EnvLoader}};
//! use z_auth_postgres::*;
//!
//! let pool = build_pg_pool(&PgConfig::from_env()?).await?;
//! run_migrations(&pool).await?;       // apply pending schema migrations
//! let auth = ZAuth::builder(EnvLoader.load_config()?, repositories(&pool))
//!     .permissions(Arc::new(PgPermissionRepository::new(pool.clone()))) // permission modes
//!     .build()?;
//!
//! auth.start().await?;   // load state; then auth.tick() periodically
//! ```
//!
//! ## Features
//!
//! - `shared` — the node registry ([`PgNodeRepository`]) for
//!   z-auth-cluster's shared mode, and the cluster migration set
//!   ([`CLUSTER_MIGRATOR`], [`run_cluster_migrations`]).
//! - `federation` *(implies `shared`)* — the federation sync store
//!   ([`PgSyncStore`]) and the session-store schema
//!   ([`SESSION_STORE_MIGRATOR`]).
//! - `mfa` — z-auth-mfa's second-factor store ([`PgMfaRepository`]) and its
//!   migration set ([`MFA_MIGRATOR`], [`run_mfa_migrations`]).
//!
//! The migration sets share `_sqlx_migrations` and never collide: core
//! versions are below 1000, cluster versions 1001–1999, mfa versions from
//! 2001.
//!
//! ```rust,ignore
//! // features = ["shared"]
//! run_cluster_migrations(&pool).await?;   // core, then cluster tables
//! let cluster = Arc::new(z_auth_cluster::SharedCluster::new(
//!     settings, transport, Arc::new(PgNodeRepository::new(pool.clone())),
//! ));
//! let auth = ZAuth::builder(config, repositories(&pool)).extension(cluster.clone()).build()?;
//! ```

#[cfg(feature = "shared")]
mod cluster;
mod codes;
pub mod config;
pub mod constants;
mod enums;
mod errors;
mod key_repository;
#[cfg(feature = "mfa")]
mod mfa;
mod permission_repository;
pub mod pool;
mod queries;
mod revocation_repository;
mod role_repository;
mod rows;
mod session_repository;
mod user_repository;
mod user_role_repository;

#[cfg(feature = "shared")]
pub use cluster::PgNodeRepository;
#[cfg(feature = "federation")]
pub use cluster::PgSyncStore;
pub use config::PgConfig;
pub use key_repository::PgKeyRepository;
#[cfg(feature = "mfa")]
pub use mfa::PgMfaRepository;
pub use permission_repository::PgPermissionRepository;
pub use pool::build_pg_pool;
pub use revocation_repository::PgRevocationRepository;
pub use role_repository::PgRoleRepository;
pub use session_repository::PgSessionRepository;
pub use user_repository::PgUserRepository;
pub use user_role_repository::PgUserRoleRepository;

use std::sync::Arc;

use z_auth::Repositories;

/// Every repository z-auth requires, on one pool.  The optional
/// [`PgPermissionRepository`] (permission modes) is passed to the builder
/// separately.
pub fn repositories(pool: &sqlx::PgPool) -> Repositories {
    Repositories {
        users: Arc::new(PgUserRepository::new(pool.clone())),
        roles: Arc::new(PgRoleRepository::new(pool.clone())),
        user_roles: Arc::new(PgUserRoleRepository::new(pool.clone())),
        sessions: Arc::new(PgSessionRepository::new(pool.clone())),
        revocations: Arc::new(PgRevocationRepository::new(pool.clone())),
        keys: Arc::new(PgKeyRepository::new(pool.clone())),
    }
}

/// Versioned schema migrations (`migrations/NNNN_*.sql`, versions below
/// 1000), embedded at compile time.  Applied migrations are recorded, with
/// checksums, in the `_sqlx_migrations` table; running the migrator only
/// applies new files.  Versions it does not know (the cluster set's) are
/// left alone.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate::Migrator {
    ignore_missing: true,
    ..sqlx::migrate!("./migrations")
};

/// z-auth-cluster's tables (`migrations_cluster/`, versions from 1001):
/// the node registry, federation snapshots, the change feed and its
/// triggers on the core tables.  Applied on top of [`MIGRATOR`]; see
/// [`run_cluster_migrations`].
#[cfg(feature = "shared")]
pub static CLUSTER_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate::Migrator {
    ignore_missing: true,
    ..sqlx::migrate!("./migrations_cluster")
};

/// Federation mode, every service except the authority: the session-store
/// schema (`migrations_session_store/`) — sessions, revocations, keys,
/// snapshots, the instance registry and the change feed; no users.
/// Install it in its own schema (`search_path`).
#[cfg(feature = "federation")]
pub static SESSION_STORE_MIGRATOR: sqlx::migrate::Migrator =
    sqlx::migrate!("./migrations_session_store");

/// Apply every pending session-store migration.
#[cfg(feature = "federation")]
pub async fn run_session_store_migrations(
    pool: &sqlx::PgPool,
) -> Result<(), sqlx::migrate::MigrateError> {
    SESSION_STORE_MIGRATOR.run(pool).await
}

/// Apply every pending core migration.  Idempotent, and safe to call from
/// several processes at once (sqlx serialises runs with an advisory lock).
///
/// ```rust,ignore
/// let pool = build_pg_pool(&PgConfig::from_env()?).await?;
/// run_migrations(&pool).await?;
/// ```
pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}

/// z-auth-mfa's tables (`migrations_mfa/`, versions from 2001): factors,
/// recovery codes, login challenges and lockout state.  Applied on top of
/// [`MIGRATOR`]; see [`run_mfa_migrations`].
#[cfg(feature = "mfa")]
pub static MFA_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate::Migrator {
    ignore_missing: true,
    ..sqlx::migrate!("./migrations_mfa")
};

/// Apply every pending core migration, then every pending mfa one.
#[cfg(feature = "mfa")]
pub async fn run_mfa_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await?;
    MFA_MIGRATOR.run(pool).await
}

/// Apply every pending core migration, then every pending cluster one.
#[cfg(feature = "shared")]
pub async fn run_cluster_migrations(
    pool: &sqlx::PgPool,
) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await?;
    CLUSTER_MIGRATOR.run(pool).await
}
