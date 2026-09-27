//! Shared helpers for auth-lib-postgres integration tests.
//!
//! These tests talk to a real PostgreSQL database; [`pool`] applies any
//! pending migrations first (create the database once with
//! `cargo run -p auth-lib-postgres --bin setup_db`).  Connection settings come
//! from `DB_*` env vars, falling back to a local default.
//!
//! Import with:
//!   mod helpers;
//!   use helpers::*;
//!
//! Every public function is cheap to call and idempotent — safe to use in
//! any test order with `--test-threads=N`.

#![allow(dead_code)] // each test binary uses a different subset
use std::sync::Arc;
use std::time::Duration;

use auth_lib::{
    AuthError, AuthLib,
    access::{NewRole, Role},
    config::RawConfig,
    token::keys::{generate_refresh_secret, generate_signing_key},
    user::{RegisterUser, User},
};
use auth_lib_postgres::{
    PgConfig, PgRevocationRepository, PgRoleRepository, PgSessionRepository, PgUserRepository,
    PgUserRoleRepository, build_pg_pool, run_migrations,
};

// ── Config ────────────────────────────────────────────────────────────────────

fn pg_config() -> PgConfig {
    PgConfig::from_env().unwrap_or_else(|_| PgConfig {
        host: "localhost".into(),
        port: 5432,
        user: "postgres".into(),
        password: "passw".into(),
        name: "auth".into(),
        max_pool_size: 20,
        connect_timeout: Duration::from_secs(10),
    })
}

// ── Service factory ───────────────────────────────────────────────────────────

/// A pool with every migration applied (idempotent; sqlx serialises
/// concurrent runs with an advisory lock).
pub async fn pool() -> sqlx::PgPool {
    let pool = build_pg_pool(&pg_config())
        .await
        .expect("Failed to connect to Postgres");
    run_migrations(&pool)
        .await
        .expect("Failed to run migrations");
    pool
}

pub async fn make_service() -> AuthLib {
    let pool = pool().await;
    let keys = generate_signing_key().expect("key generation");
    let config = RawConfig::default()
        .jwt_signing_key(keys.signing_key)
        .jwt_issuer("auth-lib-test")
        .refresh_secret(generate_refresh_secret().expect("secret generation"))
        .build()
        .expect("Failed to build test config");

    AuthLib::builder(config)
        .users(Arc::new(PgUserRepository::new(pool.clone())))
        .roles(Arc::new(PgRoleRepository::new(pool.clone())))
        .user_roles(Arc::new(PgUserRoleRepository::new(pool.clone())))
        .sessions(Arc::new(PgSessionRepository::new(pool.clone())))
        .revocations(Arc::new(PgRevocationRepository::new(pool)))
        .build()
        .expect("Failed to build auth service")
}

// ── Unique name generator ─────────────────────────────────────────────────────

/// Returns a unique string like `"base_3f2a…"` safe for use as a name/email.
pub fn unique_name(base: &str) -> String {
    format!("{base}_{}", uuid::Uuid::new_v4().simple())
}

pub fn unique_email(prefix: &str) -> String {
    format!("{}_{}", prefix, uuid::Uuid::new_v4().simple()) + "@test.example.com"
}

// ── User helpers ──────────────────────────────────────────────────────────────

/// Insert a user (replacing any existing one with the same email) and return
/// the persisted [`User`].  Clean up with [`cleanup_user_by_id`].
pub async fn create_test_user(service: &AuthLib, user_request: RegisterUser) -> User {
    if let Some(u) = service
        .users()
        .find_by_email(&user_request.email)
        .await
        .expect("find user by email failed")
    {
        cleanup_user_by_id(service, u.id)
            .await
            .expect("user cleanup failed");
    }
    service
        .users()
        .register(user_request)
        .await
        .expect("create_test_user failed")
}

/// Delete a user by ID; returns `true` if a row was removed.
pub async fn cleanup_user_by_id(service: &AuthLib, id: uuid::Uuid) -> Result<bool, AuthError> {
    service.users().delete(id).await.map(|res| res.is_some())
}

/// Delete a user by email if they exist.
pub async fn cleanup_user_by_email(
    service: &AuthLib,
    email: &str,
) -> Result<Option<uuid::Uuid>, AuthError> {
    match service.users().find_by_email(email).await? {
        Some(user) => service.users().delete(user.id).await,
        None => Ok(None),
    }
}

// ── Role helpers ──────────────────────────────────────────────────────────────

/// Insert a role (replacing any existing one with the same name) and return
/// the persisted [`Role`].
pub async fn create_test_role(service: &AuthLib, test_role: &NewRole) -> Role {
    if let Some(r) = service
        .roles()
        .find_by_name(&test_role.name)
        .await
        .expect("find_by_name failed")
    {
        cleanup_role_by_id(service, r.id)
            .await
            .expect("role cleanup failed");
    }
    service
        .roles()
        .create(test_role)
        .await
        .expect("create_test_role failed")
}

/// Delete a role by ID; returns `Some(id)` if a row was removed.
pub async fn cleanup_role_by_id(
    service: &AuthLib,
    role_id: uuid::Uuid,
) -> Result<Option<uuid::Uuid>, AuthError> {
    service.roles().delete(role_id).await
}

/// Delete a role by name if it exists.
pub async fn cleanup_role_by_name(
    service: &AuthLib,
    name: &str,
) -> Result<Option<uuid::Uuid>, AuthError> {
    match service.roles().find_by_name(name).await? {
        Some(role) => service.roles().delete(role.id).await,
        None => Ok(None),
    }
}
