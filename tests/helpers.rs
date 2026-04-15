/// Shared helpers for auth-lib integration tests.
///
/// Import with:
///   mod helpers;
///   use helpers::*;
///
/// Every public function is cheap to call and idempotent — safe to use in
/// any test order with `--test-threads=N`.
use std::sync::Arc;

use auth_lib::{
    auth::register::AuthServiceImpl,
    interfaces::{
        config::DirectLoader,
        db::{role_repo::RoleRepo, user_repo::UserRepo, user_role_repo::UserRoleRepo},
    },
    model::{
        config::{Config, DatabaseBackend, RawConfig},
        role::{NewRole, Role},
        user::{NewUser, RegisterRequest, User},
    },
    storage::{
        db_factory::{build_role_repo, build_user_repo, build_user_role_repo},
        postgres::pg_pool::{PgRoleRepo, PgUserRepo, PgUserRoleRepo, build_pool},
    },
    utils::errors::AuthError,
};

// ── Config ────────────────────────────────────────────────────────────────────

pub fn init_config() -> &'static Config {
    if Config::is_initialized() {
        return Config::global();
    }
    Config::init_with(DirectLoader::new(
        RawConfig::default()
            .db_backend(DatabaseBackend::Postgres)
            .db_host("localhost")
            .db_port(5432)
            .db_user("postgres")
            .db_password("passw")
            .db_name("auth")
            .db_max_pool_size(20)
            .db_connect_timeout_secs(10)
            .jwt_secret("my-very-long-jwt-signing-secret")
            .jwt_access_expiry_secs(900)
            .jwt_refresh_expiry_secs(604_800)
            .jwt_issuer("auth-lib-test"),
    ))
    .expect("Failed to load test config")
}

// ── Repo factories ────────────────────────────────────────────────────────────

pub async fn make_user_repo() -> Arc<dyn UserRepo> {
    let cfg = init_config();
    build_user_repo(&cfg.database)
        .await
        .expect("Failed to build user repo")
}

pub async fn make_role_repo() -> Arc<dyn RoleRepo> {
    let cfg = init_config();
    build_role_repo(&cfg.database)
        .await
        .expect("Failed to build role repo")
}

pub async fn make_user_role_repo() -> Arc<dyn UserRoleRepo> {
    let cfg = init_config();
    build_user_role_repo(&cfg.database)
        .await
        .expect("Failed to build user_role repo")
}

pub async fn make_service() -> AuthServiceImpl {
    let cfg = init_config();
    let pool = build_pool(&cfg.database)
        .await
        .expect("Failed to build DB pool");
    let user_repo = Arc::new(PgUserRepo::new(pool.clone()));
    let role_repo = Arc::new(PgRoleRepo::new(pool));

    return AuthServiceImpl::new(user_repo, role_repo);
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

/// Insert a minimal valid user and return the persisted [`User`].
///
/// The email is unique per call — no cleanup needed before creation.
/// Always clean up with [`cleanup_user_by_id`] after the test.
pub async fn create_test_user(repo: &Arc<dyn UserRepo>) -> User {
    let new_user = NewUser {
        email: unique_email("test_user"),
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$stub$stub".into(),
        jwt_secret: uuid::Uuid::new_v4().to_string(),
        username: None,
        first_name: None,
        last_name: None,
    };
    repo.create(new_user)
        .await
        .expect("create_test_user failed")
}

/// Delete a user by ID; returns `true` if a row was removed.
pub async fn cleanup_user_by_id(
    repo: &Arc<dyn UserRepo>,
    id: uuid::Uuid,
) -> Result<bool, AuthError> {
    repo.delete(id).await
}

/// Delete a user by email if they exist.
pub async fn cleanup_user_by_email(
    repo: &Arc<dyn UserRepo>,
    email: &str,
) -> Result<Option<uuid::Uuid>, AuthError> {
    if let Some(user) = repo.find_by_email(email).await? {
        repo.delete(user.id).await?;
        return Ok(Some(user.id));
    }
    Ok(None)
}

pub fn make_register_request(email: &str, password: &str) -> RegisterRequest {
    RegisterRequest {
        email: email.into(),
        password: password.into(),
        username: None,
        first_name: None,
        last_name: None,
    }
}

// ── Role helpers ──────────────────────────────────────────────────────────────

/// Insert a role with a unique name and return the persisted [`Role`].
pub async fn create_test_role(repo: &Arc<dyn RoleRepo>) -> Role {
    let name = unique_name("test_role");
    repo.create(NewRole {
        name,
        description: Some("Created by test helper".into()),
    })
    .await
    .expect("create_test_role failed")
}

/// Delete a role by ID; returns `true` if a row was removed.
pub async fn cleanup_role_by_id(
    repo: &Arc<dyn RoleRepo>,
    id: uuid::Uuid,
) -> Result<bool, AuthError> {
    repo.delete(id).await
}

/// Delete a role by name if it exists.
pub async fn cleanup_role_by_name(
    repo: &Arc<dyn RoleRepo>,
    name: &str,
) -> Result<Option<uuid::Uuid>, AuthError> {
    if let Some(role) = repo.find_by_name(name).await? {
        repo.delete(role.id).await?;
        return Ok(Some(role.id));
    }
    Ok(None)
}
