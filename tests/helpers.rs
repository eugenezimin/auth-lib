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
    auth::service::AuthServiceImpl,
    interfaces::{auth::AuthService, config::DirectLoader},
    model::{
        config::{Config, DatabaseBackend, RawConfig},
        role::{NewRole, Role},
        user::{RegisterRequest, RegisterResponse},
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

pub async fn make_service() -> Arc<dyn AuthService> {
    let cfg = init_config();
    let service: Arc<dyn AuthService> = AuthServiceImpl::build(&cfg.database)
        .await
        .expect("Failed to build auth service");
    service
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
pub async fn create_test_user(service: &Arc<dyn AuthService>) -> RegisterResponse {
    let new_user = RegisterRequest {
        email: unique_email("test_user"),
        password: "blablabla".into(),
        username: None,
        first_name: None,
        last_name: None,
    };
    service
        .register(new_user)
        .await
        .expect("create_test_user failed")
}

/// Delete a user by ID; returns `true` if a row was removed.
pub async fn cleanup_user_by_id(
    service: &Arc<dyn AuthService>,
    id: uuid::Uuid,
) -> Result<bool, AuthError> {
    service.delete_user(id).await.map(|res| res.is_some())
}

/// Delete a user by email if they exist.
pub async fn cleanup_user_by_email(
    service: &Arc<dyn AuthService>,
    email: &str,
) -> Result<Option<uuid::Uuid>, AuthError> {
    let user_id = service.find_user_by_email(email).await?.map(|user| user.id);

    if let Some(id) = user_id {
        service.delete_user(id).await?;
        return Ok(Some(id));
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
pub async fn create_test_role(service: &Arc<dyn AuthService>) -> Role {
    let name = unique_name("test_role");
    service
        .create_role(&NewRole {
            name,
            description: Some("Created by test helper".into()),
        })
        .await
        .expect("create_test_role failed")
}

/// Delete a role by ID; returns `true` if a row was removed.
pub async fn cleanup_role_by_id(
    service: &Arc<dyn AuthService>,
    role_id: uuid::Uuid,
) -> Result<Option<uuid::Uuid>, AuthError> {
    service.delete_role(role_id).await
}

/// Delete a role by name if it exists.
pub async fn cleanup_role_by_name(
    service: &Arc<dyn AuthService>,
    name: &str,
) -> Result<Option<uuid::Uuid>, AuthError> {
    if let Some(role) = service.find_role_by_name(name).await? {
        service.delete_role(role.id).await?;
        return Ok(Some(role.id));
    }
    Ok(None)
}
