//! Integration tests — user registration
//!
//! These tests talk to a real PostgreSQL database.
//! Set the same env-vars (or `.env`) that the application uses:
//!
//!   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
//!   JWT_SECRET
//!
//! Run with:
//!   cargo test --test registration_test -- --test-threads=1
//!
//! `--test-threads=1` keeps tests sequential so each one starts from a clean
//! slate without races on shared database state.

use auth_lib::{
    interfaces::auth::AuthService,
    model::{
        config::Config,
        storage::postgres::PgUserRepo,
        user::{RegisterRequest, User},
    },
    storage::pg_pool::build_pool,
};

/// Initialize config once from env / `.env`.
/// `OnceLock` inside `Config` means only the first call does real work.
fn init_config() -> &'static Config {
    if Config::is_initialized() {
        return Config::global();
    }
    Config::init().expect("Failed to load config from environment")
}

/// Build a fresh [`AuthService`] backed by a real pool.
async fn make_service() -> AuthService<PgUserRepo> {
    let cfg = init_config();
    let pool = build_pool(&cfg.database)
        .await
        .expect("Failed to build DB pool");
    let user_repo = PgUserRepo::new(pool);
    AuthService::new(user_repo, cfg.jwt.clone())
}

/// Delete a user by email so each test can start from a known state.
/// Silently succeeds if the user does not exist.
async fn cleanup_user(service: &AuthService<PgUserRepo>, email: &str) {
    let _ = service.user_repo().delete_by_email(email).await;
}

// ── Helpers for building requests ─────────────────────────────────────────────

fn valid_request() -> RegisterRequest {
    RegisterRequest {
        email: "alice@example.com".into(),
        password: "S3cur3P@ssw0rd!".into(),
        username: Some("alice".into()),
        first_name: Some("Alice".into()),
        last_name: Some("Smith".into()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Happy-path tests
// ─────────────────────────────────────────────────────────────────────────────

/// A valid registration should succeed and return a populated `User`.
#[tokio::test]
async fn test_register_success() {
    let service = make_service().await;
    cleanup_user(&service, "alice@example.com").await;

    let req = valid_request();
    let user: User = service
        .register(req)
        .await
        .expect("Registration should succeed");

    assert!(!user.id.to_string().is_empty(), "id must be set");
    assert_eq!(user.email, "alice@example.com");
    assert_eq!(user.username.as_deref(), Some("alice"));
    assert_eq!(user.first_name.as_deref(), Some("Alice"));
    assert_eq!(user.last_name.as_deref(), Some("Smith"));
    assert!(user.is_active, "new user should be active");
    assert!(!user.is_verified, "new user should not be verified yet");

    // password_hash must be stored but must NOT equal the plain-text password
    let hash = user.password_hash.expect("password_hash must be stored");
    assert_ne!(
        hash, "S3cur3P@ssw0rd!",
        "plain-text password must never be stored"
    );
    assert!(
        hash.starts_with("$argon2") || hash.starts_with("$2b"),
        "hash should use argon2 or bcrypt, got: {hash}"
    );

    cleanup_user(&service, "alice@example.com").await;
}

/// Optional fields (username, first_name, last_name) may all be omitted.
#[tokio::test]
async fn test_register_minimal_fields() {
    let service = make_service().await;
    cleanup_user(&service, "minimal@example.com").await;

    let req = RegisterRequest {
        email: "minimal@example.com".into(),
        password: "ValidP@ss1".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    let user = service
        .register(req)
        .await
        .expect("Registration with only email+password should succeed");

    assert_eq!(user.email, "minimal@example.com");
    assert!(user.username.is_none());
    assert!(user.first_name.is_none());
    assert!(user.last_name.is_none());

    cleanup_user(&service, "minimal@example.com").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Uniqueness constraint tests
// ─────────────────────────────────────────────────────────────────────────────

/// Registering twice with the same email must fail with a duplicate-email error.
#[tokio::test]
async fn test_register_duplicate_email() {
    let service = make_service().await;
    cleanup_user(&service, "dup@example.com").await;

    let req = || RegisterRequest {
        email: "dup@example.com".into(),
        password: "ValidP@ss1".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    service
        .register(req())
        .await
        .expect("First registration should succeed");

    let err = service
        .register(req())
        .await
        .expect_err("Second registration with same email must fail");

    // The error should clearly indicate a duplicate email.
    // Adjust the variant name to match your AuthError enum.
    assert!(
        matches!(err, auth_lib::model::auth::AuthError::DuplicateEmail)
            || err.to_string().to_lowercase().contains("email"),
        "Expected a duplicate-email error, got: {err:?}"
    );

    cleanup_user(&service, "dup@example.com").await;
}

/// Registering twice with the same username must fail with a duplicate-username error.
#[tokio::test]
async fn test_register_duplicate_username() {
    let service = make_service().await;
    cleanup_user(&service, "user_a@example.com").await;
    cleanup_user(&service, "user_b@example.com").await;

    let first = RegisterRequest {
        email: "user_a@example.com".into(),
        password: "ValidP@ss1".into(),
        username: Some("taken_name".into()),
        first_name: None,
        last_name: None,
    };
    let second = RegisterRequest {
        email: "user_b@example.com".into(), // different email
        password: "ValidP@ss1".into(),
        username: Some("taken_name".into()), // same username
        first_name: None,
        last_name: None,
    };

    service
        .register(first)
        .await
        .expect("First registration should succeed");

    let err = service
        .register(second)
        .await
        .expect_err("Registration with duplicate username must fail");

    assert!(
        matches!(err, auth_lib::model::auth::AuthError::DuplicateUsername)
            || err.to_string().to_lowercase().contains("username"),
        "Expected a duplicate-username error, got: {err:?}"
    );

    cleanup_user(&service, "user_a@example.com").await;
    cleanup_user(&service, "user_b@example.com").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation / input tests
// ─────────────────────────────────────────────────────────────────────────────

/// An empty email string must be rejected before hitting the database.
#[tokio::test]
async fn test_register_empty_email_rejected() {
    let service = make_service().await;

    let req = RegisterRequest {
        email: "".into(),
        password: "ValidP@ss1".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    let err = service
        .register(req)
        .await
        .expect_err("Empty email must be rejected");

    assert!(
        matches!(err, auth_lib::model::auth::AuthError::InvalidEmail)
            || err.to_string().to_lowercase().contains("email"),
        "Expected an invalid-email error, got: {err:?}"
    );
}

/// A malformed email address (no `@`) must be rejected.
#[tokio::test]
async fn test_register_malformed_email_rejected() {
    let service = make_service().await;

    let req = RegisterRequest {
        email: "not-an-email".into(),
        password: "ValidP@ss1".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    let err = service
        .register(req)
        .await
        .expect_err("Malformed email must be rejected");

    assert!(
        matches!(err, auth_lib::model::auth::AuthError::InvalidEmail)
            || err.to_string().to_lowercase().contains("email"),
        "Expected an invalid-email error, got: {err:?}"
    );
}

/// An empty password must be rejected.
#[tokio::test]
async fn test_register_empty_password_rejected() {
    let service = make_service().await;

    let req = RegisterRequest {
        email: "pw_test@example.com".into(),
        password: "".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    let err = service
        .register(req)
        .await
        .expect_err("Empty password must be rejected");

    assert!(
        matches!(err, auth_lib::model::auth::AuthError::WeakPassword)
            || err.to_string().to_lowercase().contains("password"),
        "Expected a weak/empty-password error, got: {err:?}"
    );
}

/// A password that is too short must be rejected.
#[tokio::test]
async fn test_register_short_password_rejected() {
    let service = make_service().await;

    let req = RegisterRequest {
        email: "short_pw@example.com".into(),
        password: "abc".into(), // under any reasonable minimum length
        username: None,
        first_name: None,
        last_name: None,
    };

    let err = service
        .register(req)
        .await
        .expect_err("Too-short password must be rejected");

    assert!(
        matches!(err, auth_lib::model::auth::AuthError::WeakPassword)
            || err.to_string().to_lowercase().contains("password"),
        "Expected a weak-password error, got: {err:?}"
    );
}

/// Whitespace-only email must be rejected (not silently trimmed to empty).
#[tokio::test]
async fn test_register_whitespace_email_rejected() {
    let service = make_service().await;

    let req = RegisterRequest {
        email: "   ".into(),
        password: "ValidP@ss1".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    let err = service
        .register(req)
        .await
        .expect_err("Whitespace-only email must be rejected");

    assert!(
        err.to_string().to_lowercase().contains("email"),
        "Expected an email-related error, got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DB-level constraint guard test
// ─────────────────────────────────────────────────────────────────────────────

/// Even if service-layer validation is bypassed, the DB unique index on `email`
/// prevents a duplicate row from being committed.
///
/// This test inserts a user directly via the repo (skipping service validation)
/// and then tries to insert the same email again, expecting a storage error.
#[tokio::test]
async fn test_db_unique_index_rejects_duplicate_email() {
    use auth_lib::{interfaces::user_repo::UserRepo, model::user::NewUser};

    let service = make_service().await;
    let repo = service.user_repo();
    cleanup_user(&service, "idx@example.com").await;

    let new_user = NewUser {
        email: "idx@example.com".into(),
        password_hash: Some("hashed".into()),
        username: None,
        first_name: None,
        last_name: None,
        avatar_url: None,
    };

    repo.create(new_user.clone())
        .await
        .expect("First insert should succeed");

    let err = repo
        .create(new_user)
        .await
        .expect_err("Second insert with same email must fail at the DB level");

    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unique") || msg.contains("duplicate") || msg.contains("email"),
        "Expected a DB uniqueness error, got: {err:?}"
    );

    cleanup_user(&service, "idx@example.com").await;
}
