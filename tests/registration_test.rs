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

use std::sync::Arc;

use auth_lib::{
    auth::register::AuthServiceImpl,
    interfaces::{auth::AuthService, config::DirectLoader, user_repo::UserRepo},
    model::{
        config::{Config, RawConfig},
        user::{NewUser, RegisterRequest, RegisterResponse},
    },
    storage::pg_pool::{PgUserRepo, build_pool},
    utils::errors::AuthError,
};

/// Initialize config once from env / `.env`.
/// `OnceLock` inside `Config` means only the first call does real work.
fn init_config() -> &'static Config {
    if Config::is_initialized() {
        return Config::global();
    }

    Config::init_with(DirectLoader::new(
        RawConfig::default()
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
    .expect("Failed to load config from environment")
}

/// Build a fresh `AuthServiceImpl` backed by a real Postgres pool.
fn make_service() -> AuthServiceImpl {
    let cfg = init_config();
    let pool = build_pool(&cfg.database).expect("Failed to build DB pool");
    let user_repo = Arc::new(PgUserRepo::new(pool));
    AuthServiceImpl::new(user_repo)
}

/// Build a bare `PgUserRepo` for tests that bypass the service layer.
fn make_repo() -> PgUserRepo {
    let cfg = init_config();
    let pool = build_pool(&cfg.database).expect("Failed to build DB pool");
    PgUserRepo::new(pool)
}

/// Delete a user by email so each test can start from a known state.
async fn cleanup_user(repo: &PgUserRepo, email: &str) {
    let u_exists = repo.find_by_email(email).await;
    if let Ok(Some(_)) = u_exists {
        let client = repo.pg_pool.get().await.expect("pool get failed");
        client
            .execute("DELETE FROM users WHERE email = $1", &[&email])
            .await
            .expect("cleanup DELETE failed");
    }
}

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

#[tokio::test]
async fn test_register_success() {
    let repo = make_repo();
    let service = make_service();
    cleanup_user(&repo, "alice@example.com").await;

    let res: RegisterResponse = service
        .register(valid_request())
        .await
        .expect("Registration should succeed");

    assert!(!res.user_id.to_string().is_empty(), "user_id must be set");
    assert_eq!(res.email, "alice@example.com");
    assert_eq!(res.username, Some("alice".into()));

    let user = repo
        .find_by_email("alice@example.com")
        .await
        .expect("DB query failed")
        .expect("user should exist in DB after registration");

    assert_eq!(user.first_name.as_deref(), Some("Alice"));
    assert_eq!(user.last_name.as_deref(), Some("Smith"));
    assert!(user.is_active, "new user should be active");
    assert!(!user.is_verified, "new user should not be verified yet");

    let hash = user.password_hash.expect("password_hash must be stored");
    assert_ne!(
        hash, "S3cur3P@ssw0rd!",
        "plain-text password must never be stored"
    );
    assert!(
        hash.starts_with("$argon2") || hash.starts_with("$2b"),
        "hash should use argon2 or bcrypt, got: {hash}"
    );

    cleanup_user(&repo, "alice@example.com").await;
}

#[tokio::test]
async fn test_register_minimal_fields() {
    let repo = make_repo();
    let service = make_service();
    cleanup_user(&repo, "minimal@example.com").await;

    let req = RegisterRequest {
        email: "minimal@example.com".into(),
        password: "ValidP@ss1".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    let res = service
        .register(req)
        .await
        .expect("Registration with only email + password should succeed");

    assert_eq!(res.email, "minimal@example.com");
    assert!(res.username.is_none());

    let user = repo
        .find_by_email("minimal@example.com")
        .await
        .expect("DB query failed")
        .expect("user should exist in DB");

    assert!(user.username.is_none());
    assert!(user.first_name.is_none());
    assert!(user.last_name.is_none());

    cleanup_user(&repo, "minimal@example.com").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Uniqueness constraint tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_register_duplicate_email() {
    let repo = make_repo();
    let service = make_service();
    cleanup_user(&repo, "dup@example.com").await;

    let make_req = || RegisterRequest {
        email: "dup@example.com".into(),
        password: "ValidP@ss1".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    service
        .register(make_req())
        .await
        .expect("First registration should succeed");

    let err = service
        .register(make_req())
        .await
        .expect_err("Second registration with the same email must fail");

    assert!(
        matches!(err, AuthError::EmailAlreadyTaken),
        "Expected AuthError::EmailAlreadyTaken, got: {err:?}"
    );

    cleanup_user(&repo, "dup@example.com").await;
}

#[tokio::test]
async fn test_register_duplicate_username() {
    let repo = make_repo();
    let service = make_service();
    cleanup_user(&repo, "user_a@example.com").await;
    cleanup_user(&repo, "user_b@example.com").await;

    let first = RegisterRequest {
        email: "user_a@example.com".into(),
        password: "ValidP@ss1".into(),
        username: Some("taken_name".into()),
        first_name: None,
        last_name: None,
    };
    let second = RegisterRequest {
        email: "user_b@example.com".into(),
        password: "ValidP@ss1".into(),
        username: Some("taken_name".into()),
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
        .expect_err("Registration with a duplicate username must fail");

    assert!(
        matches!(err, AuthError::UsernameAlreadyTaken),
        "Expected AuthError::UsernameAlreadyTaken, got: {err:?}"
    );

    cleanup_user(&repo, "user_a@example.com").await;
    cleanup_user(&repo, "user_b@example.com").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Input validation tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_register_empty_email_rejected() {
    let err = make_service()
        .register(RegisterRequest {
            email: "".into(),
            password: "ValidP@ss1".into(),
            username: None,
            first_name: None,
            last_name: None,
        })
        .await
        .expect_err("Empty email must be rejected");
    assert!(matches!(err, AuthError::InvalidEmail(_)));
}

#[tokio::test]
async fn test_register_malformed_email_rejected() {
    let err = make_service()
        .register(RegisterRequest {
            email: "not-an-email".into(),
            password: "ValidP@ss1".into(),
            username: None,
            first_name: None,
            last_name: None,
        })
        .await
        .expect_err("Malformed email must be rejected");
    assert!(matches!(err, AuthError::InvalidEmail(_)));
}

#[tokio::test]
async fn test_register_whitespace_email_rejected() {
    let err = make_service()
        .register(RegisterRequest {
            email: "   ".into(),
            password: "ValidP@ss1".into(),
            username: None,
            first_name: None,
            last_name: None,
        })
        .await
        .expect_err("Whitespace-only email must be rejected");
    assert!(matches!(err, AuthError::InvalidEmail(_)));
}

#[tokio::test]
async fn test_register_empty_password_rejected() {
    let err = make_service()
        .register(RegisterRequest {
            email: "pw_test@example.com".into(),
            password: "".into(),
            username: None,
            first_name: None,
            last_name: None,
        })
        .await
        .expect_err("Empty password must be rejected");
    assert!(matches!(err, AuthError::WeakPassword(_)));
}

#[tokio::test]
async fn test_register_short_password_rejected() {
    let err = make_service()
        .register(RegisterRequest {
            email: "short_pw@example.com".into(),
            password: "abc".into(),
            username: None,
            first_name: None,
            last_name: None,
        })
        .await
        .expect_err("Too-short password must be rejected");
    assert!(matches!(err, AuthError::WeakPassword(_)));
}

// ─────────────────────────────────────────────────────────────────────────────
// DB-level constraint guard
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_db_unique_index_rejects_duplicate_email() {
    let repo = make_repo();
    cleanup_user(&repo, "idx@example.com").await;

    let new_user = NewUser {
        email: "idx@example.com".into(),
        password_hash: "argon2_hashed_value".into(),
        jwt_secret: "some-random-secret".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    repo.create(new_user.clone())
        .await
        .expect("First insert should succeed");

    let err = repo
        .create(new_user)
        .await
        .expect_err("Second insert with the same email must fail at DB level");

    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unique") || msg.contains("duplicate") || msg.contains("email"),
        "Expected a DB uniqueness violation, got: {err:?}"
    );

    cleanup_user(&repo, "idx@example.com").await;
}
