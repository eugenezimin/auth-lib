/// Integration tests — user registration
///
/// These tests talk to a real PostgreSQL database.
/// Set the same env-vars (or `.env`) that the application uses:
///
///   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
///   JWT_SECRET
///
/// Run with:
///   cargo test --test registration_test -- --test-threads=1
///
/// `--test-threads=1` keeps tests sequential so each one starts from a clean
/// slate without races on shared database state.
///
/// Each test does cleanup → create → assert → cleanup to ensure it can be re-run without manual DB resets.
///
mod helpers;

use auth_lib::{
    model::user::{RegisterRequest, RegisterResponse},
    utils::errors::AuthError,
};

use crate::helpers::{cleanup_user_by_email, make_service};

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
    let service = make_service().await;
    cleanup_user_by_email(&service, "alice@example.com")
        .await
        .expect("cleanup of alice@example.com failed");

    let res: RegisterResponse = RegisterResponse::from_user(
        service
            .register(valid_request())
            .await
            .expect("Registration should succeed"),
    );

    assert!(!res.user_id.to_string().is_empty(), "user_id must be set");
    assert_eq!(res.email, "alice@example.com");
    assert_eq!(res.username, Some("alice".into()));

    let user = service
        .find_user_by_email("alice@example.com")
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

    cleanup_user_by_email(&service, "alice@example.com")
        .await
        .expect("cleanup of alice@example.com failed");
}

#[tokio::test]
async fn test_register_minimal_fields() {
    let service = make_service().await;
    cleanup_user_by_email(&service, "minimal@example.com")
        .await
        .expect("cleanup of minimal@example.com failed");

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

    let user = service
        .find_user_by_email("minimal@example.com")
        .await
        .expect("DB query failed")
        .expect("user should exist in DB");

    assert!(user.username.is_none());
    assert!(user.first_name.is_none());
    assert!(user.last_name.is_none());

    cleanup_user_by_email(&service, "minimal@example.com")
        .await
        .expect("cleanup of minimal@example.com failed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Uniqueness constraint tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_register_duplicate_email() {
    let service = make_service().await;
    cleanup_user_by_email(&service, "dup@example.com")
        .await
        .expect("cleanup of dup@example.com failed");

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

    cleanup_user_by_email(&service, "dup@example.com")
        .await
        .expect("cleanup of dup@example.com failed");
}

#[tokio::test]
async fn test_register_duplicate_username() {
    let service = make_service().await;
    cleanup_user_by_email(&service, "user_a@example.com")
        .await
        .expect("cleanup of user_a@example.com failed");
    cleanup_user_by_email(&service, "user_b@example.com")
        .await
        .expect("cleanup of user_b@example.com failed");

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

    cleanup_user_by_email(&service, "user_a@example.com")
        .await
        .expect("cleanup of user_a@example.com failed");
    cleanup_user_by_email(&service, "user_b@example.com")
        .await
        .expect("cleanup of user_b@example.com failed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Input validation tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_register_empty_email_rejected() {
    let err = make_service()
        .await
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
        .await
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
async fn test_register_empty_password_rejected() {
    let err = make_service()
        .await
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
        .await
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
    // Create a service which contains a real DB connection to all repos
    let service = make_service().await;

    // Ensure the test email is not present before we start
    cleanup_user_by_email(&service, "idx@example.com")
        .await
        .expect("cleanup of idx@example.com failed");

    // Prepare a registration request with the test email
    let register_request = RegisterRequest {
        email: "idx@example.com".into(),
        password: "BlaBlaBla123!".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    // First registration should succeed through the service layer
    // which talks to the DB and applies all validations
    service
        .register(register_request.clone())
        .await
        .expect("First insert should succeed");

    // Second registration with the same email should fail at the DB level due to the unique index
    let err = service
        .register(register_request)
        .await
        .expect_err("Second insert with the same email must fail at DB level");

    assert!(
        matches!(err, AuthError::EmailAlreadyTaken) || {
            let msg = err.to_string().to_lowercase();
            msg.contains("unique") || msg.contains("duplicate") || msg.contains("email")
        },
        "Expected a DB uniqueness violation, got: {err:?}"
    );

    // Cleanup after the test to ensure it can be re-run without manual DB resets
    cleanup_user_by_email(&service, "idx@example.com")
        .await
        .expect("cleanup of idx@example.com failed");
}
