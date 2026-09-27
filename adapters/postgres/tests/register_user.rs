//! Integration tests — user registration
//!
//! These tests talk to a real PostgreSQL database.
//! Set the same env-vars (or `.env`) that the application uses:
//!
//!   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME

///
/// Run with:
///   cargo test -p auth-lib-postgres --test registration_test -- --test-threads=1
///
/// `--test-threads=1` keeps tests sequential so each one starts from a clean
/// slate without races on shared database state.
///
/// Each test does cleanup → create → assert → cleanup to ensure it can be re-run without manual DB resets.
///
mod helpers;

use auth_lib::{
    AuthError,
    user::{NewUser, RegisterUser, UserRepository},
};
use auth_lib_postgres::PgUserRepository;

use crate::helpers::{cleanup_user_by_email, make_service, pool};

fn valid_request() -> RegisterUser {
    RegisterUser {
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

    let res = service
        .users()
        .register(valid_request())
        .await
        .expect("Registration should succeed");

    assert!(!res.id.is_nil(), "user id must be set");
    assert_eq!(res.email, "alice@example.com");
    assert_eq!(res.username, Some("alice".into()));

    let user = service
        .users()
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

    let req = RegisterUser {
        email: "minimal@example.com".into(),
        password: "ValidP@ss1".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    let res = service
        .users()
        .register(req)
        .await
        .expect("Registration with only email + password should succeed");

    assert_eq!(res.email, "minimal@example.com");
    assert!(res.username.is_none());

    let user = service
        .users()
        .find_by_email("minimal@example.com")
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

    let make_req = || RegisterUser {
        email: "dup@example.com".into(),
        password: "ValidP@ss1".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    service
        .users()
        .register(make_req())
        .await
        .expect("First registration should succeed");

    let err = service
        .users()
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

    let first = RegisterUser {
        email: "user_a@example.com".into(),
        password: "ValidP@ss1".into(),
        username: Some("taken_name".into()),
        first_name: None,
        last_name: None,
    };
    let second = RegisterUser {
        email: "user_b@example.com".into(),
        password: "ValidP@ss1".into(),
        username: Some("taken_name".into()),
        first_name: None,
        last_name: None,
    };

    service
        .users()
        .register(first)
        .await
        .expect("First registration should succeed");

    let err = service
        .users()
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
        .users()
        .register(RegisterUser {
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
        .users()
        .register(RegisterUser {
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
        .users()
        .register(RegisterUser {
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
        .users()
        .register(RegisterUser {
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
    let register_request = RegisterUser {
        email: "idx@example.com".into(),
        password: "BlaBlaBla123!".into(),
        username: None,
        first_name: None,
        last_name: None,
    };

    // First registration should succeed through the service layer
    // which talks to the DB and applies all validations
    service
        .users()
        .register(register_request.clone())
        .await
        .expect("First insert should succeed");

    // Second registration with the same email should fail at the DB level due to the unique index
    let err = service
        .users()
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

/// Goes straight to the repository (no service-side normalization) so the
/// `lower(email)` / `lower(username)` indexes themselves are exercised, along
/// with their constraint-name → error mapping.
#[tokio::test]
async fn test_db_unique_indexes_are_case_insensitive() {
    let repo = PgUserRepository::new(pool().await);
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let new_user = |email: String, username: String| NewUser {
        email,
        password_hash: "not-a-real-hash".into(),
        username: Some(username),
        first_name: None,
        last_name: None,
    };

    let user = repo
        .create(new_user(
            format!("Case_{tag}@Example.com"),
            format!("Name_{tag}"),
        ))
        .await
        .expect("first insert should succeed");

    let err = repo
        .create(new_user(
            format!("case_{tag}@example.com"),
            format!("other_{tag}"),
        ))
        .await
        .expect_err("email differing only in case must violate users_email");
    assert!(matches!(err, AuthError::EmailAlreadyTaken), "got: {err:?}");

    let err = repo
        .create(new_user(
            format!("other_{tag}@example.com"),
            format!("NAME_{tag}"),
        ))
        .await
        .expect_err("username differing only in case must violate users_username_key");
    assert!(
        matches!(err, AuthError::UsernameAlreadyTaken),
        "got: {err:?}"
    );

    let found = repo
        .find_by_username(&format!("name_{tag}"))
        .await
        .unwrap()
        .expect("username lookup ignores case");
    assert_eq!(found.id, user.id);
    assert_eq!(
        found.username,
        Some(format!("Name_{tag}")),
        "display case kept"
    );
    assert!(
        repo.exists_by_email(&format!("CASE_{tag}@EXAMPLE.COM"))
            .await
            .unwrap()
    );

    repo.delete(user.id).await.unwrap();
}
