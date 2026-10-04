//! User registration and profile management — against in-memory adapters.
// The facade's defaults need the `argon2` and `crypto` features.
#![cfg(all(feature = "argon2", feature = "crypto"))]

mod support;

use auth_lib::prelude::*;

use crate::support::{VALID_PASSWORD, make_auth, register_request};

fn full_request() -> RegisterUser {
    RegisterUser {
        email: "alice@example.com".into(),
        password: VALID_PASSWORD.into(),
        username: Some("alice".into()),
        first_name: Some("Alice".into()),
        last_name: Some("Smith".into()),
    }
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_register_success() {
    let auth = make_auth();

    let user = auth
        .users()
        .register(full_request())
        .await
        .expect("registration should succeed");

    assert_eq!(user.email, "alice@example.com");
    assert_eq!(user.username.as_deref(), Some("alice"));
    assert_eq!(user.first_name.as_deref(), Some("Alice"));
    assert_eq!(user.last_name.as_deref(), Some("Smith"));
    assert!(user.is_active, "new user should be active");
    assert!(!user.is_verified, "new user should not be verified yet");

    let hash = user.password_hash.expect("password_hash must be stored");
    assert_ne!(
        hash, VALID_PASSWORD,
        "plain-text password must never be stored"
    );
    assert!(
        hash.starts_with("$argon2"),
        "expected argon2 hash, got: {hash}"
    );

    let found = auth
        .users()
        .find_by_email("alice@example.com")
        .await
        .unwrap()
        .expect("user should exist after registration");
    assert_eq!(found.id, user.id);
}

#[tokio::test]
async fn test_register_minimal_fields() {
    let auth = make_auth();

    let user = auth
        .users()
        .register(register_request("minimal@example.com", None))
        .await
        .expect("email + password only should succeed");

    assert!(user.username.is_none());
    assert!(user.first_name.is_none());
    assert!(user.last_name.is_none());
}

// ── Uniqueness ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_register_duplicate_email() {
    let auth = make_auth();
    auth.users()
        .register(register_request("dup@example.com", None))
        .await
        .unwrap();

    let err = auth
        .users()
        .register(register_request("dup@example.com", None))
        .await
        .expect_err("duplicate email must fail");
    assert!(matches!(err, AuthError::EmailAlreadyTaken), "got: {err:?}");
}

#[tokio::test]
async fn test_register_duplicate_username() {
    let auth = make_auth();
    auth.users()
        .register(register_request("a@example.com", Some("taken")))
        .await
        .unwrap();

    let err = auth
        .users()
        .register(register_request("b@example.com", Some("taken")))
        .await
        .expect_err("duplicate username must fail");
    assert!(
        matches!(err, AuthError::UsernameAlreadyTaken),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn test_email_is_normalized_and_unique_case_insensitively() {
    let auth = make_auth();
    let user = auth
        .users()
        .register(register_request("  Alice@Example.COM ", None))
        .await
        .unwrap();
    assert_eq!(
        user.email, "alice@example.com",
        "stored email is normalized"
    );

    let err = auth
        .users()
        .register(register_request("ALICE@example.com", None))
        .await
        .expect_err("same email in another case must fail");
    assert!(matches!(err, AuthError::EmailAlreadyTaken), "got: {err:?}");

    let found = auth
        .users()
        .find_by_email("aLiCe@EXAMPLE.com")
        .await
        .unwrap()
        .expect("lookup ignores case");
    assert_eq!(found.id, user.id);
}

#[tokio::test]
async fn test_username_is_unique_case_insensitively_and_keeps_display_case() {
    let auth = make_auth();
    let user = auth
        .users()
        .register(register_request("a@example.com", Some("JohnDoe")))
        .await
        .unwrap();
    assert_eq!(user.username.as_deref(), Some("JohnDoe"));

    let err = auth
        .users()
        .register(register_request("b@example.com", Some("johndoe")))
        .await
        .expect_err("same username in another case must fail");
    assert!(
        matches!(err, AuthError::UsernameAlreadyTaken),
        "got: {err:?}"
    );

    let found = auth
        .users()
        .find_by_username("JOHNDOE")
        .await
        .unwrap()
        .expect("lookup ignores case");
    assert_eq!(found.id, user.id);
    assert_eq!(found.username.as_deref(), Some("JohnDoe"));
}

// ── Input validation ──────────────────────────────────────────────────────────

async fn register_err(email: &str, password: &str) -> AuthError {
    make_auth()
        .users()
        .register(RegisterUser {
            email: email.into(),
            password: password.into(),
            username: None,
            first_name: None,
            last_name: None,
        })
        .await
        .expect_err("registration must be rejected")
}

#[tokio::test]
async fn test_register_empty_email_rejected() {
    assert!(matches!(
        register_err("", VALID_PASSWORD).await,
        AuthError::InvalidEmail(_)
    ));
}

#[tokio::test]
async fn test_register_malformed_email_rejected() {
    assert!(matches!(
        register_err("not-an-email", VALID_PASSWORD).await,
        AuthError::InvalidEmail(_)
    ));
}

#[tokio::test]
async fn test_register_weak_passwords_rejected() {
    for pw in ["", "abc", "alllowercase1", "NoDigitsHere"] {
        assert!(
            matches!(
                register_err("pw@example.com", pw).await,
                AuthError::WeakPassword(_)
            ),
            "password {pw:?} should be rejected"
        );
    }
}

// ── Update / delete / activation ──────────────────────────────────────────────

#[tokio::test]
async fn test_update_rehashes_password_and_changes_fields() {
    let auth = make_auth();
    let user = auth.users().register(full_request()).await.unwrap();
    let old_hash = user.password_hash.clone().unwrap();

    let updated = auth
        .users()
        .update(
            user.id,
            UpdateUser {
                password: Some("An0therG00dOne".into()),
                first_name: Some("Alicia".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .expect("user exists");

    let new_hash = updated.password_hash.unwrap();
    assert_ne!(new_hash, old_hash);
    assert_ne!(
        new_hash, "An0therG00dOne",
        "raw password must never be stored"
    );
    assert!(new_hash.starts_with("$argon2"));
    assert_eq!(updated.first_name.as_deref(), Some("Alicia"));
    assert_eq!(updated.email, user.email, "unset fields stay unchanged");
}

#[tokio::test]
async fn test_update_rejects_weak_password_and_taken_email() {
    let auth = make_auth();
    let alice = auth.users().register(full_request()).await.unwrap();
    auth.users()
        .register(register_request("bob@example.com", None))
        .await
        .unwrap();

    let err = auth
        .users()
        .update(
            alice.id,
            UpdateUser {
                password: Some("weak".into()),
                ..Default::default()
            },
        )
        .await
        .expect_err("weak password must be rejected");
    assert!(matches!(err, AuthError::WeakPassword(_)));

    let err = auth
        .users()
        .update(
            alice.id,
            UpdateUser {
                email: Some("bob@example.com".into()),
                ..Default::default()
            },
        )
        .await
        .expect_err("taken email must be rejected");
    assert!(matches!(err, AuthError::EmailAlreadyTaken));

    // Re-submitting your own email is not a conflict.
    auth.users()
        .update(
            alice.id,
            UpdateUser {
                email: Some(alice.email.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("own email is allowed");
}

#[tokio::test]
async fn test_update_missing_user_returns_none() {
    let auth = make_auth();
    let res = auth
        .users()
        .update(uuid::Uuid::new_v4(), UpdateUser::default())
        .await
        .unwrap();
    assert!(res.is_none());
}

#[tokio::test]
async fn test_delete_reports_whether_user_existed() {
    let auth = make_auth();
    let user = auth.users().register(full_request()).await.unwrap();

    assert_eq!(auth.users().delete(user.id).await.unwrap(), Some(user.id));
    assert_eq!(auth.users().delete(user.id).await.unwrap(), None);
    assert!(auth.users().find_by_id(user.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_activate_deactivate() {
    let auth = make_auth();
    let user = auth.users().register(full_request()).await.unwrap();

    assert!(auth.users().deactivate(user.id).await.unwrap());
    assert!(
        !auth
            .users()
            .find_by_id(user.id)
            .await
            .unwrap()
            .unwrap()
            .is_active
    );
    assert!(auth.users().activate(user.id).await.unwrap());
    assert!(
        auth.users()
            .find_by_id(user.id)
            .await
            .unwrap()
            .unwrap()
            .is_active
    );
    assert!(!auth.users().activate(uuid::Uuid::new_v4()).await.unwrap());
}

#[tokio::test]
async fn test_user_debug_redacts_secrets() {
    let auth = make_auth();
    let user = auth.users().register(full_request()).await.unwrap();
    let dbg = format!("{user:?}");
    assert!(!dbg.contains(user.password_hash.as_deref().unwrap()));
}
