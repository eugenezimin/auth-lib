//! API layer (handlers, DTO mapping, error mapping) and facade wiring.
// The facade's defaults need the `argon2` and `crypto` features.
#![cfg(all(feature = "argon2", feature = "crypto"))]

mod support;

use auth_lib::api::dto::{
    LoginRequest, RefreshRequest, RegisterRequest, RevokeRequest, RevokeTargetDto,
};
use auth_lib::api::{ApiError, handlers};
use auth_lib::constants::*;
use auth_lib::prelude::*;

use crate::support::{IP_A, VALID_PASSWORD, ctx, make_auth, register_and_login};

#[tokio::test]
async fn test_register_handler_returns_public_user() {
    let auth = make_auth();

    let res = handlers::register(
        auth.users(),
        RegisterRequest {
            email: "api@example.com".into(),
            password: VALID_PASSWORD.into(),
            username: Some("api".into()),
            first_name: None,
            last_name: None,
        },
    )
    .await
    .expect("register should succeed");

    assert_eq!(res.email, "api@example.com");
    assert_eq!(res.username.as_deref(), Some("api"));
    assert!(res.is_active);
}

#[tokio::test]
async fn test_register_handler_maps_errors() {
    let auth = make_auth();
    let req = || RegisterRequest {
        email: "dup@example.com".into(),
        password: VALID_PASSWORD.into(),
        username: None,
        first_name: None,
        last_name: None,
    };
    handlers::register(auth.users(), req()).await.unwrap();

    let err = handlers::register(auth.users(), req())
        .await
        .expect_err("duplicate must fail");
    assert_eq!(err.status, HTTP_CONFLICT);
    assert_eq!(err.code, "email_already_taken");
}

#[test]
fn test_api_error_hides_internal_details() {
    let err = ApiError::from(AuthError::Storage("connection refused to 10.0.0.5".into()));
    assert_eq!(err.status, HTTP_INTERNAL_SERVER_ERROR);
    assert_eq!(err.message, INTERNAL_ERROR_MESSAGE);
    assert_eq!(err.body().code, "storage_error");
}

#[test]
fn test_api_error_client_statuses() {
    let cases = [
        (AuthError::InvalidCredentials, HTTP_UNAUTHORIZED),
        (AuthError::TokenRevoked, HTTP_UNAUTHORIZED),
        (AuthError::AccountDisabled, HTTP_FORBIDDEN),
        (AuthError::UserNotFound, HTTP_NOT_FOUND),
        (
            AuthError::WeakPassword("x".into()),
            HTTP_UNPROCESSABLE_ENTITY,
        ),
    ];
    for (err, status) in cases {
        assert_eq!(ApiError::from(err).status, status);
    }
}

#[tokio::test]
async fn test_login_refresh_logout_all_handlers() {
    let auth = make_auth();
    let (_, _) = register_and_login(&auth, "flow@example.com", IP_A).await;

    let pair = handlers::login(
        auth.authentication(),
        LoginRequest {
            email: "flow@example.com".into(),
            password: VALID_PASSWORD.into(),
        },
        ctx(IP_A),
    )
    .await
    .unwrap();

    let next = handlers::refresh(
        auth.authentication(),
        RefreshRequest {
            access_token: pair.access_token.clone(),
            refresh_token: pair.refresh_token.clone(),
        },
        ctx(IP_A),
    )
    .await
    .unwrap();
    assert_eq!(next.session_id, pair.session_id);

    let ended = handlers::logout_all(auth.authentication(), &next.access_token)
        .await
        .unwrap();
    assert_eq!(ended, 2);
    let err = handlers::logout_all(auth.authentication(), &next.access_token)
        .await
        .unwrap_err();
    assert_eq!(err.status, HTTP_UNAUTHORIZED);
    assert_eq!(err.code, "token_revoked");
}

#[tokio::test]
async fn test_revoke_handler_ends_sessions() {
    let auth = make_auth();
    let (_, pair) = register_and_login(&auth, "revoke@example.com", IP_A).await;

    let res = handlers::revoke(
        auth.revocation(),
        RevokeRequest {
            targets: vec![RevokeTargetDto::AccessToken(pair.access_token.clone())],
            reason: RevocationReason::Compromised,
        },
    )
    .await
    .unwrap();
    assert_eq!(res.sessions_ended, 1);
    assert!(auth.verifier().verify(&pair.access_token).is_err());
}

#[test]
fn test_request_debug_redacts_secrets() {
    let dbg = format!(
        "{:?} {:?}",
        LoginRequest {
            email: "e@example.com".into(),
            password: "hunter2-Secret".into(),
        },
        RefreshRequest {
            access_token: "access-secret".into(),
            refresh_token: "refresh-secret".into(),
        }
    );
    assert!(
        !dbg.contains("hunter2")
            && !dbg.contains("access-secret")
            && !dbg.contains("refresh-secret")
    );
}

#[cfg(feature = "serde")]
#[test]
fn test_revoke_request_wire_format() {
    let json = r#"{
        "targets": [
            {"type": "access_token", "value": "abc"},
            {"type": "session", "value": "6f9619ff-8b86-d011-b42d-00c04fc964ff"}
        ],
        "reason": "compromised"
    }"#;
    let req: RevokeRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.targets.len(), 2);
    assert!(matches!(req.targets[0], RevokeTargetDto::AccessToken(ref t) if t == "abc"));
    assert_eq!(req.reason, RevocationReason::Compromised);
}
