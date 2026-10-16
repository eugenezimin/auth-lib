//! Plain OAuth2 providers and the GitHub preset against a mock provider.

mod common;

use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use z_auth::prelude::*;
use z_auth_sso::CallbackOutcome;

use common::*;

async fn token_endpoint(server: &MockServer, at: &str, body: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path(at))
        .and(header("accept", "application/json"))
        .and(body_string_contains("client_secret=s3cret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn json_endpoint(server: &MockServer, at: &str, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(at))
        .and(header("authorization", "Bearer at-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// A Facebook-like provider: numeric-looking string id, no verified flag.
fn generic(server: &MockServer, extra: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    let base = server.uri();
    let mut settings = vec![
        ("kind", "oauth2".to_string()),
        ("issuer", "https://www.facebook.com".into()),
        ("authorize_url", format!("{base}/dialog/oauth")),
        ("token_url", format!("{base}/oauth/access_token")),
        ("userinfo_url", format!("{base}/me")),
        ("client_id", "fb-app".into()),
        ("client_secret", "s3cret".into()),
        ("scopes", "email,public_profile".into()),
        ("claims.subject", "/id".into()),
        ("claims.email", "/email".into()),
        ("claims.first_name", "/first_name".into()),
        ("provisioning", "create".into()),
    ];
    for (k, v) in extra {
        settings.retain(|(key, _)| key != k);
        settings.push((k, v.to_string()));
    }
    settings
}

#[tokio::test]
async fn a_generic_provider_maps_its_user_info() {
    let server = MockServer::start().await;
    token_endpoint(
        &server,
        "/oauth/access_token",
        json!({ "access_token": "at-1" }),
    )
    .await;
    json_endpoint(
        &server,
        "/me",
        json!({ "id": "10158", "email": "Erin@Example.com", "first_name": "Erin" }),
    )
    .await;
    let sso = sso(&[("facebook", generic(&server, &[]))]);
    let s = external_server(test_config());

    let redirect = sso.begin_login(&s.auth, "facebook").await.unwrap();
    let q = query(&redirect.url);
    assert_eq!(q["scope"], "email public_profile");
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(!q.contains_key("nonce"));

    let pair = tokens(finish(&sso, &s, &redirect, "code").await.unwrap());
    let c = claims(&s, &pair).await;
    let user = s.auth.users().find_by_id(c.sub).await.unwrap().unwrap();
    assert_eq!(user.email, "erin@example.com");
    assert_eq!(user.first_name.as_deref(), Some("Erin"));
    // No verified flag configured: the email is not taken as verified.
    assert!(!user.is_verified);
    let identity = &s.auth.account_links().list(c.sub).await.unwrap()[0];
    assert_eq!(
        (identity.issuer.as_str(), identity.subject.as_str()),
        ("https://www.facebook.com", "10158")
    );
}

#[tokio::test]
async fn unverified_emails_never_link_silently() {
    let server = MockServer::start().await;
    token_endpoint(
        &server,
        "/oauth/access_token",
        json!({ "access_token": "at-1" }),
    )
    .await;
    json_endpoint(
        &server,
        "/me",
        json!({ "id": "1", "email": "frank@example.com" }),
    )
    .await;
    let sso = sso(&[(
        "facebook",
        generic(
            &server,
            &[("link", "verified_email"), ("trust_email", "true")],
        ),
    )]);
    let s = external_server(test_config());
    let frank = register(&s.auth, "frank@example.com").await;
    s.db.set_verified(frank.id, true);

    let redirect = sso.begin_login(&s.auth, "facebook").await.unwrap();
    let outcome = finish(&sso, &s, &redirect, "code").await.unwrap();
    assert!(
        matches!(
            outcome,
            CallbackOutcome::Login(ExternalLoginOutcome::LinkConfirmation(_))
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn token_errors_reported_with_200_are_refused() {
    let server = MockServer::start().await;
    token_endpoint(
        &server,
        "/oauth/access_token",
        json!({ "error": "bad_verification_code", "error_description": "expired" }),
    )
    .await;
    let sso = sso(&[("facebook", generic(&server, &[]))]);
    let s = external_server(test_config());
    let redirect = sso.begin_login(&s.auth, "facebook").await.unwrap();
    let err = finish(&sso, &s, &redirect, "code").await;
    assert!(
        matches!(err, Err(AuthError::ExternalLoginFailed(_))),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_unreachable_provider_is_retryable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/access_token"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let sso = sso(&[("facebook", generic(&server, &[]))]);
    let s = external_server(test_config());
    let redirect = sso.begin_login(&s.auth, "facebook").await.unwrap();
    let err = finish(&sso, &s, &redirect, "code").await;
    assert!(
        matches!(err, Err(AuthError::ExternalProviderUnavailable(_))),
        "{err:?}"
    );
}

#[cfg(feature = "github")]
mod github {
    use super::*;

    fn github(server: &MockServer) -> Vec<(&'static str, String)> {
        let base = server.uri();
        vec![
            ("kind", "github".to_string()),
            ("client_id", "gh-app".into()),
            ("client_secret", "s3cret".into()),
            ("provisioning", "create".into()),
            ("authorize_url", format!("{base}/login/oauth/authorize")),
            ("token_url", format!("{base}/login/oauth/access_token")),
            ("userinfo_url", format!("{base}/user")),
            ("emails_url", format!("{base}/user/emails")),
        ]
    }

    async fn provider(emails: serde_json::Value) -> (MockServer, z_auth_sso::Sso) {
        let server = MockServer::start().await;
        token_endpoint(
            &server,
            "/login/oauth/access_token",
            json!({ "access_token": "at-1", "token_type": "bearer" }),
        )
        .await;
        json_endpoint(
            &server,
            "/user",
            json!({ "id": 583231, "login": "octocat", "name": "The Octocat" }),
        )
        .await;
        json_endpoint(&server, "/user/emails", emails).await;
        let sso = sso(&[("github", github(&server))]);
        (server, sso)
    }

    #[tokio::test]
    async fn github_signs_in_with_the_primary_verified_email() {
        let (_server, sso) = provider(json!([
            { "email": "old@example.com", "primary": false, "verified": true },
            { "email": "octo@example.com", "primary": true, "verified": true },
        ]))
        .await;
        let s = external_server(test_config());
        let redirect = sso.begin_login(&s.auth, "github").await.unwrap();
        assert_eq!(query(&redirect.url)["scope"], "read:user user:email");
        let c = claims(&s, &tokens(finish(&sso, &s, &redirect, "c").await.unwrap())).await;
        let user = s.auth.users().find_by_id(c.sub).await.unwrap().unwrap();
        assert_eq!(user.email, "octo@example.com");
        // GitHub's verified flag is trusted by default.
        assert!(user.is_verified);
        assert_eq!(user.username.as_deref(), Some("octocat"));
        let identity = &s.auth.account_links().list(c.sub).await.unwrap()[0];
        assert_eq!(
            (identity.issuer.as_str(), identity.subject.as_str()),
            ("https://github.com", "583231")
        );
    }

    #[tokio::test]
    async fn an_unverified_primary_email_is_passed_over() {
        let (_server, sso) = provider(json!([
            { "email": "squatted@example.com", "primary": true, "verified": false },
            { "email": "real@example.com", "primary": false, "verified": true },
        ]))
        .await;
        let s = external_server(test_config());
        let redirect = sso.begin_login(&s.auth, "github").await.unwrap();
        let c = claims(&s, &tokens(finish(&sso, &s, &redirect, "c").await.unwrap())).await;
        let user = s.auth.users().find_by_id(c.sub).await.unwrap().unwrap();
        assert_eq!(user.email, "real@example.com");
    }

    #[tokio::test]
    async fn without_a_verified_email_no_user_is_created() {
        let (_server, sso) = provider(json!([
            { "email": "x@example.com", "primary": true, "verified": false },
        ]))
        .await;
        let s = external_server(test_config());
        let redirect = sso.begin_login(&s.auth, "github").await.unwrap();
        let err = finish(&sso, &s, &redirect, "c").await;
        assert!(matches!(err, Err(AuthError::InvalidEmail(_))), "{err:?}");
    }
}
