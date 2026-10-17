//! OpenID Connect sign-in against a mock provider (discovery, JWKS, token
//! endpoint, user info).
#![cfg(feature = "oidc")]

mod common;

use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use z_auth::prelude::*;
use z_auth_sso::{CallbackOutcome, CallbackParams, Redirect, Sso};

use common::*;

const CLIENT_ID: &str = "z-auth-client";

struct Idp {
    server: MockServer,
}

impl Idp {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "userinfo_endpoint": format!("{issuer}/userinfo"),
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [
                    // Not a signing key: skipped, not fatal.
                    { "kty": "RSA", "use": "enc", "kid": "enc", "alg": "RSA-OAEP",
                      "n": "AQAB", "e": "AQAB" },
                    { "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
                      "kid": "k1", "x": EC_X, "y": EC_Y },
                ]
            })))
            .mount(&server)
            .await;
        Self { server }
    }

    fn issuer(&self) -> String {
        self.server.uri()
    }

    fn provider(&self, extra: &[(&str, &str)]) -> Vec<(&'static str, String)> {
        let mut settings = vec![
            ("kind", "oidc".to_string()),
            ("issuer", self.issuer()),
            ("client_id", CLIENT_ID.into()),
            ("client_secret", "s3cret".into()),
            ("provisioning", "create".into()),
            ("trust_email", "true".into()),
        ];
        for (k, v) in extra {
            let k: &'static str = Box::leak(k.to_string().into_boxed_str());
            settings.retain(|(key, _)| *key != k);
            settings.push((k, v.to_string()));
        }
        settings
    }

    /// The claims of a valid ID token for `redirect`.
    fn claims(&self, redirect: &Redirect, sub: &str) -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({
            "iss": self.issuer(),
            "aud": CLIENT_ID,
            "sub": sub,
            "iat": now,
            "exp": now + 300,
            "nonce": query(&redirect.url)["nonce"],
            "email": format!("{sub}@example.com"),
            "email_verified": true,
            "given_name": "Ann",
        })
    }

    /// The token endpoint answers the next code with `claims`, signed.
    async fn answer(&self, claims: &Value, kid: &str) {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.into());
        let key = EncodingKey::from_ec_pem(EC_KEY_PEM.as_bytes()).unwrap();
        self.answer_token(encode(&header, claims, &key).unwrap())
            .await;
    }

    async fn answer_token(&self, id_token: String) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header_exists("authorization"))
            .and(body_string_contains("code_verifier="))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "at",
                "token_type": "Bearer",
                "id_token": id_token,
            })))
            // One code, one answer: a later redirect mounts its own.
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }
}

async fn setup(extra: &[(&str, &str)]) -> (Idp, Sso, Server) {
    let idp = Idp::start().await;
    let sso = sso(&[("acme", idp.provider(extra))]);
    (idp, sso, external_server(test_config()))
}

#[tokio::test]
async fn the_authorization_url_carries_pkce_state_and_nonce() {
    let (idp, sso, s) = setup(&[]).await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    assert!(
        redirect
            .url
            .starts_with(&format!("{}/authorize?", idp.issuer()))
    );
    let q = query(&redirect.url);
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["redirect_uri"], CALLBACK);
    assert_eq!(q["scope"], "openid email profile");
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(q["state"].len() >= 43 && q["nonce"].len() >= 43);
    assert_ne!(q["state"], redirect.binding);
}

#[tokio::test]
async fn a_valid_id_token_signs_the_user_in() {
    let (idp, sso, s) = setup(&[]).await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    idp.answer(&idp.claims(&redirect, "ann"), "k1").await;
    let pair = tokens(finish(&sso, &s, &redirect, "code-1").await.unwrap());
    let c = claims(&s, &pair).await;
    assert_eq!(c.amr, ["fed"]);
    let user = s.auth.users().find_by_id(c.sub).await.unwrap().unwrap();
    assert_eq!(user.email, "ann@example.com");
    assert!(user.is_verified);
    assert_eq!(user.first_name.as_deref(), Some("Ann"));
    let identity = &s.auth.account_links().list(c.sub).await.unwrap()[0];
    assert_eq!(identity.provider, "acme");
    assert_eq!(identity.issuer, idp.issuer());
    assert_eq!(identity.subject, "ann");

    // Each redirect is accepted once.
    let err = finish(&sso, &s, &redirect, "code-1").await;
    assert!(matches!(err, Err(AuthError::ChallengeExpired)));
}

#[tokio::test]
async fn the_callback_must_come_from_the_browser_that_started_it() {
    let (idp, sso, s) = setup(&[]).await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    idp.answer(&idp.claims(&redirect, "ann"), "k1").await;
    let err = sso
        .callback(
            &s.auth,
            callback_params(&redirect, "code"),
            "someone-elses-cookie",
            ctx(IP_A),
        )
        .await;
    assert!(matches!(err, Err(AuthError::ExternalLoginFailed(_))));
}

#[tokio::test]
async fn a_missing_binding_is_named_and_keeps_the_redirect() {
    let (idp, sso, s) = setup(&[]).await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    idp.answer(&idp.claims(&redirect, "ann"), "k1").await;
    let err = sso
        .callback(&s.auth, callback_params(&redirect, "code"), " ", ctx(IP_A))
        .await;
    match err {
        Err(AuthError::ExternalLoginFailed(m)) => {
            assert!(m.contains("cookie `sso-binding`"), "{m}")
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // A host that forgot the binding has not burnt the user's redirect.
    tokens(finish(&sso, &s, &redirect, "code").await.unwrap());
}

#[tokio::test]
async fn the_binding_cookie_is_set_and_cleared_by_sso() {
    let (_idp, sso, s) = setup(&[]).await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    let cookie = sso.set_binding_cookie(&redirect).unwrap();
    assert_eq!(
        cookie,
        format!(
            "sso-binding={}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax",
            redirect.binding
        )
    );
    assert!(sso.clear_binding_cookie().unwrap().contains("Max-Age=0"));
}

#[tokio::test]
async fn the_header_transport_works_the_same_way() {
    let idp = Idp::start().await;
    let settings = z_auth_sso::config::RawSsoConfig::default()
        .callback_url("https://app.example.com/sso/callback")
        .binding_transport("header")
        .provider("acme", idp.provider(&[]))
        .build()
        .unwrap();
    assert_eq!(settings.binding.name, "X-SSO-Binding");
    let sso = Sso::new(settings).unwrap();
    let s = external_server(test_config());
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    assert_eq!(sso.set_binding_cookie(&redirect), None);
    idp.answer(&idp.claims(&redirect, "ann"), "k1").await;
    // The host's page sends the value it kept, in X-SSO-Binding.
    tokens(finish(&sso, &s, &redirect, "code").await.unwrap());

    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    let err = sso
        .callback(
            &s.auth,
            callback_params(&redirect, "code"),
            "forged",
            ctx(IP_A),
        )
        .await;
    match err {
        Err(AuthError::ExternalLoginFailed(m)) => {
            assert!(m.contains("header `X-SSO-Binding`"), "{m}")
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn redirects_expire() {
    let (idp, sso, s) = setup(&[]).await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    idp.answer(&idp.claims(&redirect, "ann"), "k1").await;
    s.clock.advance(Duration::from_secs(601));
    let err = finish(&sso, &s, &redirect, "code").await;
    assert!(matches!(err, Err(AuthError::ChallengeExpired)));
}

/// Changes one claim of a valid ID token.
type Tamper = Box<dyn Fn(&mut Value)>;

#[tokio::test]
async fn tampered_id_tokens_are_refused() {
    let cases: Vec<(&str, Tamper)> = vec![
        ("nonce", Box::new(|c| c["nonce"] = json!("other"))),
        ("audience", Box::new(|c| c["aud"] = json!("another-client"))),
        (
            "issuer",
            Box::new(|c| c["iss"] = json!("https://evil.example")),
        ),
        (
            "expired",
            Box::new(|c| c["exp"] = json!(chrono::Utc::now().timestamp() - 3600)),
        ),
        (
            "azp",
            Box::new(|c| {
                c["aud"] = json!([CLIENT_ID, "another-client"]);
                c["azp"] = json!("another-client");
            }),
        ),
        ("no subject", Box::new(|c| c["sub"] = json!(""))),
    ];
    for (case, tamper) in cases {
        let (idp, sso, s) = setup(&[]).await;
        let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
        let mut claims = idp.claims(&redirect, "ann");
        tamper(&mut claims);
        idp.answer(&claims, "k1").await;
        let err = finish(&sso, &s, &redirect, "code").await;
        assert!(
            matches!(err, Err(AuthError::ExternalLoginFailed(_))),
            "{case}: {err:?}"
        );
    }
}

#[tokio::test]
async fn unknown_keys_and_symmetric_signatures_are_refused() {
    let (idp, sso, s) = setup(&[]).await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    idp.answer(&idp.claims(&redirect, "ann"), "rotated-away")
        .await;
    let err = finish(&sso, &s, &redirect, "code").await;
    assert!(
        matches!(err, Err(AuthError::ExternalLoginFailed(_))),
        "{err:?}"
    );

    // "Signed" with HMAC: the classic algorithm-confusion attack.
    let (idp, sso, s) = setup(&[]).await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("k1".into());
    let forged = encode(
        &header,
        &idp.claims(&redirect, "ann"),
        &EncodingKey::from_secret(EC_X.as_bytes()),
    )
    .unwrap();
    idp.answer_token(forged).await;
    let err = finish(&sso, &s, &redirect, "code").await;
    assert!(
        matches!(err, Err(AuthError::ExternalLoginFailed(_))),
        "{err:?}"
    );
}

#[tokio::test]
async fn provider_errors_end_the_redirect() {
    let (_idp, sso, s) = setup(&[]).await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    let params = CallbackParams {
        state: query(&redirect.url).get("state").cloned(),
        code: None,
        error: Some("access_denied".into()),
        error_description: Some("the user declined".into()),
    };
    let err = sso
        .callback(&s.auth, params.clone(), &redirect.binding, ctx(IP_A))
        .await;
    assert!(matches!(err, Err(AuthError::ExternalLoginFailed(_))));
    let err = sso
        .callback(&s.auth, params, &redirect.binding, ctx(IP_A))
        .await;
    assert!(matches!(err, Err(AuthError::ChallengeExpired)));
}

#[tokio::test]
async fn the_discovery_document_must_name_the_configured_issuer() {
    let idp = Idp::start().await;
    let mut settings = idp.provider(&[]);
    settings.retain(|(k, _)| *k != "issuer");
    // Same server, but configured with a trailing path: a different issuer.
    settings.push(("issuer", format!("{}/", idp.issuer())));
    let sso = sso(&[("acme", settings)]);
    let s = external_server(test_config());
    let err = sso.begin_login(&s.auth, "acme").await;
    assert!(matches!(err, Err(AuthError::Config(_))), "{:?}", err.err());
}

#[tokio::test]
async fn unknown_providers_are_reported() {
    let (_idp, sso, s) = setup(&[]).await;
    let err = sso.begin_login(&s.auth, "nope").await;
    assert!(matches!(err, Err(AuthError::UnknownProvider(_))));
}

#[tokio::test]
async fn the_profile_may_come_from_the_user_info_endpoint() {
    let (idp, sso, s) = setup(&[]).await;
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sub": "bob", "email": "bob@example.com", "email_verified": "true",
        })))
        .mount(&idp.server)
        .await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    let mut claims = idp.claims(&redirect, "bob");
    claims.as_object_mut().unwrap().remove("email");
    idp.answer(&claims, "k1").await;
    let c = claims_of(&s, finish(&sso, &s, &redirect, "code").await.unwrap()).await;
    let user = s.auth.users().find_by_id(c.sub).await.unwrap().unwrap();
    assert_eq!(user.email, "bob@example.com");
    assert!(user.is_verified);
}

#[tokio::test]
async fn user_info_for_another_subject_is_refused() {
    let (idp, sso, s) = setup(&[]).await;
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sub": "mallory", "email": "victim@example.com", "email_verified": true,
        })))
        .mount(&idp.server)
        .await;
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    let mut claims = idp.claims(&redirect, "bob");
    claims.as_object_mut().unwrap().remove("email");
    idp.answer(&claims, "k1").await;
    let err = finish(&sso, &s, &redirect, "code").await;
    assert!(matches!(err, Err(AuthError::ExternalLoginFailed(_))));
}

#[tokio::test]
async fn the_providers_mfa_counts_only_when_trusted() {
    for (trust, expected) in [("false", vec!["fed"]), ("true", vec!["fed", "mfa", "otp"])] {
        let (idp, sso, s) = setup(&[("trust_amr", trust)]).await;
        let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
        let mut claims = idp.claims(&redirect, "ann");
        claims["amr"] = json!(["otp", "mfa"]);
        idp.answer(&claims, "k1").await;
        let c = claims_of(&s, finish(&sso, &s, &redirect, "code").await.unwrap()).await;
        assert_eq!(c.amr, expected);
    }
}

#[tokio::test]
async fn a_signed_in_user_links_an_identity() {
    let (idp, sso, s) = setup(&[("provisioning", "deny")]).await;
    let user = register(&s.auth, "carol@example.com").await;
    let pair = s
        .auth
        .authentication()
        .login(credentials("carol@example.com"), ctx(IP_A))
        .await
        .and_then(LoginOutcome::into_tokens)
        .unwrap();

    let redirect = sso
        .begin_link(&s.auth, &pair.access_token, "acme")
        .await
        .unwrap();
    // The provider's email differs from the account's: linking does not
    // depend on it.
    idp.answer(&idp.claims(&redirect, "carol-at-acme"), "k1")
        .await;
    let CallbackOutcome::Linked(identity) = finish(&sso, &s, &redirect, "code").await.unwrap()
    else {
        panic!("expected a link");
    };
    assert_eq!(identity.user_id, user.id);

    // From now on the identity signs Carol in.
    let redirect = sso.begin_login(&s.auth, "acme").await.unwrap();
    idp.answer(&idp.claims(&redirect, "carol-at-acme"), "k1")
        .await;
    let c = claims_of(&s, finish(&sso, &s, &redirect, "code").await.unwrap()).await;
    assert_eq!(c.sub, user.id);
}

#[tokio::test]
async fn linking_from_an_old_session_is_refused_before_leaving() {
    let (_idp, sso, s) = setup(&[]).await;
    register(&s.auth, "dave@example.com").await;
    let pair = s
        .auth
        .authentication()
        .login(credentials("dave@example.com"), ctx(IP_A))
        .await
        .and_then(LoginOutcome::into_tokens)
        .unwrap();
    s.clock.advance(Duration::from_secs(240));
    let pair = s
        .auth
        .authentication()
        .refresh(&pair.access_token, &pair.refresh_token, ctx(IP_A))
        .await
        .unwrap();
    s.clock.advance(Duration::from_secs(240));
    let pair = s
        .auth
        .authentication()
        .refresh(&pair.access_token, &pair.refresh_token, ctx(IP_A))
        .await
        .unwrap();
    s.clock.advance(Duration::from_secs(240));
    let err = sso.begin_link(&s.auth, &pair.access_token, "acme").await;
    assert!(
        matches!(err, Err(AuthError::ReauthenticationRequired)),
        "{:?}",
        err.err()
    );
}

async fn claims_of(s: &Server, outcome: CallbackOutcome) -> Claims {
    claims(s, &tokens(outcome)).await
}
