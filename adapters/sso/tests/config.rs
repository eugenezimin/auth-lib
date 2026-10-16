//! Loading `sso` settings from a configuration file and the environment.
// The fixtures use every kind.
#![cfg(all(feature = "oidc", feature = "github"))]

use std::collections::HashMap;
use std::time::Duration;

use z_auth::conf::config::{ConfigError, ConfigSource};
use z_auth::identity::external::{LinkPolicy, Provisioning};
use z_auth_sso::config::{ProviderKind, SsoConfigLoader, SsoSettings, SsoSourceLoader, TokenAuth};

const FILE: &str = r#"
sso:
  callback_url: https://app.example.com/auth/sso/callback
  flow_ttl_secs: 300
  providers:
    google:
      kind: oidc
      display_name: Google
      issuer: https://accounts.google.com
      client_id: google-client
      link: verified_email
      provisioning: create
      trust_email: true
    linkedin:
      kind: oidc
      issuer: https://www.linkedin.com/oauth
      client_id: li-client
      scopes: [openid, email]
    github:
      kind: github
      client_id: gh-client
    facebook:
      kind: oauth2
      issuer: https://www.facebook.com
      authorize_url: https://www.facebook.com/v19.0/dialog/oauth
      token_url: https://graph.facebook.com/v19.0/oauth/access_token
      userinfo_url: https://graph.facebook.com/me?fields=id,name,email
      client_id: fb-client
      claims:
        subject: /id
        email: /email
"#;

fn env(
    pairs: &[(&'static str, &'static str)],
) -> impl Fn(&str) -> Option<String> + Send + Sync + 'static {
    let map: HashMap<&'static str, &'static str> = pairs.iter().copied().collect();
    move |key| map.get(key).map(|v| v.to_string())
}

fn load(yaml: &str, vars: &[(&'static str, &'static str)]) -> Result<SsoSettings, ConfigError> {
    let source = ConfigSource::yaml_str(yaml)?.with_lookup(env(vars));
    SsoSourceLoader::new(source).load_settings()
}

fn parse_error(r: Result<SsoSettings, ConfigError>) -> String {
    match r {
        Err(ConfigError::Parse { key, reason }) => format!("{key}: {reason}"),
        Err(ConfigError::Missing(key)) => format!("missing {key}"),
        Ok(s) => panic!("expected an error, got {s:?}"),
    }
}

#[test]
fn providers_load_from_the_file_with_secrets_from_the_environment() {
    let s = load(
        FILE,
        &[
            ("AUTH_SSO_GOOGLE_CLIENT_SECRET", "g-secret"),
            ("AUTH_SSO_GITHUB_CLIENT_SECRET", "gh-secret"),
            ("AUTH_SSO_LINKEDIN_CLIENT_ID", "li-from-env"),
        ],
    )
    .unwrap();
    assert_eq!(s.callback_url, "https://app.example.com/auth/sso/callback");
    assert_eq!(s.flow_ttl, Duration::from_secs(300));
    let names: Vec<_> = s.providers.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["facebook", "github", "google", "linkedin"]);

    let google = &s.providers[2];
    assert_eq!(google.display_name, "Google");
    assert_eq!(google.client_secret.as_deref(), Some("g-secret"));
    assert_eq!(google.scopes, ["openid", "email", "profile"]);
    assert_eq!(google.policy.link, LinkPolicy::VerifiedEmail);
    assert_eq!(google.policy.provisioning, Provisioning::Create);
    assert!(google.policy.trust_email);
    assert_eq!(google.policy.max_links, 1);
    assert!(!format!("{google:?}").contains("g-secret"));

    let linkedin = &s.providers[3];
    assert_eq!(linkedin.client_id, "li-from-env");
    assert_eq!(linkedin.scopes, ["openid", "email"]);
    assert_eq!(linkedin.policy.link, LinkPolicy::ConfirmWithPassword);
    assert_eq!(linkedin.policy.provisioning, Provisioning::Deny);
    assert!(!linkedin.policy.trust_email);

    let github = &s.providers[1];
    assert!(matches!(github.kind, ProviderKind::GitHub(_)));
    assert!(github.policy.trust_email);

    let ProviderKind::OAuth2(fb) = &s.providers[0].kind else {
        panic!("facebook is oauth2");
    };
    assert_eq!(fb.claims.subject, "/id");
    assert_eq!(fb.claims.email.as_deref(), Some("/email"));
    assert_eq!(fb.token_auth, TokenAuth::Post);
    assert!(fb.pkce);
}

#[test]
fn providers_may_come_from_the_environment_alone() {
    let source = ConfigSource::from_lookup(env(&[
        ("AUTH_SSO_CALLBACK_URL", "https://app.example.com/cb"),
        ("AUTH_SSO_PROVIDERS", "okta"),
        ("AUTH_SSO_OKTA_KIND", "oidc"),
        ("AUTH_SSO_OKTA_ISSUER", "https://acme.okta.com"),
        ("AUTH_SSO_OKTA_CLIENT_ID", "okta-client"),
        ("AUTH_SSO_OKTA_TOKEN_AUTH", "post"),
    ]));
    let s = SsoSourceLoader::new(source).load_settings().unwrap();
    assert_eq!(s.providers.len(), 1);
    assert_eq!(
        s.providers[0].kind,
        ProviderKind::Oidc(z_auth_sso::config::OidcEndpoints {
            issuer: "https://acme.okta.com".into(),
            token_auth: Some(TokenAuth::Post),
        })
    );
}

#[test]
fn mistakes_are_reported_with_their_path() {
    let base = "sso:\n  callback_url: https://a.example/cb\n  providers:\n    p:\n";
    let with = |lines: &str| format!("{base}{lines}");

    let e = parse_error(load(
        &with("      kind: oidc\n      client_id: c\n      isuer: https://x\n"),
        &[],
    ));
    assert!(e.contains("sso.providers.p.isuer"), "{e}");

    // A setting of another kind.
    let e = parse_error(load(
        &with(
            "      kind: oidc\n      issuer: https://x\n      client_id: c\n      claims:\n        subject: /id\n",
        ),
        &[],
    ));
    assert!(e.contains("not a setting of kind `oidc`"), "{e}");

    let e = parse_error(load(
        &with("      kind: oidc\n      issuer: https://x\n"),
        &[],
    ));
    assert!(e.contains("missing sso.providers.p.client_id"), "{e}");

    let e = parse_error(load(&with("      kind: saml\n      client_id: c\n"), &[]));
    assert!(e.contains("unknown kind 'saml'"), "{e}");

    let e = parse_error(load(
        &with("      kind: oidc\n      issuer: http://idp.example\n      client_id: c\n"),
        &[],
    ));
    assert!(e.contains("https"), "{e}");

    let e = parse_error(load(
        &with(
            "      kind: oidc\n      issuer: https://x\n      client_id: c\n      link: always\n",
        ),
        &[],
    ));
    assert!(e.contains("unknown link policy"), "{e}");

    let e = parse_error(load(
        &with(
            "      kind: oauth2\n      issuer: x\n      authorize_url: https://x/a\n      token_url: https://x/t\n      userinfo_url: https://x/u\n      client_id: c\n      claims:\n        subject: id\n",
        ),
        &[],
    ));
    assert!(e.contains("JSON pointer"), "{e}");

    let e = parse_error(load(&with("      kind: github\n      client_id: c\n"), &[]));
    assert!(e.contains("missing sso.providers.p.client_secret"), "{e}");

    let bad_name =
        "sso:\n  callback_url: https://a.example/cb\n  providers:\n    My-IdP:\n      kind: oidc\n";
    let e = parse_error(load(bad_name, &[]));
    assert!(e.contains("provider names must match"), "{e}");

    let e = parse_error(load("sso:\n  providers: ~\n", &[]));
    assert!(e.contains("missing AUTH_SSO_CALLBACK_URL"), "{e}");
}

#[test]
fn openid_is_always_requested_from_oidc_providers() {
    let s = load(
        "sso:\n  callback_url: https://a.example/cb\n  providers:\n    p:\n      kind: oidc\n      issuer: https://x\n      client_id: c\n      scopes: email\n",
        &[],
    )
    .unwrap();
    assert_eq!(s.providers[0].scopes, ["openid", "email"]);
}
