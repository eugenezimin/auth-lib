//! Shared helpers: a z-auth with external identities in memory, a mock
//! identity provider, and the browser's side of a redirect.
#![allow(dead_code)] // each test binary uses a different subset

use std::collections::HashMap;

pub use z_auth_testkit::*;

use z_auth::prelude::*;
use z_auth_sso::config::{RawSsoConfig, SsoSettings};
use z_auth_sso::{CallbackOutcome, CallbackParams, Redirect, Sso};

pub const CALLBACK: &str = "http://localhost:8080/auth/sso/callback";

/// A P-256 key (PKCS#8) and its public coordinates, signing the test ID
/// tokens.
pub const EC_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggWmPURrTtOZeNErJ
IRQHlBhE+7j+DgW8lDyrWKQhZaehRANCAASBamHZGO1rPdjray97H+2rfCWB8x7A
lYaN+gRAwyEmrQHCcZkYTVDuZuTCGtCoQrOW/LiP1GHycMY28ek8wCSf
-----END PRIVATE KEY-----
";
pub const EC_X: &str = "gWph2Rjtaz3Y62svex_tq3wlgfMewJWGjfoEQMMhJq0";
pub const EC_Y: &str = "AcJxmRhNUO5m5MIa0KhCs5b8uI_UYfJwxjbx6TzAJJ8";

/// An [`Sso`] over the given providers (`(name, settings)`).
pub fn sso(providers: &[(&str, Vec<(&str, String)>)]) -> Sso {
    Sso::new(settings(providers)).expect("sso")
}

pub fn settings(providers: &[(&str, Vec<(&str, String)>)]) -> SsoSettings {
    let mut raw = RawSsoConfig::default().callback_url(CALLBACK);
    for (name, settings) in providers {
        raw = raw.provider(*name, settings.iter().map(|(k, v)| (*k, v.clone())));
    }
    raw.build().expect("sso settings")
}

/// The query parameters of a URL.
pub fn query(url: &str) -> HashMap<String, String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The provider sends the browser back with `code`.
pub fn callback_params(redirect: &Redirect, code: &str) -> CallbackParams {
    CallbackParams {
        state: query(&redirect.url).get("state").cloned(),
        code: Some(code.into()),
        error: None,
        error_description: None,
    }
}

pub async fn finish(
    sso: &Sso,
    s: &Server,
    redirect: &Redirect,
    code: &str,
) -> Result<CallbackOutcome, AuthError> {
    sso.callback(
        &s.auth,
        callback_params(redirect, code),
        &redirect.binding,
        ctx(IP_A),
    )
    .await
}

pub fn tokens(outcome: CallbackOutcome) -> TokenPair {
    match outcome {
        CallbackOutcome::Login(ExternalLoginOutcome::Tokens(pair)) => pair,
        other => panic!("expected tokens, got {other:?}"),
    }
}

pub async fn claims(s: &Server, pair: &TokenPair) -> Claims {
    s.auth
        .authentication()
        .verify_access_token(&pair.access_token)
        .await
        .unwrap()
}
