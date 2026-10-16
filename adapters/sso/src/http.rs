//! What every provider shares: random secrets, PKCE, the token request and
//! reading claims out of JSON.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::ACCEPT;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use z_auth::AuthError;

use crate::config::TokenAuth;
use crate::constants::{HTTP_TIMEOUT_SECS, SECRET_LEN, USER_AGENT};

/// The client used when the host supplies none: rustls, a timeout, no
/// redirects (an identity provider's endpoints answer directly).
pub fn default_client() -> Result<reqwest::Client, AuthError> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AuthError::Config(format!("HTTP client: {e}")))
}

/// A URL-safe random secret of [`SECRET_LEN`] bytes.
pub fn random_secret() -> Result<String, AuthError> {
    let mut buf = [0u8; SECRET_LEN];
    getrandom::fill(&mut buf).map_err(|e| AuthError::Internal(format!("OS RNG failure: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// Base64url SHA-256 — the PKCE S256 challenge of a verifier, and how
/// browser bindings are stored.
pub fn sha256_b64(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

pub fn unavailable(what: &str, e: impl std::fmt::Display) -> AuthError {
    AuthError::ExternalProviderUnavailable(format!("{what}: {e}"))
}

pub fn failed(reason: impl Into<String>) -> AuthError {
    AuthError::ExternalLoginFailed(reason.into())
}

/// The token endpoint's answer (RFC 6749 §5).
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: Option<String>,
    #[cfg_attr(not(feature = "oidc"), allow(dead_code))]
    pub id_token: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Exchange an authorization code at `token_url`.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_code(
    http: &reqwest::Client,
    token_url: &str,
    auth: TokenAuth,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: Option<&str>,
) -> Result<TokenResponse, AuthError> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(verifier) = pkce_verifier {
        form.push(("code_verifier", verifier));
    }
    let mut request = http.post(token_url).header(ACCEPT, "application/json");
    match (auth, client_secret) {
        (TokenAuth::Basic, Some(secret)) => {
            request = request.basic_auth(form_encode(client_id), Some(form_encode(secret)));
        }
        (TokenAuth::Post, Some(secret)) => {
            form.push(("client_id", client_id));
            form.push(("client_secret", secret));
        }
        (_, None) => form.push(("client_id", client_id)),
    }
    let response = request
        .form(&form)
        .send()
        .await
        .map_err(|e| unavailable("token endpoint", e))?;
    let status = response.status();
    if status.is_server_error() {
        return Err(unavailable("token endpoint", status));
    }
    let body: TokenResponse = response
        .json()
        .await
        .map_err(|e| unavailable("token endpoint", e))?;
    // Some providers (GitHub) report errors with 200 OK.
    if let Some(error) = &body.error {
        let detail = body.error_description.as_deref().unwrap_or_default();
        return Err(failed(format!(
            "the provider refused the code: {error} {detail}"
        )));
    }
    if !status.is_success() {
        return Err(failed(format!("the provider refused the code ({status})")));
    }
    Ok(body)
}

/// `application/x-www-form-urlencoded` encoding of a client credential, as
/// RFC 6749 §2.3.1 requires before Basic authentication.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// GET `url` with the access token, as JSON.
pub async fn get_json(
    http: &reqwest::Client,
    url: &str,
    access_token: &str,
    what: &str,
) -> Result<Value, AuthError> {
    let response = http
        .get(url)
        .bearer_auth(access_token)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| unavailable(what, e))?;
    let status = response.status();
    if status.is_server_error() {
        return Err(unavailable(what, status));
    }
    if !status.is_success() {
        return Err(failed(format!(
            "the provider's {what} refused the token ({status})"
        )));
    }
    response.json().await.map_err(|e| unavailable(what, e))
}

/// A claim as text: strings as they are, numbers written out (GitHub's
/// numeric ids).
pub fn text_at(json: &Value, pointer: &str) -> Option<String> {
    match json.pointer(pointer)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// A claim as a boolean: `true`, or the string `"true"` some providers send.
pub fn bool_at(json: &Value, pointer: &str) -> bool {
    match json.pointer(pointer) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc_7636() {
        // RFC 7636 appendix B.
        assert_eq!(
            sha256_b64("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn secrets_are_url_safe_and_distinct() {
        let a = random_secret().unwrap();
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(a, random_secret().unwrap());
    }

    #[test]
    fn claims_read_strings_numbers_and_loose_booleans() {
        let json = serde_json::json!({
            "id": 42, "login": "octo", "blank": " ",
            "v1": true, "v2": "true", "v3": "no",
        });
        assert_eq!(text_at(&json, "/id").as_deref(), Some("42"));
        assert_eq!(text_at(&json, "/login").as_deref(), Some("octo"));
        assert_eq!(text_at(&json, "/blank"), None);
        assert_eq!(text_at(&json, "/missing"), None);
        assert!(bool_at(&json, "/v1") && bool_at(&json, "/v2"));
        assert!(!bool_at(&json, "/v3") && !bool_at(&json, "/missing"));
    }

    #[test]
    fn credentials_are_form_encoded_for_basic_auth() {
        assert_eq!(form_encode("a b:c%"), "a+b%3Ac%25");
    }
}
