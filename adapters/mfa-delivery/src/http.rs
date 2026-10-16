//! The HTTP client shared by the API providers.

use std::time::Duration;

use z_auth::AuthError;

use crate::constants::MAX_ERROR_BODY_CHARS;
use crate::router::failed;

pub(crate) fn client(timeout: Duration) -> Result<reqwest::Client, AuthError> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("z-auth-mfa-delivery/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AuthError::Config(format!("HTTP client: {e}")))
}

/// `Ok` for a 2xx answer; otherwise the status and the start of the body.
pub(crate) async fn check(provider: &str, res: reqwest::Response) -> Result<(), AuthError> {
    let status = res.status();
    if status.is_success() {
        return Ok(());
    }
    let body = res.text().await.unwrap_or_default();
    let body: String = body.chars().take(MAX_ERROR_BODY_CHARS).collect();
    Err(failed(provider, format!("{status}: {body}")))
}

/// `"Name" <address>` for APIs that take a display name inline.
#[cfg(any(feature = "postmark", feature = "mailgun"))]
pub(crate) fn mailbox(name: &str, address: &str) -> String {
    let name = name.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{name}\" <{address}>")
}
