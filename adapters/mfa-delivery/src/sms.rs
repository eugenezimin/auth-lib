//! SMS senders: Twilio (feature `twilio`) and a signed webhook (feature
//! `webhook`).

#[cfg(any(feature = "twilio", feature = "webhook"))]
use {
    crate::message,
    crate::router::failed,
    async_trait::async_trait,
    chrono::Utc,
    z_auth::AuthError,
    z_auth_mfa::{CodeDelivery, CodeSender},
};

#[cfg(any(feature = "twilio", feature = "webhook"))]
fn text(sender_name: &str, d: &CodeDelivery) -> String {
    message::sms(sender_name, d.purpose, &d.code, d.expires_at, Utc::now())
}

// ── Twilio ────────────────────────────────────────────────────────────────────

/// Twilio Programmable Messaging (basic auth `<account sid>:<auth token>`).
#[cfg(feature = "twilio")]
pub struct TwilioSender {
    pub(crate) http: reqwest::Client,
    pub(crate) cfg: crate::config::TwilioConfig,
    pub(crate) sender_name: String,
}

#[cfg(feature = "twilio")]
#[async_trait]
impl CodeSender for TwilioSender {
    async fn send(&self, d: CodeDelivery) -> Result<(), AuthError> {
        use crate::config::TwilioSender as From_;

        let body = text(&self.sender_name, &d);
        let (from_key, from_value) = match &self.cfg.sender {
            From_::From(number) => ("From", number.as_str()),
            From_::MessagingService(sid) => ("MessagingServiceSid", sid.as_str()),
        };
        let form = [
            ("To", d.destination.as_str()),
            (from_key, from_value),
            ("Body", body.as_str()),
        ];
        let res = self
            .http
            .post(format!(
                "{}/2010-04-01/Accounts/{}/Messages.json",
                self.cfg.api_base, self.cfg.account_sid
            ))
            .basic_auth(&self.cfg.account_sid, Some(self.cfg.auth_token.expose()))
            .form(&form)
            .send()
            .await
            .map_err(|e| failed("twilio", e))?;
        crate::http::check("twilio", res).await
    }
}

// ── Webhook ───────────────────────────────────────────────────────────────────

#[cfg(feature = "webhook")]
pub use webhook::{WebhookSender, signature};

#[cfg(feature = "webhook")]
mod webhook {
    use std::time::Duration;

    use hmac::{Hmac, KeyInit, Mac};
    use serde_json::json;
    use sha2::Sha256;
    use z_auth_mfa::CodePurpose;

    use super::*;
    use crate::config::{Secret, WebhookConfig};
    use crate::constants::{WEBHOOK_SIGNATURE_HEADER, WEBHOOK_TIMESTAMP_HEADER};

    /// A JSON `POST` per code to your own SMS gateway; see the crate README
    /// for the payload and the signature.
    pub struct WebhookSender {
        http: reqwest::Client,
        url: reqwest::Url,
        secret: Option<Secret>,
        bearer_token: Option<Secret>,
        sender_name: String,
    }

    impl WebhookSender {
        pub fn new(
            cfg: &WebhookConfig,
            sender_name: &str,
            timeout: Duration,
        ) -> Result<Self, AuthError> {
            let url = reqwest::Url::parse(&cfg.url)
                .map_err(|e| AuthError::Config(format!("SMS webhook URL {:?}: {e}", cfg.url)))?;
            Ok(Self {
                http: crate::http::client(timeout)?,
                url,
                secret: cfg.secret.clone(),
                bearer_token: cfg.bearer_token.clone(),
                sender_name: sender_name.to_owned(),
            })
        }
    }

    /// `sha256=<hex>` of HMAC-SHA256 over `"{timestamp}.{body}"`.
    pub fn signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    fn purpose_name(p: CodePurpose) -> &'static str {
        match p {
            CodePurpose::Login => "login",
            CodePurpose::Enrollment => "enrollment",
            CodePurpose::StepUp => "step_up",
        }
    }

    #[async_trait]
    impl CodeSender for WebhookSender {
        async fn send(&self, d: CodeDelivery) -> Result<(), AuthError> {
            let body = serde_json::to_vec(&json!({
                "to": d.destination,
                "message": text(&self.sender_name, &d),
                "code": d.code,
                "purpose": purpose_name(d.purpose),
                "method": d.method.as_str(),
                "expires_at": d.expires_at.to_rfc3339(),
                "user_id": d.user_id.to_string(),
            }))
            .map_err(|e| failed("webhook", e))?;
            let mut req = self
                .http
                .post(self.url.clone())
                .header("content-type", "application/json");
            if let Some(secret) = &self.secret {
                let ts = Utc::now().timestamp();
                req = req.header(WEBHOOK_TIMESTAMP_HEADER, ts.to_string()).header(
                    WEBHOOK_SIGNATURE_HEADER,
                    signature(secret.expose(), ts, &body),
                );
            }
            if let Some(token) = &self.bearer_token {
                req = req.bearer_auth(token.expose());
            }
            let res = req
                .body(body)
                .send()
                .await
                .map_err(|e| failed("webhook", e))?;
            crate::http::check("webhook", res).await
        }
    }
}
