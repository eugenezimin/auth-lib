//! Email senders: SMTP (feature `smtp`), SendGrid, Postmark and Mailgun
//! (features of the same names).

#[cfg(any(feature = "sendgrid", feature = "postmark"))]
use serde_json::json;
#[cfg(any(
    feature = "smtp",
    feature = "sendgrid",
    feature = "postmark",
    feature = "mailgun"
))]
use {
    crate::message::{self, EmailMessage},
    crate::router::failed,
    async_trait::async_trait,
    chrono::Utc,
    z_auth::AuthError,
    z_auth_mfa::{CodeDelivery, CodeSender},
};

#[cfg(any(
    feature = "smtp",
    feature = "sendgrid",
    feature = "postmark",
    feature = "mailgun"
))]
fn render(sender_name: &str, d: &CodeDelivery) -> EmailMessage {
    message::email(sender_name, d.purpose, &d.code, d.expires_at, Utc::now())
}

// ── SMTP ──────────────────────────────────────────────────────────────────────

#[cfg(feature = "smtp")]
pub use smtp::{SmtpSender, build_email};

#[cfg(feature = "smtp")]
mod smtp {
    use std::time::Duration;

    use lettre::message::{Mailbox, MultiPart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

    use super::*;
    use crate::config::{SmtpConfig, SmtpSecurity};

    /// Sends through an SMTP server (STARTTLS, implicit TLS, or plain for
    /// local development).  One connection per message.
    pub struct SmtpSender {
        transport: AsyncSmtpTransport<Tokio1Executor>,
        sender_name: String,
        from: String,
    }

    impl SmtpSender {
        pub fn new(
            cfg: &SmtpConfig,
            sender_name: &str,
            timeout: Duration,
        ) -> Result<Self, AuthError> {
            let config_err = |e: lettre::transport::smtp::Error| {
                AuthError::Config(format!("SMTP transport for {}: {e}", cfg.host))
            };
            let mut builder = match cfg.security {
                SmtpSecurity::Tls => {
                    AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host).map_err(config_err)?
                }
                SmtpSecurity::StartTls => {
                    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
                        .map_err(config_err)?
                }
                SmtpSecurity::None => {
                    AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host)
                }
            }
            .port(cfg.port)
            .timeout(Some(timeout));
            if let Some((user, pass)) = &cfg.credentials {
                builder =
                    builder.credentials(Credentials::new(user.clone(), pass.expose().to_owned()));
            }
            // Fail at startup, not at the first send.
            cfg.from
                .parse::<lettre::Address>()
                .map_err(|e| AuthError::Config(format!("SMTP From address {:?}: {e}", cfg.from)))?;
            Ok(Self {
                transport: builder.build(),
                sender_name: sender_name.to_owned(),
                from: cfg.from.clone(),
            })
        }
    }

    /// A multipart (text + HTML) email of `msg` from
    /// `sender_name <from>` to `to`.
    pub fn build_email(
        sender_name: &str,
        from: &str,
        to: &str,
        msg: &EmailMessage,
    ) -> Result<lettre::Message, AuthError> {
        let from = Mailbox::new(
            Some(sender_name.to_owned()),
            from.parse()
                .map_err(|e| failed("smtp", format!("bad From address: {e}")))?,
        );
        let to: Mailbox = to
            .parse()
            .map_err(|e| failed("smtp", format!("bad recipient: {e}")))?;
        lettre::Message::builder()
            .from(from)
            .to(to)
            .subject(msg.subject.clone())
            .multipart(MultiPart::alternative_plain_html(
                msg.text.clone(),
                msg.html.clone(),
            ))
            .map_err(|e| failed("smtp", e))
    }

    #[async_trait]
    impl CodeSender for SmtpSender {
        async fn send(&self, d: CodeDelivery) -> Result<(), AuthError> {
            let email = build_email(
                &self.sender_name,
                &self.from,
                &d.destination,
                &render(&self.sender_name, &d),
            )?;
            self.transport
                .send(email)
                .await
                .map_err(|e| failed("smtp", e))?;
            Ok(())
        }
    }
}

// ── SendGrid ──────────────────────────────────────────────────────────────────

/// SendGrid's v3 Mail Send API (`Authorization: Bearer <key>`).
#[cfg(feature = "sendgrid")]
pub struct SendGridSender {
    pub(crate) http: reqwest::Client,
    pub(crate) cfg: crate::config::SendGridConfig,
    pub(crate) sender_name: String,
}

#[cfg(feature = "sendgrid")]
#[async_trait]
impl CodeSender for SendGridSender {
    async fn send(&self, d: CodeDelivery) -> Result<(), AuthError> {
        let msg = render(&self.sender_name, &d);
        let body = json!({
            "personalizations": [{ "to": [{ "email": d.destination }] }],
            "from": { "email": self.cfg.from, "name": self.sender_name },
            "subject": msg.subject,
            "content": [
                { "type": "text/plain", "value": msg.text },
                { "type": "text/html", "value": msg.html },
            ],
        });
        let res = self
            .http
            .post(format!("{}/v3/mail/send", self.cfg.api_base))
            .bearer_auth(self.cfg.api_key.expose())
            .json(&body)
            .send()
            .await
            .map_err(|e| failed("sendgrid", e))?;
        crate::http::check("sendgrid", res).await
    }
}

// ── Postmark ──────────────────────────────────────────────────────────────────

/// Postmark's email API (`X-Postmark-Server-Token`).
#[cfg(feature = "postmark")]
pub struct PostmarkSender {
    pub(crate) http: reqwest::Client,
    pub(crate) cfg: crate::config::PostmarkConfig,
    pub(crate) sender_name: String,
}

#[cfg(feature = "postmark")]
#[async_trait]
impl CodeSender for PostmarkSender {
    async fn send(&self, d: CodeDelivery) -> Result<(), AuthError> {
        let msg = render(&self.sender_name, &d);
        let body = json!({
            "From": crate::http::mailbox(&self.sender_name, &self.cfg.from),
            "To": d.destination,
            "Subject": msg.subject,
            "TextBody": msg.text,
            "HtmlBody": msg.html,
            "MessageStream": self.cfg.message_stream,
        });
        let res = self
            .http
            .post(format!("{}/email", self.cfg.api_base))
            .header("X-Postmark-Server-Token", self.cfg.server_token.expose())
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| failed("postmark", e))?;
        crate::http::check("postmark", res).await
    }
}

// ── Mailgun ───────────────────────────────────────────────────────────────────

/// Mailgun's messages API (basic auth `api:<key>`, form body).
#[cfg(feature = "mailgun")]
pub struct MailgunSender {
    pub(crate) http: reqwest::Client,
    pub(crate) cfg: crate::config::MailgunConfig,
    pub(crate) sender_name: String,
}

#[cfg(feature = "mailgun")]
#[async_trait]
impl CodeSender for MailgunSender {
    async fn send(&self, d: CodeDelivery) -> Result<(), AuthError> {
        let msg = render(&self.sender_name, &d);
        let from = crate::http::mailbox(&self.sender_name, &self.cfg.from);
        let form = [
            ("from", from.as_str()),
            ("to", d.destination.as_str()),
            ("subject", msg.subject.as_str()),
            ("text", msg.text.as_str()),
            ("html", msg.html.as_str()),
        ];
        let res = self
            .http
            .post(format!(
                "{}/v3/{}/messages",
                self.cfg.api_base, self.cfg.domain
            ))
            .basic_auth("api", Some(self.cfg.api_key.expose()))
            .form(&form)
            .send()
            .await
            .map_err(|e| failed("mailgun", e))?;
        crate::http::check("mailgun", res).await
    }
}
