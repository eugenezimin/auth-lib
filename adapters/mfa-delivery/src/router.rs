//! [`build`] — the [`CodeSender`] for a [`DeliveryConfig`]: email codes to
//! the email provider, SMS codes to the SMS provider.

use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
use z_auth::AuthError;
use z_auth_mfa::{CodeDelivery, CodeSender, MfaMethod};

use crate::config::{DeliveryConfig, EmailProvider, SmsProvider};
use crate::log::LogCodeSender;

/// The sender for `cfg`, ready for `Mfa::with_code_sender`.  Fails with
/// [`AuthError::Config`] for a provider whose feature isn't compiled in or
/// whose settings can't be used (e.g. an unparsable From address).
pub fn build(cfg: &DeliveryConfig) -> Result<Arc<dyn CodeSender>, AuthError> {
    Ok(Arc::new(MethodRouter {
        email: email_sender(cfg)?,
        email_provider: cfg.email.name(),
        sms: sms_sender(cfg)?,
        sms_provider: cfg.sms.name(),
    }))
}

/// The email sender alone.
pub fn email_sender(cfg: &DeliveryConfig) -> Result<Arc<dyn CodeSender>, AuthError> {
    Ok(match &cfg.email {
        EmailProvider::Log => Arc::new(LogCodeSender),
        #[cfg(feature = "smtp")]
        EmailProvider::Smtp(c) => Arc::new(crate::email::SmtpSender::new(
            c,
            &cfg.sender_name,
            cfg.timeout,
        )?),
        #[cfg(feature = "sendgrid")]
        EmailProvider::SendGrid(c) => Arc::new(crate::email::SendGridSender {
            http: crate::http::client(cfg.timeout)?,
            cfg: c.clone(),
            sender_name: cfg.sender_name.clone(),
        }),
        #[cfg(feature = "postmark")]
        EmailProvider::Postmark(c) => Arc::new(crate::email::PostmarkSender {
            http: crate::http::client(cfg.timeout)?,
            cfg: c.clone(),
            sender_name: cfg.sender_name.clone(),
        }),
        #[cfg(feature = "mailgun")]
        EmailProvider::Mailgun(c) => Arc::new(crate::email::MailgunSender {
            http: crate::http::client(cfg.timeout)?,
            cfg: c.clone(),
            sender_name: cfg.sender_name.clone(),
        }),
        #[allow(unreachable_patterns)]
        other => return Err(not_compiled(other.name())),
    })
}

/// The SMS sender alone.
pub fn sms_sender(cfg: &DeliveryConfig) -> Result<Arc<dyn CodeSender>, AuthError> {
    Ok(match &cfg.sms {
        SmsProvider::Log => Arc::new(LogCodeSender),
        #[cfg(feature = "twilio")]
        SmsProvider::Twilio(c) => Arc::new(crate::sms::TwilioSender {
            http: crate::http::client(cfg.timeout)?,
            cfg: c.clone(),
            sender_name: cfg.sender_name.clone(),
        }),
        #[cfg(feature = "webhook")]
        SmsProvider::Webhook(c) => Arc::new(crate::sms::WebhookSender::new(
            c,
            &cfg.sender_name,
            cfg.timeout,
        )?),
        #[allow(unreachable_patterns)]
        other => return Err(not_compiled(other.name())),
    })
}

fn not_compiled(provider: &str) -> AuthError {
    AuthError::Config(format!(
        "z-auth-mfa-delivery was built without the `{provider}` feature"
    ))
}

/// Email codes to one sender, SMS codes to another.
pub struct MethodRouter {
    pub email: Arc<dyn CodeSender>,
    /// Shown in logs.
    pub email_provider: &'static str,
    pub sms: Arc<dyn CodeSender>,
    /// Shown in logs.
    pub sms_provider: &'static str,
}

#[async_trait]
impl CodeSender for MethodRouter {
    async fn send(&self, d: CodeDelivery) -> Result<(), AuthError> {
        let (sender, provider) = match d.method {
            MfaMethod::Email => (&self.email, self.email_provider),
            MfaMethod::Sms => (&self.sms, self.sms_provider),
            other => return Err(failed("router", format!("{other} codes are not delivered"))),
        };
        let (method, purpose, to) = (d.method, d.purpose, mask(&d.destination));
        sender.send(d).await?;
        tracing::debug!(provider, %method, ?purpose, %to, "second-factor code sent");
        Ok(())
    }
}

/// [`AuthError::CodeDeliveryFailed`] naming the provider.  z-auth keeps the
/// detail out of HTTP responses; the host should log it.
pub(crate) fn failed(provider: &str, err: impl Display) -> AuthError {
    AuthError::CodeDeliveryFailed(format!("{provider}: {err}"))
}

/// `a***@example.com` / `***0100` — enough to tell destinations apart in
/// logs without recording them.
pub fn mask(destination: &str) -> String {
    match destination.split_once('@') {
        Some((local, domain)) => {
            format!("{}***@{domain}", local.chars().next().unwrap_or('*'))
        }
        None => {
            let chars: Vec<char> = destination.chars().collect();
            let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
            format!("***{tail}")
        }
    }
}
