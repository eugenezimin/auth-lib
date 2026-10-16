//! [`DeliveryConfig`] — who delivers z-auth-mfa's email and SMS codes.
//!
//! The types are always available; a provider whose Cargo feature is off
//! is rejected when loading (and by [`crate::build`]).

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use z_auth::conf::config::ConfigError;

use crate::constants::*;

#[derive(Debug, Clone)]
pub struct DeliveryConfig {
    /// In subjects, SMS texts and the From display name.
    pub sender_name: String,
    /// Per send — codes go out while the user's request waits.
    pub timeout: Duration,
    pub email: EmailProvider,
    pub sms: SmsProvider,
}

#[derive(Debug, Clone)]
pub enum EmailProvider {
    /// Codes are only logged (development).
    Log,
    Smtp(SmtpConfig),
    SendGrid(SendGridConfig),
    Postmark(PostmarkConfig),
    Mailgun(MailgunConfig),
}

#[derive(Debug, Clone)]
pub enum SmsProvider {
    /// Codes are only logged (development).
    Log,
    Twilio(TwilioConfig),
    Webhook(WebhookConfig),
}

impl EmailProvider {
    /// The `AUTH_MFA_EMAIL_PROVIDER` value.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Smtp(_) => "smtp",
            Self::SendGrid(_) => "sendgrid",
            Self::Postmark(_) => "postmark",
            Self::Mailgun(_) => "mailgun",
        }
    }
}

impl SmsProvider {
    /// The `AUTH_MFA_SMS_PROVIDER` value.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Twilio(_) => "twilio",
            Self::Webhook(_) => "webhook",
        }
    }
}

/// A credential: never printed by `Debug`.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Plain connection upgraded with STARTTLS (required).  Port 587.
    StartTls,
    /// TLS from the first byte ("SMTPS").  Port 465.
    Tls,
    /// No encryption — local development servers only (Mailpit, MailHog).
    None,
}

impl SmtpSecurity {
    pub fn default_port(self) -> u16 {
        match self {
            Self::StartTls => SMTP_STARTTLS_PORT,
            Self::Tls => SMTP_TLS_PORT,
            Self::None => SMTP_PLAIN_PORT,
        }
    }
}

impl FromStr for SmtpSecurity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "starttls" => Ok(Self::StartTls),
            "tls" => Ok(Self::Tls),
            "none" => Ok(Self::None),
            _ => Err("expected starttls, tls or none".into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    /// Username and password, or `None` for an unauthenticated relay.
    pub credentials: Option<(String, Secret)>,
    /// The From address.
    pub from: String,
}

#[derive(Debug, Clone)]
pub struct SendGridConfig {
    pub api_key: Secret,
    pub from: String,
    /// [`SENDGRID_API`]; another base only for tests / proxies.
    pub api_base: String,
}

#[derive(Debug, Clone)]
pub struct PostmarkConfig {
    pub server_token: Secret,
    pub message_stream: String,
    pub from: String,
    /// [`POSTMARK_API`]; another base only for tests / proxies.
    pub api_base: String,
}

#[derive(Debug, Clone)]
pub struct MailgunConfig {
    pub api_key: Secret,
    pub domain: String,
    pub from: String,
    /// [`MAILGUN_API_US`] or [`MAILGUN_API_EU`].
    pub api_base: String,
}

#[derive(Debug, Clone)]
pub struct TwilioConfig {
    pub account_sid: String,
    pub auth_token: Secret,
    pub sender: TwilioSender,
    /// [`TWILIO_API`]; another base only for tests / proxies.
    pub api_base: String,
}

/// Where Twilio messages come from.
#[derive(Debug, Clone)]
pub enum TwilioSender {
    /// A Twilio phone number (E.164) or alphanumeric sender ID.
    From(String),
    /// A Messaging Service SID — Twilio picks the number.
    MessagingService(String),
}

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// An `http(s)` URL.
    pub url: String,
    /// Signs each request ([`WEBHOOK_SIGNATURE_HEADER`]) when set.
    pub secret: Option<Secret>,
    /// Sent as `Authorization: Bearer …` when set.
    pub bearer_token: Option<Secret>,
}

impl Default for DeliveryConfig {
    /// Both providers `log`.
    fn default() -> Self {
        Self {
            sender_name: DEFAULT_SENDER_NAME.into(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            email: EmailProvider::Log,
            sms: SmsProvider::Log,
        }
    }
}

impl DeliveryConfig {
    /// Reads the `AUTH_MFA_*` delivery variables (see [`crate::constants`]).
    /// Like z-auth's loaders, it does not read `.env` files itself.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Like [`Self::from_env`], reading variables through `get`.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let env = Env(&get);
        let timeout = match env.parse::<u64>(ENV_TIMEOUT_SECS)? {
            Some(0) => return Err(invalid(ENV_TIMEOUT_SECS, "must be greater than 0")),
            Some(s) => Duration::from_secs(s),
            None => Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        };
        let sender_name = std::iter::once(ENV_SENDER_NAME)
            .chain(ENV_SENDER_NAME_FALLBACKS)
            .find_map(|key| env.opt(key))
            .unwrap_or_else(|| DEFAULT_SENDER_NAME.into());
        Ok(Self {
            sender_name,
            timeout,
            email: email_provider(&env)?,
            sms: sms_provider(&env)?,
        })
    }
}

fn email_provider(env: &Env) -> Result<EmailProvider, ConfigError> {
    let provider = env
        .opt(ENV_EMAIL_PROVIDER)
        .unwrap_or_else(|| "log".into())
        .to_ascii_lowercase();
    let from = || -> Result<String, ConfigError> {
        let from = env.req(ENV_EMAIL_FROM, ENV_EMAIL_PROVIDER, &provider)?;
        validate_email(&from).map_err(|reason| invalid(ENV_EMAIL_FROM, reason))?;
        Ok(from)
    };
    Ok(match provider.as_str() {
        "log" => EmailProvider::Log,
        "smtp" => {
            compiled(cfg!(feature = "smtp"), ENV_EMAIL_PROVIDER, "smtp")?;
            let security = env
                .parse(ENV_SMTP_SECURITY)?
                .unwrap_or(SmtpSecurity::StartTls);
            let credentials = match (env.opt(ENV_SMTP_USERNAME), env.opt(ENV_SMTP_PASSWORD)) {
                (Some(user), Some(pass)) => Some((user, Secret(pass))),
                (None, None) => None,
                (Some(_), None) => {
                    return Err(ConfigError::Missing(format!(
                        "{ENV_SMTP_PASSWORD} (set with {ENV_SMTP_USERNAME})"
                    )));
                }
                (None, Some(_)) => {
                    return Err(ConfigError::Missing(format!(
                        "{ENV_SMTP_USERNAME} (set with {ENV_SMTP_PASSWORD})"
                    )));
                }
            };
            EmailProvider::Smtp(SmtpConfig {
                host: env.req(ENV_SMTP_HOST, ENV_EMAIL_PROVIDER, "smtp")?,
                port: env.parse(ENV_SMTP_PORT)?.unwrap_or(security.default_port()),
                security,
                credentials,
                from: from()?,
            })
        }
        "sendgrid" => {
            compiled(cfg!(feature = "sendgrid"), ENV_EMAIL_PROVIDER, "sendgrid")?;
            EmailProvider::SendGrid(SendGridConfig {
                api_key: Secret(env.req(ENV_SENDGRID_API_KEY, ENV_EMAIL_PROVIDER, "sendgrid")?),
                from: from()?,
                api_base: SENDGRID_API.into(),
            })
        }
        "postmark" => {
            compiled(cfg!(feature = "postmark"), ENV_EMAIL_PROVIDER, "postmark")?;
            EmailProvider::Postmark(PostmarkConfig {
                server_token: Secret(env.req(
                    ENV_POSTMARK_SERVER_TOKEN,
                    ENV_EMAIL_PROVIDER,
                    "postmark",
                )?),
                message_stream: env
                    .opt(ENV_POSTMARK_MESSAGE_STREAM)
                    .unwrap_or_else(|| DEFAULT_POSTMARK_STREAM.into()),
                from: from()?,
                api_base: POSTMARK_API.into(),
            })
        }
        "mailgun" => {
            compiled(cfg!(feature = "mailgun"), ENV_EMAIL_PROVIDER, "mailgun")?;
            let api_base = match env
                .opt(ENV_MAILGUN_REGION)
                .map(|r| r.to_ascii_lowercase())
                .as_deref()
            {
                None | Some("us") => MAILGUN_API_US,
                Some("eu") => MAILGUN_API_EU,
                Some(_) => return Err(invalid(ENV_MAILGUN_REGION, "expected us or eu")),
            };
            EmailProvider::Mailgun(MailgunConfig {
                api_key: Secret(env.req(ENV_MAILGUN_API_KEY, ENV_EMAIL_PROVIDER, "mailgun")?),
                domain: env.req(ENV_MAILGUN_DOMAIN, ENV_EMAIL_PROVIDER, "mailgun")?,
                from: from()?,
                api_base: api_base.into(),
            })
        }
        _ => {
            return Err(invalid(
                ENV_EMAIL_PROVIDER,
                "expected log, smtp, sendgrid, postmark or mailgun",
            ));
        }
    })
}

fn sms_provider(env: &Env) -> Result<SmsProvider, ConfigError> {
    let provider = env
        .opt(ENV_SMS_PROVIDER)
        .unwrap_or_else(|| "log".into())
        .to_ascii_lowercase();
    Ok(match provider.as_str() {
        "log" => SmsProvider::Log,
        "twilio" => {
            compiled(cfg!(feature = "twilio"), ENV_SMS_PROVIDER, "twilio")?;
            let sender = match (
                env.opt(ENV_TWILIO_FROM),
                env.opt(ENV_TWILIO_MESSAGING_SERVICE_SID),
            ) {
                (Some(from), None) => TwilioSender::From(from),
                (None, Some(sid)) => TwilioSender::MessagingService(sid),
                (None, None) => {
                    return Err(ConfigError::Missing(format!(
                        "{ENV_TWILIO_FROM} or {ENV_TWILIO_MESSAGING_SERVICE_SID} \
                         (required by {ENV_SMS_PROVIDER}=twilio)"
                    )));
                }
                (Some(_), Some(_)) => {
                    return Err(invalid(
                        ENV_TWILIO_FROM,
                        format!("set exactly one of it and {ENV_TWILIO_MESSAGING_SERVICE_SID}"),
                    ));
                }
            };
            SmsProvider::Twilio(TwilioConfig {
                account_sid: env.req(ENV_TWILIO_ACCOUNT_SID, ENV_SMS_PROVIDER, "twilio")?,
                auth_token: Secret(env.req(ENV_TWILIO_AUTH_TOKEN, ENV_SMS_PROVIDER, "twilio")?),
                sender,
                api_base: TWILIO_API.into(),
            })
        }
        "webhook" => {
            compiled(cfg!(feature = "webhook"), ENV_SMS_PROVIDER, "webhook")?;
            let url = env.req(ENV_SMS_WEBHOOK_URL, ENV_SMS_PROVIDER, "webhook")?;
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                return Err(invalid(ENV_SMS_WEBHOOK_URL, "must be an http(s) URL"));
            }
            SmsProvider::Webhook(WebhookConfig {
                url,
                secret: env.opt(ENV_SMS_WEBHOOK_SECRET).map(Secret),
                bearer_token: env.opt(ENV_SMS_WEBHOOK_BEARER_TOKEN).map(Secret),
            })
        }
        _ => return Err(invalid(ENV_SMS_PROVIDER, "expected log, twilio or webhook")),
    })
}

/// A plausible single address: `local@domain.tld`, no spaces or brackets.
pub(crate) fn validate_email(addr: &str) -> Result<(), String> {
    let ok = addr.len() <= MAX_EMAIL_LEN
        && !addr
            .chars()
            .any(|c| c.is_whitespace() || "<>,;\"".contains(c))
        && matches!(addr.split_once('@'), Some((local, domain))
            if !local.is_empty() && domain.contains('.') && !domain.contains('@')
                && !domain.starts_with('.') && !domain.ends_with('.'));
    if ok {
        Ok(())
    } else {
        Err(format!("{addr:?} is not an email address"))
    }
}

/// `provider` was selected but its feature isn't compiled in.
fn compiled(enabled: bool, key: &str, provider: &str) -> Result<(), ConfigError> {
    if enabled {
        Ok(())
    } else {
        Err(invalid(
            key,
            format!("z-auth-mfa-sender was built without the `{provider}` feature"),
        ))
    }
}

fn invalid(key: &str, reason: impl fmt::Display) -> ConfigError {
    ConfigError::Parse {
        key: key.into(),
        reason: reason.to_string(),
    }
}

/// Variable lookups; blank values count as unset.
struct Env<'a>(&'a dyn Fn(&str) -> Option<String>);

impl Env<'_> {
    fn opt(&self, key: &str) -> Option<String> {
        (self.0)(key)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    }

    /// `key`, required because `selector` is `provider`.
    fn req(&self, key: &str, selector: &str, provider: &str) -> Result<String, ConfigError> {
        self.opt(key).ok_or_else(|| {
            ConfigError::Missing(format!("{key} (required by {selector}={provider})"))
        })
    }

    fn parse<T>(&self, key: &str) -> Result<Option<T>, ConfigError>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        self.opt(key)
            .map(|v| v.parse::<T>().map_err(|e| invalid(key, e)))
            .transpose()
    }
}
