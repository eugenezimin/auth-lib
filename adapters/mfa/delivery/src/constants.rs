//! z-auth-mfa-sender constants: defaults, provider endpoints and the
//! `AUTH_MFA_*` environment variables read by
//! [`DeliveryConfig::from_env`](crate::DeliveryConfig::from_env).

// ── Defaults ──────────────────────────────────────────────────────────────────

/// Sender name when neither `AUTH_MFA_SENDER_NAME`, `AUTH_MFA_TOTP_ISSUER`
/// nor `AUTH_JWT_ISSUER` is set.
pub const DEFAULT_SENDER_NAME: &str = "z-auth";
/// Per send — codes go out while the user's request waits.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
pub const SMTP_STARTTLS_PORT: u16 = 587;
pub const SMTP_TLS_PORT: u16 = 465;
pub const SMTP_PLAIN_PORT: u16 = 25;
/// Postmark's default transactional stream.
pub const DEFAULT_POSTMARK_STREAM: &str = "outbound";
/// Longest email address accepted (RFC 5321 path limit).
pub const MAX_EMAIL_LEN: usize = 254;
/// Characters of a provider's error answer kept in `CodeDeliveryFailed`.
pub const MAX_ERROR_BODY_CHARS: usize = 200;

// ── Provider endpoints ────────────────────────────────────────────────────────

pub const SENDGRID_API: &str = "https://api.sendgrid.com";
pub const POSTMARK_API: &str = "https://api.postmarkapp.com";
pub const MAILGUN_API_US: &str = "https://api.mailgun.net";
pub const MAILGUN_API_EU: &str = "https://api.eu.mailgun.net";
pub const TWILIO_API: &str = "https://api.twilio.com";

// ── Webhook ───────────────────────────────────────────────────────────────────

/// Unix time (seconds) the webhook request was signed at.
pub const WEBHOOK_TIMESTAMP_HEADER: &str = "X-ZAuth-Timestamp";
/// `sha256=<hex HMAC-SHA256(secret, "{timestamp}.{body}")>`.
pub const WEBHOOK_SIGNATURE_HEADER: &str = "X-ZAuth-Signature";

// ── Environment variables ─────────────────────────────────────────────────────

/// `log` | `smtp` | `sendgrid` | `postmark` | `mailgun`.
pub const ENV_EMAIL_PROVIDER: &str = "AUTH_MFA_EMAIL_PROVIDER";
/// `log` | `twilio` | `webhook`.
pub const ENV_SMS_PROVIDER: &str = "AUTH_MFA_SMS_PROVIDER";
pub const ENV_SENDER_NAME: &str = "AUTH_MFA_SENDER_NAME";
/// Fallbacks for the sender name, in order (z-auth-mfa's TOTP issuer, then
/// z-auth's JWT issuer).
pub const ENV_SENDER_NAME_FALLBACKS: [&str; 2] = ["AUTH_MFA_TOTP_ISSUER", "AUTH_JWT_ISSUER"];
pub const ENV_EMAIL_FROM: &str = "AUTH_MFA_EMAIL_FROM";
pub const ENV_TIMEOUT_SECS: &str = "AUTH_MFA_DELIVERY_TIMEOUT_SECS";

pub const ENV_SMTP_HOST: &str = "AUTH_MFA_SMTP_HOST";
pub const ENV_SMTP_PORT: &str = "AUTH_MFA_SMTP_PORT";
/// `starttls` | `tls` | `none`.
pub const ENV_SMTP_SECURITY: &str = "AUTH_MFA_SMTP_SECURITY";
pub const ENV_SMTP_USERNAME: &str = "AUTH_MFA_SMTP_USERNAME";
pub const ENV_SMTP_PASSWORD: &str = "AUTH_MFA_SMTP_PASSWORD";

pub const ENV_SENDGRID_API_KEY: &str = "AUTH_MFA_SENDGRID_API_KEY";

pub const ENV_POSTMARK_SERVER_TOKEN: &str = "AUTH_MFA_POSTMARK_SERVER_TOKEN";
pub const ENV_POSTMARK_MESSAGE_STREAM: &str = "AUTH_MFA_POSTMARK_MESSAGE_STREAM";

pub const ENV_MAILGUN_API_KEY: &str = "AUTH_MFA_MAILGUN_API_KEY";
pub const ENV_MAILGUN_DOMAIN: &str = "AUTH_MFA_MAILGUN_DOMAIN";
/// `us` | `eu`.
pub const ENV_MAILGUN_REGION: &str = "AUTH_MFA_MAILGUN_REGION";

pub const ENV_TWILIO_ACCOUNT_SID: &str = "AUTH_MFA_TWILIO_ACCOUNT_SID";
pub const ENV_TWILIO_AUTH_TOKEN: &str = "AUTH_MFA_TWILIO_AUTH_TOKEN";
pub const ENV_TWILIO_FROM: &str = "AUTH_MFA_TWILIO_FROM";
pub const ENV_TWILIO_MESSAGING_SERVICE_SID: &str = "AUTH_MFA_TWILIO_MESSAGING_SERVICE_SID";

pub const ENV_SMS_WEBHOOK_URL: &str = "AUTH_MFA_SMS_WEBHOOK_URL";
pub const ENV_SMS_WEBHOOK_SECRET: &str = "AUTH_MFA_SMS_WEBHOOK_SECRET";
pub const ENV_SMS_WEBHOOK_BEARER_TOKEN: &str = "AUTH_MFA_SMS_WEBHOOK_BEARER_TOKEN";
