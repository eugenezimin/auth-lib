//! z-auth-mfa-delivery — delivers z-auth-mfa's email and SMS codes.
//!
//! z-auth-mfa generates, stores and checks codes and leaves delivery to a
//! [`CodeSender`](z_auth_mfa::CodeSender).  This crate provides one per
//! provider, picked by configuration:
//!
//! - email: SMTP (`smtp`), SendGrid (`sendgrid`), Postmark (`postmark`),
//!   Mailgun (`mailgun`);
//! - SMS: Twilio (`twilio`), or a JSON `POST` to your own gateway signed
//!   with HMAC-SHA256 (`webhook`);
//! - `log` for either: the code is written to the log (development).
//!
//! Each provider is a Cargo feature of the same name (all on by default).
//!
//! ```no_run
//! # fn wire() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use z_auth_mfa::Mfa;
//! use z_auth_mfa::config::{MfaConfigLoader, MfaEnvLoader};
//! use z_auth_mfa_delivery::DeliveryConfig;
//! # let repo: Arc<dyn z_auth_mfa::MfaRepository> = unimplemented!();
//!
//! let delivery = DeliveryConfig::from_env()?;               // AUTH_MFA_*_PROVIDER, …
//! let mfa = Mfa::new(MfaEnvLoader.load_settings()?, repo)
//!     .with_code_sender(z_auth_mfa_delivery::build(&delivery)?);
//! # Ok(()) }
//! ```
//!
//! Codes are sent while the user's request waits, so every provider runs
//! with a timeout (`AUTH_MFA_DELIVERY_TIMEOUT_SECS`).  Failures are
//! `AuthError::CodeDeliveryFailed` — 503 `code_delivery_failed` over
//! z-auth's HTTP mapping, with the provider's answer kept for the host's
//! log.  Real providers never log codes.

pub mod config;
pub mod constants;
pub mod email;
pub mod log;
pub mod message;
pub mod sms;

#[cfg(feature = "http")]
mod http;
mod router;

pub use config::{DeliveryConfig, EmailProvider, Secret, SmsProvider};
pub use log::LogCodeSender;
pub use router::{MethodRouter, build, email_sender, mask, sms_sender};
