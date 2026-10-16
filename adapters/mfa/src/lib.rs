//! # z-auth-mfa
//!
//! Two-factor authentication for [z-auth](z_auth), plugged into
//! [`ZAuth`](z_auth::ZAuth) as an [`Extension`](z_auth::Extension) and
//! configured entirely through `AUTH_MFA_*` ([`config`]):
//!
//! ```rust,ignore
//! use z_auth_mfa::{Mfa, config::{MfaConfigLoader, MfaEnvLoader}};
//!
//! let mfa = Arc::new(Mfa::new(MfaEnvLoader.load_settings()?, mfa_repository));
//! let auth = ZAuth::builder(config, repos).extension(mfa.clone()).build()?;
//!
//! match auth.authentication().login(credentials, ctx.clone()).await? {
//!     LoginOutcome::Tokens(pair) => { /* no second factor needed */ }
//!     LoginOutcome::SecondFactor(challenge) => {
//!         // ask for a code, then
//!         let pair = auth.authentication().complete_login(proof, ctx).await?;
//!     }
//! }
//! ```
//!
//! Second factors:
//!
//! - **TOTP** — authenticator apps (RFC 6238; SHA-1/256/512, 6–8 digits).
//!   Secrets are sealed at rest and every time step is accepted once.
//! - **Email / SMS codes** — generated and checked here, delivered by the
//!   host's [`CodeSender`].
//! - **Recovery codes** — issued with the first factor, single use, stored
//!   as keyed hashes.
//!
//! A login challenge is a stored row: attempts per challenge, single use,
//! optional client binding and a per-user lockout are enforced by the
//! store ([`MfaRepository`]).  Sessions opened through a second factor
//! carry `amr` = `["mfa", "otp" | "sms", "pwd"]`; guard sensitive routes
//! with z-auth's `Authorizer::require_mfa`.
//!
//! Enrollment and factor management go through [`MfaService`]
//! ([`Mfa::service`]), with framework-agnostic endpoints in [`api`].
//!
//! ## Features
//!
//! - `aead` *(default)* — built-in XChaCha20-Poly1305 [`SecretSealer`];
//!   without it the host supplies one ([`Mfa::with_sealer`]).
//!
//! z-auth-mfa ships no database code: `z-auth-postgres` implements
//! [`MfaRepository`] behind its `mfa` feature.

pub mod api;
pub mod config;
pub mod constants;
pub mod crypto;
mod extension;
pub mod gate;
pub mod keys;
pub mod model;
pub mod prelude;
pub mod report;
pub mod repository;
pub mod sender;
pub mod service;
pub mod service_impl;

pub use crypto::SecretSealer;
pub use extension::{EXTENSION_NAME, Mfa};
pub use model::MfaMethod;
pub use report::MfaTickReport;
pub use repository::MfaRepository;
pub use sender::{CodeDelivery, CodePurpose, CodeSender};
pub use service::MfaService;
pub use service_impl::MfaServiceImpl;
