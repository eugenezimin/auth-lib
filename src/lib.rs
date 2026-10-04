//! # auth-lib
//!
//! A storage- and transport-agnostic authentication library.
//!
//! auth-lib defines the auth domain — users, roles, sessions, tokens — and
//! the **ports** (traits) it needs from the outside world.  The host
//! application supplies the adapters (database repositories, HTTP routing);
//! the library ships no database driver and no web server.
//!
//! ## Layout
//!
//! Each bounded context follows the same shape:
//!
//! | file              | contents                                   |
//! |-------------------|--------------------------------------------|
//! | `model.rs`        | plain data structures                      |
//! | `repository.rs`   | persistence ports the host implements      |
//! | `service.rs`      | public service trait                       |
//! | `service_impl.rs` | default service implementation             |
//!
//! Contexts: [`user`], [`access`] (roles), [`authorization`] (permissions,
//! token claims, request-time checks), [`credentials`], [`authentication`],
//! [`token`].  Cross-cutting: [`config`], [`constants`], [`error`], [`clock`],
//! [`api`] (framework-agnostic endpoint contracts) and [`facade`] ([`AuthLib`]).
//!
//! ## Features
//!
//! - `argon2` *(default)* — built-in Argon2id password hasher.
//! - `crypto` *(default)* — built-in Ed25519 JWT access tokens and HMAC refresh tokens.
//! - `serde` — `Serialize`/`Deserialize` on models and API DTOs.

pub mod access;
pub mod api;
pub mod authentication;
pub mod authorization;
pub mod clock;
#[cfg(feature = "cluster")]
pub mod cluster;
pub mod config;
pub mod constants;
pub mod credentials;
pub mod error;
pub mod events;
pub mod facade;
pub mod prelude;
mod random;
pub mod token;
pub mod user;

pub use error::AuthError;
pub use facade::{AuthLib, AuthLibBuilder, Repositories};
