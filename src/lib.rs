//! # z-auth
//!
//! A storage- and transport-agnostic authentication library.
//!
//! z-auth defines the auth domain — users, roles, sessions, tokens — and
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
//! Contexts, grouped by area:
//!
//! | module         | contexts                                                       |
//! |----------------|----------------------------------------------------------------|
//! | [`identity`]   | [`user`](identity::user), [`credentials`](identity::credentials), [`access`](identity::access) (roles) |
//! | [`security`]   | [`authentication`](security::authentication), [`authorization`](security::authorization) (permissions, token claims, request-time checks), [`session`](security::session), [`token`](security::token) |
//! | [`eventing`]   | domain events and the publisher port                           |
//! | [`conf`]       | [`config`](conf::config), [`constants`](conf::constants)        |
//! | [`utils`]      | [`error`](utils::error), [`clock`](utils::clock), [`fence`](utils::fence), [`validation`](utils::validation) |
//! | [`controller`] | [`facade`](controller::facade) ([`ZAuth`]), [`extension`](controller::extension) ([`Extension`]), [`api`](controller::api) (framework-agnostic endpoint contracts), [`prelude`] |
//!
//! Groups depend on each other in one direction only, with no cycles:
//! `controller` → `eventing` → `security` → `identity` → `utils` → `conf`.
//! A lower layer that must notify a higher one does so through its own port
//! ([`TokenEvents`](security::token::TokenEvents),
//! [`CatalogEvents`](security::authorization::CatalogEvents),
//! [`AccountSessions`](identity::user::AccountSessions)), which the higher
//! layer implements.
//!
//! ## Extensions
//!
//! Optional components plug in through the [`Extension`] port on
//! [`ZAuthBuilder::extension`]: they subscribe to domain events (new and
//! enforced revocations — the denylist changes —, verifying keys, catalog
//! changes), may wrap services and install a refresh gate or a serving
//! fence, and are driven by [`ZAuth::start`], [`tick`](ZAuth::tick) and
//! [`shutdown`](ZAuth::shutdown).  Clustering — shared mode and
//! federation mode — lives in the separate `z-auth-cluster` crate, which
//! the service application imports when it needs it.
//!
//! ## Features
//!
//! - `argon2` *(default)* — built-in Argon2id password hasher.
//! - `crypto` *(default)* — built-in Ed25519 JWT access tokens and HMAC refresh tokens.
//! - `serde` *(default)* — `Serialize`/`Deserialize` on models and API DTOs.

pub mod conf;
pub mod controller;
pub mod eventing;
pub mod identity;
pub mod security;
pub mod utils;

pub use controller::extension::Extension;
pub use controller::facade::{Repositories, ZAuth, ZAuthBuilder};
pub use controller::prelude;
pub use utils::error::AuthError;

/// This z-auth version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
