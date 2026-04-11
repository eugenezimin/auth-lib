//! Configuration loader interface.
//!
//! Defines the [`ConfigLoader`] trait that any config source must implement,
//! plus the two built-in loaders shipped with the library:
//!
//! - [`EnvLoader`]    – reads from environment variables / `.env` file  *(default)*
//! - [`DirectLoader`] – accepts a pre-filled [`RawConfig`] struct directly
//!
//! # Adding a custom loader
//!
//! ```rust,no_run
//! use auth_lib::interfaces::config::{ConfigLoader, RawConfig};
//! use auth_lib::model::config::ConfigError;
//!
//! struct VaultLoader { token: String }
//!
//! impl ConfigLoader for VaultLoader {
//!     fn load(&self) -> Result<RawConfig, ConfigError> {
//!         // fetch secrets from HashiCorp Vault, a remote KV store, etc.
//!         Ok(RawConfig {
//!             db_host:     "db.internal".into(),
//!             db_password: "vault-secret".into(),
//!             jwt_secret:  "vault-jwt-key".into(),
//!             ..RawConfig::default()
//!         })
//!     }
//! }
//! ```

use std::time::Duration;

use crate::model::config::{
    ConfigError, DatabaseConfig, EnvLoader, JwtConfig, RawConfig, ServerConfig,
};

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Any type that can produce a [`RawConfig`] snapshot.
///
/// Implement this trait to plug in custom config sources (Vault, AWS SSM,
/// a TOML file, a test fixture, …).  The library calls [`load`](Self::load)
/// exactly once during [`Config::init_with`](crate::model::config::Config::init_with).
pub trait ConfigLoader: Send + Sync {
    fn load(&self) -> Result<RawConfig, ConfigError>;
}
