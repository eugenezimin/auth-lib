//! Configuration loader interface.
//!
//! Defines the [`ConfigLoader`] trait that any config source must implement.
//! Built-in implementations live in [`crate::conf::config::loaders`]:
//!
//! - [`EnvLoader`](crate::conf::config::EnvLoader)       – reads `AUTH_*` environment variables
//! - [`SourceLoader`](crate::conf::config::SourceLoader) – reads a [`ConfigSource`](crate::conf::config::ConfigSource):
//!   the `auth` section of a YAML file, the environment, or both
//! - [`DirectLoader`](crate::conf::config::DirectLoader) – accepts a pre-filled [`RawConfig`]
//!
//! # Adding a custom loader
//!
//! ```rust
//! use z_auth::conf::config::{ConfigError, ConfigLoader, RawConfig};
//!
//! struct VaultLoader;
//!
//! impl ConfigLoader for VaultLoader {
//!     fn load(&self) -> Result<RawConfig, ConfigError> {
//!         // fetch secrets from HashiCorp Vault, a remote KV store, etc.
//!         Ok(RawConfig::default().refresh_secret("dmF1bHQtc2VjcmV0LXZhdWx0LXNlY3JldC12YXVsdA=="))
//!     }
//! }
//! ```

use crate::conf::config::model::{AuthConfig, ConfigError, RawConfig};

/// Any type that can produce a [`RawConfig`] snapshot.
///
/// Implement this trait to plug in custom config sources (Vault, AWS SSM,
/// a TOML file, a test fixture, …).
pub trait ConfigLoader: Send + Sync {
    fn load(&self) -> Result<RawConfig, ConfigError>;

    /// Load and validate into a ready-to-use [`AuthConfig`].
    fn load_config(&self) -> Result<AuthConfig, ConfigError> {
        self.load()?.build()
    }
}
