/// Configuration loader interface.
///
/// Defines the [`ConfigLoader`] trait that any config source must implement,
/// plus the two built-in loaders shipped with the library:
///
/// - [`EnvLoader`]    – reads from environment variables / `.env` file  *(default)*
/// - [`DirectLoader`] – accepts a pre-filled [`RawConfig`] struct directly
///
/// # Adding a custom loader
///
/// ```rust,ignore
/// use auth_lib::interfaces::config::{ConfigLoader, RawConfig};
/// use auth_lib::model::config::ConfigError;
///
/// struct VaultLoader { token: String }
///
/// impl ConfigLoader for VaultLoader {
///     fn load(&self) -> Result<RawConfig, ConfigError> {
///         // fetch secrets from HashiCorp Vault, a remote KV store, etc.
///         Ok(RawConfig {
///             db_host:     Some("db.internal".into()),
///             db_password: Some("vault-secret".into()),
///             jwt_secret:  Some("vault-jwt-key".into()),
///             ..RawConfig::default()
///         })
///     }
/// }
/// ```
use crate::model::config::{ConfigError, RawConfig};

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Any type that can produce a [`RawConfig`] snapshot.
///
/// Implement this trait to plug in custom config sources (Vault, AWS SSM,
/// a TOML file, a test fixture, …).  The library calls [`load`](Self::load)
/// exactly once during [`Config::init_with`](crate::model::config::Config::init_with).
pub trait ConfigLoader: Send + Sync {
    fn load(&self) -> Result<RawConfig, ConfigError>;
}

// ── Built-in loaders ──────────────────────────────────────────────────────────

/// Loads configuration from environment variables (and an optional `.env` file).
///
/// This is the default loader used by [`Config::init`].
pub struct EnvLoader;

/// Loads configuration from a caller-supplied [`RawConfig`] struct.
///
/// Useful in tests, CLI tools, or any context where the caller already holds
/// the values and does not want to go through environment variables.
///
/// # Example
///
/// ```rust,ignore
/// use auth_lib::interfaces::config::{DirectLoader, RawConfig};
/// use auth_lib::model::config::Config;
///
/// Config::init_with(DirectLoader::new(
///     RawConfig::default()
///         .db_host("localhost")
///         .db_user("postgres")
///         .db_password("secret")
///         .jwt_secret("super-secret-key"),
/// ))
/// .expect("config failed");
/// ```
pub struct DirectLoader {
    pub raw_config: RawConfig,
}
