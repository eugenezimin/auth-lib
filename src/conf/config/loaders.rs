//! Configuration implementation.
//!
//! Provides the built-in [`ConfigLoader`]s and all `impl` blocks for the
//! types declared in [`crate::conf::config::model`].
//!
//! # Example — environment variables
//!
//! ```rust,no_run
//! use z_auth::conf::config::{ConfigLoader, EnvLoader};
//!
//! let config = EnvLoader.load_config().expect("failed to load config");
//! ```
//!
//! # Example — pre-filled struct (no env)
//!
//! ```rust
//! use z_auth::conf::config::{ConfigLoader, DirectLoader, RawConfig};
//!
//! let config = DirectLoader::new(RawConfig::default().jwt_issuer("my-auth"))
//!     .load_config()
//!     .expect("failed to load config");
//! assert_eq!(config.jwt.issuer, "my-auth");
//! ```

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::conf::config::loader::ConfigLoader;
use crate::conf::config::model::{
    AuthConfig, AuthzConfig, AuthzMode, ConfigError, JwtConfig, PasswordPolicy, RawConfig,
    RetryMatch, SessionConfig,
};
use crate::conf::constants::*;

// ── Loaders ───────────────────────────────────────────────────────────────────

/// Loads configuration from `AUTH_*` environment variables.
///
/// Reads the process environment only — loading a `.env` file is left to the
/// host application (e.g. via `dotenvy`) so the library never mutates the
/// environment.
pub struct EnvLoader;

/// Loads configuration from a caller-supplied [`RawConfig`] struct.
///
/// Useful in tests, CLI tools, or any context where the caller already holds
/// the values.
pub struct DirectLoader {
    pub raw_config: RawConfig,
}

impl DirectLoader {
    pub fn new(raw_config: RawConfig) -> Self {
        Self { raw_config }
    }
}

impl ConfigLoader for DirectLoader {
    fn load(&self) -> Result<RawConfig, ConfigError> {
        Ok(self.raw_config.clone())
    }
}

impl ConfigLoader for EnvLoader {
    fn load(&self) -> Result<RawConfig, ConfigError> {
        Ok(RawConfig {
            jwt_signing_key: env_str(ENV_JWT_SIGNING_KEY),
            jwt_verifying_keys: env_str(ENV_JWT_VERIFYING_KEYS).map(|v| {
                v.split(',')
                    .map(|k| k.trim().to_string())
                    .filter(|k| !k.is_empty())
                    .collect()
            }),
            jwt_access_ttl_secs: parse_opt(ENV_JWT_ACCESS_TTL_SECS)?,
            jwt_leeway_secs: parse_opt(ENV_JWT_LEEWAY_SECS)?,
            jwt_issuer: env_str(ENV_JWT_ISSUER),
            refresh_secret: env_str(ENV_REFRESH_SECRET),
            session_idle_timeout_secs: parse_opt(ENV_SESSION_IDLE_TIMEOUT_SECS)?,
            session_absolute_timeout_secs: parse_opt(ENV_SESSION_ABSOLUTE_TIMEOUT_SECS)?,
            session_history_size: parse_opt(ENV_SESSION_HISTORY_SIZE)?,
            refresh_grace_secs: parse_opt(ENV_REFRESH_GRACE_SECS)?,
            ip_binding: parse_opt(ENV_IP_BINDING)?,
            max_sessions_per_user: parse_opt(ENV_MAX_SESSIONS_PER_USER)?,
            password_min_length: parse_opt(ENV_PASSWORD_MIN_LENGTH)?,
            password_require_uppercase: parse_opt(ENV_PASSWORD_REQUIRE_UPPERCASE)?,
            password_require_digit: parse_opt(ENV_PASSWORD_REQUIRE_DIGIT)?,
            authz_mode: env_str(ENV_AUTHZ_MODE),
            refresh_retry_match: env_str(ENV_REFRESH_RETRY_MATCH),
        })
    }
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn parse_opt<T>(key: &str) -> Result<Option<T>, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Err(_) => Ok(None),
        Ok(raw) => raw.parse::<T>().map(Some).map_err(|e| ConfigError::Parse {
            key: key.into(),
            reason: e.to_string(),
        }),
    }
}

fn decode_b64(field: &str, value: &str) -> Result<Vec<u8>, ConfigError> {
    BASE64.decode(value.trim()).map_err(|e| ConfigError::Parse {
        key: field.into(),
        reason: format!("invalid base64: {e}"),
    })
}

fn decode_key(field: &str, value: &str) -> Result<[u8; 32], ConfigError> {
    decode_b64(field, value)?
        .try_into()
        .map_err(|v: Vec<u8>| ConfigError::Parse {
            key: field.into(),
            reason: format!("expected {ED25519_KEY_LEN} bytes, got {}", v.len()),
        })
}

// ── RawConfig impls ───────────────────────────────────────────────────────────

impl RawConfig {
    /// Base64 Ed25519 signing seed (32 bytes).
    pub fn jwt_signing_key(mut self, v: impl Into<String>) -> Self {
        self.jwt_signing_key = Some(v.into());
        self
    }
    /// Base64 Ed25519 verifying keys (32 bytes each).
    pub fn jwt_verifying_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.jwt_verifying_keys = Some(keys.into_iter().map(Into::into).collect());
        self
    }
    pub fn jwt_access_ttl_secs(mut self, v: u64) -> Self {
        self.jwt_access_ttl_secs = Some(v);
        self
    }
    pub fn jwt_leeway_secs(mut self, v: u64) -> Self {
        self.jwt_leeway_secs = Some(v);
        self
    }
    pub fn jwt_issuer(mut self, v: impl Into<String>) -> Self {
        self.jwt_issuer = Some(v.into());
        self
    }
    /// Base64 refresh-token HMAC key (at least 32 bytes).
    pub fn refresh_secret(mut self, v: impl Into<String>) -> Self {
        self.refresh_secret = Some(v.into());
        self
    }
    pub fn session_idle_timeout_secs(mut self, v: u64) -> Self {
        self.session_idle_timeout_secs = Some(v);
        self
    }
    pub fn session_absolute_timeout_secs(mut self, v: u64) -> Self {
        self.session_absolute_timeout_secs = Some(v);
        self
    }
    pub fn session_history_size(mut self, v: u32) -> Self {
        self.session_history_size = Some(v);
        self
    }
    pub fn refresh_grace_secs(mut self, v: u64) -> Self {
        self.refresh_grace_secs = Some(v);
        self
    }
    pub fn ip_binding(mut self, v: bool) -> Self {
        self.ip_binding = Some(v);
        self
    }
    pub fn max_sessions_per_user(mut self, v: u32) -> Self {
        self.max_sessions_per_user = Some(v);
        self
    }
    pub fn password_min_length(mut self, v: usize) -> Self {
        self.password_min_length = Some(v);
        self
    }
    pub fn password_require_uppercase(mut self, v: bool) -> Self {
        self.password_require_uppercase = Some(v);
        self
    }
    pub fn password_require_digit(mut self, v: bool) -> Self {
        self.password_require_digit = Some(v);
        self
    }
    /// `none` | `rbac` | `permissions` | `combined`.
    pub fn authz_mode(mut self, v: impl Into<String>) -> Self {
        self.authz_mode = Some(v.into());
        self
    }
    /// Comma set of `ip`, `user_agent`, `fingerprint`.
    pub fn refresh_retry_match(mut self, v: impl Into<String>) -> Self {
        self.refresh_retry_match = Some(v.into());
        self
    }

    /// Validate and convert into a typed [`AuthConfig`].
    ///
    /// Returns [`ConfigError::Parse`] for malformed keys or out-of-range
    /// values.  Keys are optional here; their presence is checked where they
    /// are used.
    pub fn build(self) -> Result<AuthConfig, ConfigError> {
        let signing_key = self
            .jwt_signing_key
            .as_deref()
            .map(|k| decode_key(FIELD_JWT_SIGNING_KEY, k))
            .transpose()?;
        let verifying_keys = self
            .jwt_verifying_keys
            .unwrap_or_default()
            .iter()
            .map(|k| decode_key(FIELD_JWT_VERIFYING_KEYS, k))
            .collect::<Result<Vec<_>, _>>()?;

        let refresh_secret = self
            .refresh_secret
            .as_deref()
            .map(|s| decode_b64(FIELD_REFRESH_SECRET, s))
            .transpose()?;
        if let Some(ref secret) = refresh_secret
            && secret.len() < MIN_REFRESH_SECRET_LEN
        {
            return Err(ConfigError::Parse {
                key: FIELD_REFRESH_SECRET.into(),
                reason: format!(
                    "must be at least {MIN_REFRESH_SECRET_LEN} bytes, got {}",
                    secret.len()
                ),
            });
        }

        let history_size = self
            .session_history_size
            .unwrap_or(DEFAULT_SESSION_HISTORY_SIZE);
        if history_size < 2 {
            return Err(ConfigError::Parse {
                key: ENV_SESSION_HISTORY_SIZE.into(),
                reason: "must be at least 2 (current + previous generation)".into(),
            });
        }

        let jwt = JwtConfig {
            signing_key,
            verifying_keys,
            access_token_ttl: secs(self.jwt_access_ttl_secs, DEFAULT_ACCESS_TOKEN_TTL_SECS),
            leeway: secs(self.jwt_leeway_secs, DEFAULT_JWT_LEEWAY_SECS),
            issuer: self.jwt_issuer.unwrap_or_else(|| DEFAULT_JWT_ISSUER.into()),
        };

        let session = SessionConfig {
            refresh_secret,
            idle_timeout: secs(
                self.session_idle_timeout_secs,
                DEFAULT_SESSION_IDLE_TIMEOUT_SECS,
            ),
            absolute_timeout: secs(
                self.session_absolute_timeout_secs,
                DEFAULT_SESSION_ABSOLUTE_TIMEOUT_SECS,
            ),
            history_size,
            refresh_grace: secs(self.refresh_grace_secs, DEFAULT_REFRESH_GRACE_SECS),
            ip_binding: self.ip_binding.unwrap_or(DEFAULT_IP_BINDING),
            retry_match: self
                .refresh_retry_match
                .as_deref()
                .map(str::parse)
                .transpose()?
                .unwrap_or_default(),
            max_sessions_per_user: self
                .max_sessions_per_user
                .unwrap_or(DEFAULT_MAX_SESSIONS_PER_USER),
        };

        let password = PasswordPolicy {
            min_length: self
                .password_min_length
                .unwrap_or(DEFAULT_PASSWORD_MIN_LENGTH),
            require_uppercase: self
                .password_require_uppercase
                .unwrap_or(DEFAULT_PASSWORD_REQUIRE_UPPERCASE),
            require_digit: self
                .password_require_digit
                .unwrap_or(DEFAULT_PASSWORD_REQUIRE_DIGIT),
        };

        let authz = AuthzConfig {
            mode: self
                .authz_mode
                .as_deref()
                .unwrap_or(DEFAULT_AUTHZ_MODE)
                .parse()?,
        };

        Ok(AuthConfig {
            jwt,
            session,
            password,
            authz,
        })
    }
}

impl std::str::FromStr for AuthzMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, ConfigError> {
        match s.trim() {
            "none" => Ok(Self::None),
            "rbac" => Ok(Self::Rbac),
            "permissions" => Ok(Self::Permissions),
            "combined" => Ok(Self::Combined),
            other => Err(ConfigError::Parse {
                key: ENV_AUTHZ_MODE.into(),
                reason: format!("expected none | rbac | permissions | combined, got '{other}'"),
            }),
        }
    }
}

impl std::str::FromStr for RetryMatch {
    type Err = ConfigError;

    /// Comma set of `ip`, `user_agent`, `fingerprint`; at least one.
    fn from_str(s: &str) -> Result<Self, ConfigError> {
        let mut m = RetryMatch {
            ip: false,
            user_agent: false,
            fingerprint: false,
        };
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part {
                "ip" => m.ip = true,
                "user_agent" => m.user_agent = true,
                "fingerprint" => m.fingerprint = true,
                other => {
                    return Err(ConfigError::Parse {
                        key: ENV_REFRESH_RETRY_MATCH.into(),
                        reason: format!(
                            "unknown criterion '{other}' (ip | user_agent | fingerprint)"
                        ),
                    });
                }
            }
        }
        if !(m.ip || m.user_agent || m.fingerprint) {
            return Err(ConfigError::Parse {
                key: ENV_REFRESH_RETRY_MATCH.into(),
                reason: "at least one criterion is required".into(),
            });
        }
        Ok(m)
    }
}

fn secs(v: Option<u64>, default: u64) -> Duration {
    Duration::from_secs(v.unwrap_or(default))
}

// ── Defaults ──────────────────────────────────────────────────────────────────

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: DEFAULT_PASSWORD_MIN_LENGTH,
            require_uppercase: DEFAULT_PASSWORD_REQUIRE_UPPERCASE,
            require_digit: DEFAULT_PASSWORD_REQUIRE_DIGIT,
        }
    }
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfig")
            .field("signing_key", &self.signing_key.map(|_| REDACTED))
            .field("verifying_keys", &self.verifying_keys.len())
            .field("access_token_ttl", &self.access_token_ttl)
            .field("leeway", &self.leeway)
            .field("issuer", &self.issuer)
            .finish()
    }
}

impl std::fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionConfig")
            .field(
                "refresh_secret",
                &self.refresh_secret.as_ref().map(|_| REDACTED),
            )
            .field("idle_timeout", &self.idle_timeout)
            .field("absolute_timeout", &self.absolute_timeout)
            .field("history_size", &self.history_size)
            .field("refresh_grace", &self.refresh_grace)
            .field("ip_binding", &self.ip_binding)
            .field("retry_match", &self.retry_match)
            .field("max_sessions_per_user", &self.max_sessions_per_user)
            .finish()
    }
}

impl std::fmt::Debug for RawConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawConfig")
            .field(
                "jwt_signing_key",
                &self.jwt_signing_key.as_ref().map(|_| REDACTED),
            )
            .field("jwt_verifying_keys", &self.jwt_verifying_keys)
            .field("jwt_access_ttl_secs", &self.jwt_access_ttl_secs)
            .field("jwt_leeway_secs", &self.jwt_leeway_secs)
            .field("jwt_issuer", &self.jwt_issuer)
            .field(
                "refresh_secret",
                &self.refresh_secret.as_ref().map(|_| REDACTED),
            )
            .field("session_idle_timeout_secs", &self.session_idle_timeout_secs)
            .field(
                "session_absolute_timeout_secs",
                &self.session_absolute_timeout_secs,
            )
            .field("session_history_size", &self.session_history_size)
            .field("refresh_grace_secs", &self.refresh_grace_secs)
            .field("ip_binding", &self.ip_binding)
            .field("max_sessions_per_user", &self.max_sessions_per_user)
            .field("authz_mode", &self.authz_mode)
            .field("refresh_retry_match", &self.refresh_retry_match)
            .finish()
    }
}

// ── ConfigError impls ─────────────────────────────────────────────────────────

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(key) => {
                write!(f, "missing required configuration field: {key}")
            }
            Self::Parse { key, reason } => {
                write!(f, "failed to parse configuration field '{key}': {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}
