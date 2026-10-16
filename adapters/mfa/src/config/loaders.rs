//! z-auth-mfa configuration loaders: [`MfaEnvLoader`] (environment) and
//! [`MfaDirectLoader`] (a pre-filled [`RawMfaConfig`]), plus the parsing
//! and validation behind [`RawMfaConfig::build`].
//!
//! ```rust,no_run
//! use z_auth_mfa::config::{MfaConfigLoader, MfaEnvLoader};
//!
//! let settings = MfaEnvLoader.load_settings().expect("mfa config");
//! ```

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use z_auth::conf::config::{ConfigError, RetryMatch};

use crate::config::model::{
    ChallengeConfig, CodeConfig, Enforcement, LockoutConfig, MfaKeys, MfaSettings, RawMfaConfig,
    RecoveryConfig, TotpConfig, Unenrolled,
};
use crate::constants::*;
use crate::model::{MfaMethod, TotpAlgorithm};

/// Any source of a [`RawMfaConfig`].
pub trait MfaConfigLoader: Send + Sync {
    fn load(&self) -> Result<RawMfaConfig, ConfigError>;

    /// Load and validate into [`MfaSettings`].
    fn load_settings(&self) -> Result<MfaSettings, ConfigError> {
        self.load()?.build()
    }
}

/// Reads the `AUTH_MFA_*` environment variables.  Like z-auth's
/// `EnvLoader`, it never loads a `.env` file itself.
pub struct MfaEnvLoader;

/// A caller-supplied [`RawMfaConfig`].
pub struct MfaDirectLoader {
    pub raw_config: RawMfaConfig,
}

impl MfaDirectLoader {
    pub fn new(raw_config: RawMfaConfig) -> Self {
        Self { raw_config }
    }
}

impl MfaConfigLoader for MfaDirectLoader {
    fn load(&self) -> Result<RawMfaConfig, ConfigError> {
        Ok(self.raw_config.clone())
    }
}

impl MfaConfigLoader for MfaEnvLoader {
    fn load(&self) -> Result<RawMfaConfig, ConfigError> {
        Ok(RawMfaConfig {
            enforcement: env_str(ENV_MFA_ENFORCEMENT),
            required_roles: env_str(ENV_MFA_REQUIRED_ROLES).map(|v| split_list(&v)),
            unenrolled: env_str(ENV_MFA_UNENROLLED),
            methods: env_str(ENV_MFA_METHODS).map(|v| split_list(&v)),
            encryption_key: env_str(ENV_MFA_ENCRYPTION_KEY),
            previous_encryption_keys: env_str(ENV_MFA_PREVIOUS_ENCRYPTION_KEYS)
                .map(|v| split_list(&v)),
            hash_key: env_str(ENV_MFA_HASH_KEY),
            totp_issuer: env_str(ENV_MFA_TOTP_ISSUER),
            totp_algorithm: env_str(ENV_MFA_TOTP_ALGORITHM),
            totp_digits: parse_opt(ENV_MFA_TOTP_DIGITS)?,
            totp_period_secs: parse_opt(ENV_MFA_TOTP_PERIOD_SECS)?,
            totp_skew_steps: parse_opt(ENV_MFA_TOTP_SKEW_STEPS)?,
            totp_secret_bytes: parse_opt(ENV_MFA_TOTP_SECRET_BYTES)?,
            enrollment_ttl_secs: parse_opt(ENV_MFA_ENROLLMENT_TTL_SECS)?,
            recovery_code_count: parse_opt(ENV_MFA_RECOVERY_CODE_COUNT)?,
            recovery_code_length: parse_opt(ENV_MFA_RECOVERY_CODE_LENGTH)?,
            challenge_ttl_secs: parse_opt(ENV_MFA_CHALLENGE_TTL_SECS)?,
            challenge_max_attempts: parse_opt(ENV_MFA_CHALLENGE_MAX_ATTEMPTS)?,
            challenge_match: env_str(ENV_MFA_CHALLENGE_MATCH),
            lockout_threshold: parse_opt(ENV_MFA_LOCKOUT_THRESHOLD)?,
            lockout_window_secs: parse_opt(ENV_MFA_LOCKOUT_WINDOW_SECS)?,
            lockout_secs: parse_opt(ENV_MFA_LOCKOUT_SECS)?,
            code_digits: parse_opt(ENV_MFA_CODE_DIGITS)?,
            code_ttl_secs: parse_opt(ENV_MFA_CODE_TTL_SECS)?,
            code_resend_secs: parse_opt(ENV_MFA_CODE_RESEND_SECS)?,
            code_max_sends: parse_opt(ENV_MFA_CODE_MAX_SENDS)?,
            auto_send: parse_opt(ENV_MFA_AUTO_SEND)?,
            end_sessions_on_removal: parse_opt(ENV_MFA_END_SESSIONS_ON_REMOVAL)?,
            purge_interval_secs: parse_opt(ENV_MFA_PURGE_INTERVAL_SECS)?,
            purge_retention_secs: parse_opt(ENV_MFA_PURGE_RETENTION_SECS)?,
        })
    }
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

fn parse_opt<T>(key: &str) -> Result<Option<T>, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env_str(key) {
        None => Ok(None),
        Some(raw) => raw
            .trim()
            .parse::<T>()
            .map(Some)
            .map_err(|e| invalid(key, e)),
    }
}

fn invalid(key: &str, reason: impl std::fmt::Display) -> ConfigError {
    ConfigError::Parse {
        key: key.into(),
        reason: reason.to_string(),
    }
}

fn decode_b64(key: &str, value: &str) -> Result<Vec<u8>, ConfigError> {
    BASE64
        .decode(value.trim())
        .map_err(|e| invalid(key, format!("invalid base64: {e}")))
}

fn encryption_key(key: &str, value: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = decode_b64(key, value)?;
    <[u8; ENCRYPTION_KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| {
        invalid(
            key,
            format!("must be {ENCRYPTION_KEY_LEN} bytes, got {}", bytes.len()),
        )
    })
}

fn secs(v: Option<u64>, default: u64) -> Duration {
    Duration::from_secs(v.unwrap_or(default))
}

fn in_range<T: PartialOrd + std::fmt::Display + Copy>(
    key: &str,
    value: T,
    min: T,
    max: T,
) -> Result<T, ConfigError> {
    if value < min || value > max {
        return Err(invalid(key, format!("must be {min}–{max}, got {value}")));
    }
    Ok(value)
}

fn positive_secs(key: &str, v: Option<u64>, default: u64) -> Result<Duration, ConfigError> {
    let value = v.unwrap_or(default);
    if value == 0 {
        return Err(invalid(key, "must be at least 1"));
    }
    Ok(Duration::from_secs(value))
}

impl std::str::FromStr for Unenrolled {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, ConfigError> {
        match s.trim() {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(invalid(
                ENV_MFA_UNENROLLED,
                format!("expected allow | deny, got '{other}'"),
            )),
        }
    }
}

fn parse_enforcement(value: &str, roles: Option<Vec<String>>) -> Result<Enforcement, ConfigError> {
    match value.trim() {
        "off" => Ok(Enforcement::Off),
        "optional" => Ok(Enforcement::Optional),
        "required" => Ok(Enforcement::Required),
        "roles" => {
            let roles = roles.unwrap_or_default();
            if roles.is_empty() {
                return Err(ConfigError::Missing(format!(
                    "{ENV_MFA_REQUIRED_ROLES} (required by {ENV_MFA_ENFORCEMENT}=roles)"
                )));
            }
            for role in &roles {
                z_auth::utils::validation::validate_code(role)
                    .map_err(|e| invalid(ENV_MFA_REQUIRED_ROLES, e))?;
            }
            Ok(Enforcement::Roles(roles))
        }
        other => Err(invalid(
            ENV_MFA_ENFORCEMENT,
            format!("expected off | optional | required | roles, got '{other}'"),
        )),
    }
}

fn parse_methods(methods: Vec<String>) -> Result<Vec<MfaMethod>, ConfigError> {
    let mut parsed: Vec<MfaMethod> = Vec::new();
    for m in &methods {
        let method: MfaMethod = m.parse().map_err(|e| invalid(ENV_MFA_METHODS, e))?;
        if parsed.contains(&method) {
            return Err(invalid(ENV_MFA_METHODS, format!("'{method}' listed twice")));
        }
        parsed.push(method);
    }
    if parsed.is_empty() {
        return Err(invalid(ENV_MFA_METHODS, "at least one method is required"));
    }
    Ok(parsed)
}

fn parse_client_match(value: &str) -> Result<Option<RetryMatch>, ConfigError> {
    if value.trim() == "none" {
        return Ok(None);
    }
    // Same syntax as AUTH_REFRESH_RETRY_MATCH; report this key on errors.
    value.parse::<RetryMatch>().map(Some).map_err(|e| match e {
        ConfigError::Parse { reason, .. } => invalid(ENV_MFA_CHALLENGE_MATCH, reason),
        other => other,
    })
}

// ── RawMfaConfig impls ────────────────────────────────────────────────────────

impl RawMfaConfig {
    /// `off` | `optional` | `required` | `roles`.
    pub fn enforcement(mut self, v: impl Into<String>) -> Self {
        self.enforcement = Some(v.into());
        self
    }
    /// Role codes that require a second factor (enforcement `roles`).
    pub fn required_roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_roles = Some(roles.into_iter().map(Into::into).collect());
        self
    }
    /// `allow` | `deny`.
    pub fn unenrolled(mut self, v: impl Into<String>) -> Self {
        self.unenrolled = Some(v.into());
        self
    }
    /// Ordered subset of `totp`, `email`, `sms`.
    pub fn methods<I, S>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.methods = Some(methods.into_iter().map(Into::into).collect());
        self
    }
    /// Base64, 32 bytes.
    pub fn encryption_key(mut self, v: impl Into<String>) -> Self {
        self.encryption_key = Some(v.into());
        self
    }
    /// Base64 keys still accepted for opening sealed values.
    pub fn previous_encryption_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.previous_encryption_keys = Some(keys.into_iter().map(Into::into).collect());
        self
    }
    /// Base64, ≥ 32 bytes.
    pub fn hash_key(mut self, v: impl Into<String>) -> Self {
        self.hash_key = Some(v.into());
        self
    }
    pub fn totp_issuer(mut self, v: impl Into<String>) -> Self {
        self.totp_issuer = Some(v.into());
        self
    }
    /// `sha1` | `sha256` | `sha512`.
    pub fn totp_algorithm(mut self, v: impl Into<String>) -> Self {
        self.totp_algorithm = Some(v.into());
        self
    }
    pub fn totp_digits(mut self, v: u32) -> Self {
        self.totp_digits = Some(v);
        self
    }
    pub fn totp_period_secs(mut self, v: u64) -> Self {
        self.totp_period_secs = Some(v);
        self
    }
    pub fn totp_skew_steps(mut self, v: u32) -> Self {
        self.totp_skew_steps = Some(v);
        self
    }
    pub fn totp_secret_bytes(mut self, v: usize) -> Self {
        self.totp_secret_bytes = Some(v);
        self
    }
    pub fn enrollment_ttl_secs(mut self, v: u64) -> Self {
        self.enrollment_ttl_secs = Some(v);
        self
    }
    /// 0 disables recovery codes.
    pub fn recovery_code_count(mut self, v: u32) -> Self {
        self.recovery_code_count = Some(v);
        self
    }
    pub fn recovery_code_length(mut self, v: usize) -> Self {
        self.recovery_code_length = Some(v);
        self
    }
    pub fn challenge_ttl_secs(mut self, v: u64) -> Self {
        self.challenge_ttl_secs = Some(v);
        self
    }
    pub fn challenge_max_attempts(mut self, v: u32) -> Self {
        self.challenge_max_attempts = Some(v);
        self
    }
    /// `none` or a comma set of `ip`, `user_agent`, `fingerprint`.
    pub fn challenge_match(mut self, v: impl Into<String>) -> Self {
        self.challenge_match = Some(v.into());
        self
    }
    /// 0 never locks.
    pub fn lockout_threshold(mut self, v: u32) -> Self {
        self.lockout_threshold = Some(v);
        self
    }
    pub fn lockout_window_secs(mut self, v: u64) -> Self {
        self.lockout_window_secs = Some(v);
        self
    }
    pub fn lockout_secs(mut self, v: u64) -> Self {
        self.lockout_secs = Some(v);
        self
    }
    pub fn code_digits(mut self, v: u32) -> Self {
        self.code_digits = Some(v);
        self
    }
    pub fn code_ttl_secs(mut self, v: u64) -> Self {
        self.code_ttl_secs = Some(v);
        self
    }
    pub fn code_resend_secs(mut self, v: u64) -> Self {
        self.code_resend_secs = Some(v);
        self
    }
    pub fn code_max_sends(mut self, v: u32) -> Self {
        self.code_max_sends = Some(v);
        self
    }
    pub fn auto_send(mut self, v: bool) -> Self {
        self.auto_send = Some(v);
        self
    }
    pub fn end_sessions_on_removal(mut self, v: bool) -> Self {
        self.end_sessions_on_removal = Some(v);
        self
    }
    pub fn purge_interval_secs(mut self, v: u64) -> Self {
        self.purge_interval_secs = Some(v);
        self
    }
    pub fn purge_retention_secs(mut self, v: u64) -> Self {
        self.purge_retention_secs = Some(v);
        self
    }

    /// Validate and convert into [`MfaSettings`].
    ///
    /// # Errors
    /// [`ConfigError::Missing`] without a hash key, or with enforcement
    /// `roles` but no roles; [`ConfigError::Parse`] for a value that does
    /// not parse or is out of range.
    pub fn build(self) -> Result<MfaSettings, ConfigError> {
        let hash_key = match self.hash_key.as_deref() {
            Some(v) => decode_b64(ENV_MFA_HASH_KEY, v)?,
            None => return Err(ConfigError::Missing(ENV_MFA_HASH_KEY.into())),
        };
        if hash_key.len() < MIN_HASH_KEY_LEN {
            return Err(invalid(
                ENV_MFA_HASH_KEY,
                format!(
                    "must be at least {MIN_HASH_KEY_LEN} bytes, got {}",
                    hash_key.len()
                ),
            ));
        }
        let keys = MfaKeys {
            encryption_key: self
                .encryption_key
                .as_deref()
                .map(|v| encryption_key(ENV_MFA_ENCRYPTION_KEY, v))
                .transpose()?,
            previous_encryption_keys: self
                .previous_encryption_keys
                .unwrap_or_default()
                .iter()
                .map(|v| encryption_key(ENV_MFA_PREVIOUS_ENCRYPTION_KEYS, v))
                .collect::<Result<_, _>>()?,
            hash_key,
        };

        let enforcement = parse_enforcement(
            self.enforcement.as_deref().unwrap_or(DEFAULT_ENFORCEMENT),
            self.required_roles,
        )?;
        let unenrolled = self
            .unenrolled
            .as_deref()
            .unwrap_or(DEFAULT_UNENROLLED)
            .parse()?;
        let methods = parse_methods(self.methods.unwrap_or_else(|| split_list(DEFAULT_METHODS)))?;

        let totp = TotpConfig {
            issuer: self.totp_issuer.filter(|s| !s.trim().is_empty()),
            algorithm: self
                .totp_algorithm
                .as_deref()
                .unwrap_or(DEFAULT_TOTP_ALGORITHM)
                .parse::<TotpAlgorithm>()
                .map_err(|e| invalid(ENV_MFA_TOTP_ALGORITHM, e))?,
            digits: in_range(
                ENV_MFA_TOTP_DIGITS,
                self.totp_digits.unwrap_or(DEFAULT_TOTP_DIGITS),
                MIN_TOTP_DIGITS,
                MAX_TOTP_DIGITS,
            )?,
            period: positive_secs(
                ENV_MFA_TOTP_PERIOD_SECS,
                self.totp_period_secs,
                DEFAULT_TOTP_PERIOD_SECS,
            )?,
            skew_steps: in_range(
                ENV_MFA_TOTP_SKEW_STEPS,
                self.totp_skew_steps.unwrap_or(DEFAULT_TOTP_SKEW_STEPS),
                0,
                MAX_TOTP_SKEW_STEPS,
            )?,
            secret_bytes: in_range(
                ENV_MFA_TOTP_SECRET_BYTES,
                self.totp_secret_bytes.unwrap_or(DEFAULT_TOTP_SECRET_BYTES),
                MIN_TOTP_SECRET_BYTES,
                MAX_TOTP_SECRET_BYTES,
            )?,
        };

        let recovery = RecoveryConfig {
            count: in_range(
                ENV_MFA_RECOVERY_CODE_COUNT,
                self.recovery_code_count
                    .unwrap_or(DEFAULT_RECOVERY_CODE_COUNT),
                0,
                MAX_RECOVERY_CODE_COUNT,
            )?,
            length: in_range(
                ENV_MFA_RECOVERY_CODE_LENGTH,
                self.recovery_code_length
                    .unwrap_or(DEFAULT_RECOVERY_CODE_LENGTH),
                MIN_RECOVERY_CODE_LENGTH,
                MAX_RECOVERY_CODE_LENGTH,
            )?,
        };

        let challenge = ChallengeConfig {
            ttl: positive_secs(
                ENV_MFA_CHALLENGE_TTL_SECS,
                self.challenge_ttl_secs,
                DEFAULT_CHALLENGE_TTL_SECS,
            )?,
            max_attempts: in_range(
                ENV_MFA_CHALLENGE_MAX_ATTEMPTS,
                self.challenge_max_attempts
                    .unwrap_or(DEFAULT_CHALLENGE_MAX_ATTEMPTS),
                1,
                u32::MAX,
            )?,
            client_match: parse_client_match(
                self.challenge_match
                    .as_deref()
                    .unwrap_or(DEFAULT_CHALLENGE_MATCH),
            )?,
        };

        let lockout = LockoutConfig {
            threshold: self.lockout_threshold.unwrap_or(DEFAULT_LOCKOUT_THRESHOLD),
            window: positive_secs(
                ENV_MFA_LOCKOUT_WINDOW_SECS,
                self.lockout_window_secs,
                DEFAULT_LOCKOUT_WINDOW_SECS,
            )?,
            duration: positive_secs(
                ENV_MFA_LOCKOUT_SECS,
                self.lockout_secs,
                DEFAULT_LOCKOUT_SECS,
            )?,
        };

        let codes = CodeConfig {
            digits: in_range(
                ENV_MFA_CODE_DIGITS,
                self.code_digits.unwrap_or(DEFAULT_CODE_DIGITS),
                MIN_CODE_DIGITS,
                MAX_CODE_DIGITS,
            )?,
            ttl: positive_secs(
                ENV_MFA_CODE_TTL_SECS,
                self.code_ttl_secs,
                DEFAULT_CODE_TTL_SECS,
            )?,
            resend_after: secs(self.code_resend_secs, DEFAULT_CODE_RESEND_SECS),
            max_sends: in_range(
                ENV_MFA_CODE_MAX_SENDS,
                self.code_max_sends.unwrap_or(DEFAULT_CODE_MAX_SENDS),
                1,
                u32::MAX,
            )?,
            auto_send: self.auto_send.unwrap_or(DEFAULT_AUTO_SEND),
        };

        Ok(MfaSettings {
            enforcement,
            unenrolled,
            methods,
            keys,
            totp,
            enrollment_ttl: positive_secs(
                ENV_MFA_ENROLLMENT_TTL_SECS,
                self.enrollment_ttl_secs,
                DEFAULT_ENROLLMENT_TTL_SECS,
            )?,
            recovery,
            challenge,
            lockout,
            codes,
            end_sessions_on_removal: self
                .end_sessions_on_removal
                .unwrap_or(DEFAULT_END_SESSIONS_ON_REMOVAL),
            purge_interval: positive_secs(
                ENV_MFA_PURGE_INTERVAL_SECS,
                self.purge_interval_secs,
                DEFAULT_PURGE_INTERVAL_SECS,
            )?,
            purge_retention: secs(self.purge_retention_secs, DEFAULT_PURGE_RETENTION_SECS),
        })
    }
}
