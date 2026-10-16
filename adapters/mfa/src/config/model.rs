//! z-auth-mfa configuration data models: what [`MfaEnvLoader`] reads from
//! `AUTH_MFA_*`.
//!
//! [`MfaEnvLoader`]: crate::config::MfaEnvLoader

use std::time::Duration;

use z_auth::conf::config::RetryMatch;

use crate::model::{MfaMethod, TotpAlgorithm};

/// Everything z-auth-mfa needs beyond z-auth's own `AuthConfig`.
#[derive(Debug, Clone)]
pub struct MfaSettings {
    /// Who must use a second factor.
    pub enforcement: Enforcement,
    /// What a user who must use a second factor but has none gets.
    pub unenrolled: Unenrolled,
    /// Enabled methods, preferred first.  Never empty.
    pub methods: Vec<MfaMethod>,
    pub keys: MfaKeys,
    pub totp: TotpConfig,
    /// How long an unconfirmed enrollment stays valid.
    pub enrollment_ttl: Duration,
    pub recovery: RecoveryConfig,
    pub challenge: ChallengeConfig,
    pub lockout: LockoutConfig,
    pub codes: CodeConfig,
    /// End the user's sessions when a factor is removed or all are reset.
    pub end_sessions_on_removal: bool,
    /// How often `ZAuth::tick` purges expired rows.
    pub purge_interval: Duration,
    /// How long expired rows are kept.
    pub purge_retention: Duration,
}

/// Who must use a second factor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// Second factors are ignored: logins never get a challenge.
    Off,
    /// Users who enrolled a factor are challenged; others are not.
    Optional,
    /// Every user must use one.
    Required,
    /// Users with any of these role codes must use one; others are
    /// challenged if they enrolled.
    Roles(Vec<String>),
}

/// What a login gets when a second factor is required but none is enrolled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unenrolled {
    /// Password-only tokens (`amr` without `mfa`): the host lets them enroll
    /// and guards everything else with `Authorizer::require_mfa`.
    Allow,
    /// Refuse the login (`AuthError::SecondFactorNotEnrolled`).
    Deny,
}

/// Keys for sealing secrets and hashing codes.
#[derive(Clone)]
pub struct MfaKeys {
    /// Seals TOTP secrets and destinations.  Optional when the host
    /// supplies its own `SecretSealer`.
    pub encryption_key: Option<[u8; 32]>,
    /// Earlier encryption keys, still accepted for opening.
    pub previous_encryption_keys: Vec<[u8; 32]>,
    /// HMAC key for recovery codes, one-time codes and challenge tokens.
    pub hash_key: Vec<u8>,
}

/// TOTP parameters for new enrollments.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// Shown in authenticator apps.  `None` = z-auth's JWT issuer.
    pub issuer: Option<String>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: Duration,
    /// Steps accepted on either side of the current one.
    pub skew_steps: u32,
    pub secret_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryConfig {
    /// Codes issued with the first factor; 0 disables recovery codes.
    pub count: u32,
    /// Characters per code.
    pub length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeConfig {
    pub ttl: Duration,
    /// Second-step attempts per challenge.
    pub max_attempts: u32,
    /// Request attributes that must match between the two steps; `None`
    /// compares nothing.
    pub client_match: Option<RetryMatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutConfig {
    /// Failures per window that lock the user; 0 = never.
    pub threshold: u32,
    pub window: Duration,
    pub duration: Duration,
}

/// Email / SMS one-time codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeConfig {
    pub digits: u32,
    pub ttl: Duration,
    /// Minimum gap between two sends.
    pub resend_after: Duration,
    /// Sends while a code is valid.
    pub max_sends: u32,
    /// At login, send a code right away when the user has no TOTP factor.
    pub auto_send: bool,
}

/// A flat, fully optional snapshot of every z-auth-mfa knob.  Fields left
/// as `None` fall back to the defaults in [`crate::constants`].  Keys are
/// base64 strings (standard alphabet).
#[derive(Clone, Default)]
pub struct RawMfaConfig {
    /// `off` | `optional` | `required` | `roles`.
    pub enforcement: Option<String>,
    /// Role codes (enforcement `roles`).
    pub required_roles: Option<Vec<String>>,
    /// `allow` | `deny`.
    pub unenrolled: Option<String>,
    /// Ordered subset of `totp`, `email`, `sms`.
    pub methods: Option<Vec<String>>,
    pub encryption_key: Option<String>,
    pub previous_encryption_keys: Option<Vec<String>>,
    pub hash_key: Option<String>,
    pub totp_issuer: Option<String>,
    /// `sha1` | `sha256` | `sha512`.
    pub totp_algorithm: Option<String>,
    pub totp_digits: Option<u32>,
    pub totp_period_secs: Option<u64>,
    pub totp_skew_steps: Option<u32>,
    pub totp_secret_bytes: Option<usize>,
    pub enrollment_ttl_secs: Option<u64>,
    pub recovery_code_count: Option<u32>,
    pub recovery_code_length: Option<usize>,
    pub challenge_ttl_secs: Option<u64>,
    pub challenge_max_attempts: Option<u32>,
    /// `none` or a comma set of `ip`, `user_agent`, `fingerprint`.
    pub challenge_match: Option<String>,
    pub lockout_threshold: Option<u32>,
    pub lockout_window_secs: Option<u64>,
    pub lockout_secs: Option<u64>,
    pub code_digits: Option<u32>,
    pub code_ttl_secs: Option<u64>,
    pub code_resend_secs: Option<u64>,
    pub code_max_sends: Option<u32>,
    pub auto_send: Option<bool>,
    pub end_sessions_on_removal: Option<bool>,
    pub purge_interval_secs: Option<u64>,
    pub purge_retention_secs: Option<u64>,
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for MfaKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaKeys")
            .field(
                "encryption_key",
                &self.encryption_key.as_ref().map(|_| REDACTED),
            )
            .field(
                "previous_encryption_keys",
                &format!("<{} redacted>", self.previous_encryption_keys.len()),
            )
            .field("hash_key", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for RawMfaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secret = |v: &Option<String>| v.as_ref().map(|_| REDACTED);
        f.debug_struct("RawMfaConfig")
            .field("enforcement", &self.enforcement)
            .field("required_roles", &self.required_roles)
            .field("unenrolled", &self.unenrolled)
            .field("methods", &self.methods)
            .field("encryption_key", &secret(&self.encryption_key))
            .field(
                "previous_encryption_keys",
                &self
                    .previous_encryption_keys
                    .as_ref()
                    .map(|k| format!("<{} redacted>", k.len())),
            )
            .field("hash_key", &secret(&self.hash_key))
            .field("totp_issuer", &self.totp_issuer)
            .field("totp_algorithm", &self.totp_algorithm)
            .field("totp_digits", &self.totp_digits)
            .field("totp_period_secs", &self.totp_period_secs)
            .field("totp_skew_steps", &self.totp_skew_steps)
            .field("totp_secret_bytes", &self.totp_secret_bytes)
            .field("enrollment_ttl_secs", &self.enrollment_ttl_secs)
            .field("recovery_code_count", &self.recovery_code_count)
            .field("recovery_code_length", &self.recovery_code_length)
            .field("challenge_ttl_secs", &self.challenge_ttl_secs)
            .field("challenge_max_attempts", &self.challenge_max_attempts)
            .field("challenge_match", &self.challenge_match)
            .field("lockout_threshold", &self.lockout_threshold)
            .field("lockout_window_secs", &self.lockout_window_secs)
            .field("lockout_secs", &self.lockout_secs)
            .field("code_digits", &self.code_digits)
            .field("code_ttl_secs", &self.code_ttl_secs)
            .field("code_resend_secs", &self.code_resend_secs)
            .field("code_max_sends", &self.code_max_sends)
            .field("auto_send", &self.auto_send)
            .field("end_sessions_on_removal", &self.end_sessions_on_removal)
            .field("purge_interval_secs", &self.purge_interval_secs)
            .field("purge_retention_secs", &self.purge_retention_secs)
            .finish()
    }
}
