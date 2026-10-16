//! z-auth-mfa constants: defaults, limits and the `AUTH_MFA_*` environment
//! variables read by [`MfaEnvLoader`](crate::config::MfaEnvLoader), and their
//! paths in the `mfa` section of the configuration file.

use z_auth::conf::config::Key;

// ── Policy ────────────────────────────────────────────────────────────────────

/// `off` | `optional` | `required` | `roles`.
pub const DEFAULT_ENFORCEMENT: &str = "optional";
/// `allow` | `deny`: what a required-but-unenrolled user gets at login.
pub const DEFAULT_UNENROLLED: &str = "allow";
/// Enabled methods, preferred first.
pub const DEFAULT_METHODS: &str = "totp";

// ── Keys ──────────────────────────────────────────────────────────────────────

/// XChaCha20-Poly1305 key length (sealing TOTP secrets and destinations).
pub const ENCRYPTION_KEY_LEN: usize = 32;
/// Minimum length of the HMAC key for codes and challenge tokens.
pub const MIN_HASH_KEY_LEN: usize = 32;
/// SHA-256 bytes of an encryption key used as its id in sealed values.
pub const SEALED_KEY_ID_LEN: usize = 8;
/// Version byte of the sealed-value format.
pub const SEALED_FORMAT_VERSION: u8 = 1;

// ── TOTP ──────────────────────────────────────────────────────────────────────

/// `sha1` is what most authenticator apps support.
pub const DEFAULT_TOTP_ALGORITHM: &str = "sha1";
pub const DEFAULT_TOTP_DIGITS: u32 = 6;
pub const MIN_TOTP_DIGITS: u32 = 6;
pub const MAX_TOTP_DIGITS: u32 = 8;
pub const DEFAULT_TOTP_PERIOD_SECS: u64 = 30;
/// Steps accepted on either side of the current one (clock drift).
pub const DEFAULT_TOTP_SKEW_STEPS: u32 = 1;
pub const MAX_TOTP_SKEW_STEPS: u32 = 5;
/// 160 bits, as RFC 4226 recommends.
pub const DEFAULT_TOTP_SECRET_BYTES: usize = 20;
pub const MIN_TOTP_SECRET_BYTES: usize = 16;
pub const MAX_TOTP_SECRET_BYTES: usize = 64;
/// How long an unconfirmed enrollment stays valid.
pub const DEFAULT_ENROLLMENT_TTL_SECS: u64 = 600;
/// Longest factor label, in characters.
pub const MAX_FACTOR_LABEL_LEN: usize = 64;

// ── Recovery codes ────────────────────────────────────────────────────────────

/// Codes issued with the first factor (0 = no recovery codes).
pub const DEFAULT_RECOVERY_CODE_COUNT: u32 = 10;
pub const MAX_RECOVERY_CODE_COUNT: u32 = 32;
/// Crockford base32 characters per code (50 bits at the default).
pub const DEFAULT_RECOVERY_CODE_LENGTH: usize = 10;
pub const MIN_RECOVERY_CODE_LENGTH: usize = 8;
pub const MAX_RECOVERY_CODE_LENGTH: usize = 32;

// ── Login challenges ──────────────────────────────────────────────────────────

pub const DEFAULT_CHALLENGE_TTL_SECS: u64 = 300;
/// Codes accepted per challenge before it dies.
pub const DEFAULT_CHALLENGE_MAX_ATTEMPTS: u32 = 5;
/// `none`, or a comma set of `ip`, `user_agent`, `fingerprint` that must
/// match between the password step and the second step.
pub const DEFAULT_CHALLENGE_MATCH: &str = "none";
/// Random bytes in a challenge token.
pub const CHALLENGE_SECRET_LEN: usize = 32;
/// Prefix of the challenge-token format `mfa1.<id>.<secret>`.
pub const CHALLENGE_TOKEN_VERSION: &str = "mfa1";

// ── Lockout ───────────────────────────────────────────────────────────────────

/// Failed second-factor attempts per user per window before a lockout
/// (0 = never lock).
pub const DEFAULT_LOCKOUT_THRESHOLD: u32 = 10;
pub const DEFAULT_LOCKOUT_WINDOW_SECS: u64 = 900;
pub const DEFAULT_LOCKOUT_SECS: u64 = 900;

// ── Email / SMS codes ─────────────────────────────────────────────────────────

pub const DEFAULT_CODE_DIGITS: u32 = 6;
pub const MIN_CODE_DIGITS: u32 = 6;
pub const MAX_CODE_DIGITS: u32 = 10;
pub const DEFAULT_CODE_TTL_SECS: u64 = 300;
/// Minimum gap between two sends of a code.
pub const DEFAULT_CODE_RESEND_SECS: u64 = 30;
/// Sends per challenge (or per enrollment) while its code is valid.
pub const DEFAULT_CODE_MAX_SENDS: u32 = 5;
/// Send a code right away at login when the user has no TOTP factor.
pub const DEFAULT_AUTO_SEND: bool = true;
/// Longest destination accepted (email address or phone number).
pub const MAX_DESTINATION_LEN: usize = 254;

// ── Housekeeping ──────────────────────────────────────────────────────────────

/// End the user's sessions when a factor is removed or all are reset.
pub const DEFAULT_END_SESSIONS_ON_REMOVAL: bool = true;
/// How often `ZAuth::tick` purges expired challenges and enrollments.
pub const DEFAULT_PURGE_INTERVAL_SECS: u64 = 300;
/// Expired rows are kept this long before the purge removes them.
pub const DEFAULT_PURGE_RETENTION_SECS: u64 = 86_400;

// ── Wire values ───────────────────────────────────────────────────────────────

/// Proof method name of a recovery code (the factors are `totp`, `email`
/// and `sms`).
pub const METHOD_RECOVERY_CODE: &str = "recovery_code";

// ── Environment variables (read by `config::MfaEnvLoader`) ───────────────────

pub const ENV_MFA_ENFORCEMENT: &str = "AUTH_MFA_ENFORCEMENT";
pub const ENV_MFA_REQUIRED_ROLES: &str = "AUTH_MFA_REQUIRED_ROLES";
pub const ENV_MFA_UNENROLLED: &str = "AUTH_MFA_UNENROLLED";
pub const ENV_MFA_METHODS: &str = "AUTH_MFA_METHODS";
/// Base64, 32 bytes.
pub const ENV_MFA_ENCRYPTION_KEY: &str = "AUTH_MFA_ENCRYPTION_KEY";
/// Comma-separated base64 keys still accepted for decryption.
pub const ENV_MFA_PREVIOUS_ENCRYPTION_KEYS: &str = "AUTH_MFA_PREVIOUS_ENCRYPTION_KEYS";
/// Base64, ≥ 32 bytes.
pub const ENV_MFA_HASH_KEY: &str = "AUTH_MFA_HASH_KEY";
pub const ENV_MFA_TOTP_ISSUER: &str = "AUTH_MFA_TOTP_ISSUER";
pub const ENV_MFA_TOTP_ALGORITHM: &str = "AUTH_MFA_TOTP_ALGORITHM";
pub const ENV_MFA_TOTP_DIGITS: &str = "AUTH_MFA_TOTP_DIGITS";
pub const ENV_MFA_TOTP_PERIOD_SECS: &str = "AUTH_MFA_TOTP_PERIOD_SECS";
pub const ENV_MFA_TOTP_SKEW_STEPS: &str = "AUTH_MFA_TOTP_SKEW_STEPS";
pub const ENV_MFA_TOTP_SECRET_BYTES: &str = "AUTH_MFA_TOTP_SECRET_BYTES";
pub const ENV_MFA_ENROLLMENT_TTL_SECS: &str = "AUTH_MFA_ENROLLMENT_TTL_SECS";
pub const ENV_MFA_RECOVERY_CODE_COUNT: &str = "AUTH_MFA_RECOVERY_CODE_COUNT";
pub const ENV_MFA_RECOVERY_CODE_LENGTH: &str = "AUTH_MFA_RECOVERY_CODE_LENGTH";
pub const ENV_MFA_CHALLENGE_TTL_SECS: &str = "AUTH_MFA_CHALLENGE_TTL_SECS";
pub const ENV_MFA_CHALLENGE_MAX_ATTEMPTS: &str = "AUTH_MFA_CHALLENGE_MAX_ATTEMPTS";
pub const ENV_MFA_CHALLENGE_MATCH: &str = "AUTH_MFA_CHALLENGE_MATCH";
pub const ENV_MFA_LOCKOUT_THRESHOLD: &str = "AUTH_MFA_LOCKOUT_THRESHOLD";
pub const ENV_MFA_LOCKOUT_WINDOW_SECS: &str = "AUTH_MFA_LOCKOUT_WINDOW_SECS";
pub const ENV_MFA_LOCKOUT_SECS: &str = "AUTH_MFA_LOCKOUT_SECS";
pub const ENV_MFA_CODE_DIGITS: &str = "AUTH_MFA_CODE_DIGITS";
pub const ENV_MFA_CODE_TTL_SECS: &str = "AUTH_MFA_CODE_TTL_SECS";
pub const ENV_MFA_CODE_RESEND_SECS: &str = "AUTH_MFA_CODE_RESEND_SECS";
pub const ENV_MFA_CODE_MAX_SENDS: &str = "AUTH_MFA_CODE_MAX_SENDS";
pub const ENV_MFA_AUTO_SEND: &str = "AUTH_MFA_AUTO_SEND";
pub const ENV_MFA_END_SESSIONS_ON_REMOVAL: &str = "AUTH_MFA_END_SESSIONS_ON_REMOVAL";
pub const ENV_MFA_PURGE_INTERVAL_SECS: &str = "AUTH_MFA_PURGE_INTERVAL_SECS";
pub const ENV_MFA_PURGE_RETENTION_SECS: &str = "AUTH_MFA_PURGE_RETENTION_SECS";

// ── Configuration file (read by `config::MfaSourceLoader`) ───────────────────

/// z-auth-mfa's top-level section in the configuration file.
pub const SECTION: &str = "mfa";

/// Sub-sections of [`SECTION`] that belong to other crates and are not
/// checked here: `mfa.delivery` is read by z-auth-mfa-sender.
pub const FOREIGN_SECTIONS: &[&str] = &["mfa.delivery"];

/// Every z-auth-mfa setting: its environment variable and its path in the
/// file.
pub const KEYS: &[Key] = &[
    Key::new(ENV_MFA_ENFORCEMENT, "mfa.enforcement"),
    Key::new(ENV_MFA_REQUIRED_ROLES, "mfa.required_roles"),
    Key::new(ENV_MFA_UNENROLLED, "mfa.unenrolled"),
    Key::new(ENV_MFA_METHODS, "mfa.methods"),
    Key::new(ENV_MFA_ENCRYPTION_KEY, "mfa.encryption_key"),
    Key::new(
        ENV_MFA_PREVIOUS_ENCRYPTION_KEYS,
        "mfa.previous_encryption_keys",
    ),
    Key::new(ENV_MFA_HASH_KEY, "mfa.hash_key"),
    Key::new(ENV_MFA_TOTP_ISSUER, "mfa.totp.issuer"),
    Key::new(ENV_MFA_TOTP_ALGORITHM, "mfa.totp.algorithm"),
    Key::new(ENV_MFA_TOTP_DIGITS, "mfa.totp.digits"),
    Key::new(ENV_MFA_TOTP_PERIOD_SECS, "mfa.totp.period_secs"),
    Key::new(ENV_MFA_TOTP_SKEW_STEPS, "mfa.totp.skew_steps"),
    Key::new(ENV_MFA_TOTP_SECRET_BYTES, "mfa.totp.secret_bytes"),
    Key::new(ENV_MFA_ENROLLMENT_TTL_SECS, "mfa.enrollment_ttl_secs"),
    Key::new(ENV_MFA_RECOVERY_CODE_COUNT, "mfa.recovery.code_count"),
    Key::new(ENV_MFA_RECOVERY_CODE_LENGTH, "mfa.recovery.code_length"),
    Key::new(ENV_MFA_CHALLENGE_TTL_SECS, "mfa.challenge.ttl_secs"),
    Key::new(ENV_MFA_CHALLENGE_MAX_ATTEMPTS, "mfa.challenge.max_attempts"),
    Key::new(ENV_MFA_CHALLENGE_MATCH, "mfa.challenge.match"),
    Key::new(ENV_MFA_LOCKOUT_THRESHOLD, "mfa.lockout.threshold"),
    Key::new(ENV_MFA_LOCKOUT_WINDOW_SECS, "mfa.lockout.window_secs"),
    Key::new(ENV_MFA_LOCKOUT_SECS, "mfa.lockout.duration_secs"),
    Key::new(ENV_MFA_CODE_DIGITS, "mfa.code.digits"),
    Key::new(ENV_MFA_CODE_TTL_SECS, "mfa.code.ttl_secs"),
    Key::new(ENV_MFA_CODE_RESEND_SECS, "mfa.code.resend_secs"),
    Key::new(ENV_MFA_CODE_MAX_SENDS, "mfa.code.max_sends"),
    Key::new(ENV_MFA_AUTO_SEND, "mfa.code.auto_send"),
    Key::new(
        ENV_MFA_END_SESSIONS_ON_REMOVAL,
        "mfa.end_sessions_on_removal",
    ),
    Key::new(ENV_MFA_PURGE_INTERVAL_SECS, "mfa.purge.interval_secs"),
    Key::new(ENV_MFA_PURGE_RETENTION_SECS, "mfa.purge.retention_secs"),
];
