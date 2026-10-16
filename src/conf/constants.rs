//! Library-wide constants.
//!
//! Every default, limit and environment-variable name used by z-auth lives
//! here — no other module should hard-code these values.

use crate::conf::config::source::Key;

// ── Access tokens (JWT) ───────────────────────────────────────────────────────

/// Default access-token lifetime: 5 minutes.
pub const DEFAULT_ACCESS_TOKEN_TTL_SECS: u64 = 300;

/// Default clock-skew tolerance when checking `exp`.
pub const DEFAULT_JWT_LEEWAY_SECS: u64 = 30;

/// Default `iss` claim.
pub const DEFAULT_JWT_ISSUER: &str = "z-auth";

/// Ed25519 key length (both the signing seed and the verifying key).
pub const ED25519_KEY_LEN: usize = 32;

/// Number of SHA-256 bytes of the verifying key used as the JWT `kid`.
pub const JWT_KID_LEN: usize = 8;

/// The only JWT `alg` accepted or produced.
pub const JWT_ALG: &str = "EdDSA";

/// JWT `typ` header value.
pub const JWT_TYP: &str = "JWT";

// ── Sessions & refresh tokens ─────────────────────────────────────────────────

/// Maximum number of concurrent active sessions per user.
pub const DEFAULT_MAX_SESSIONS_PER_USER: u32 = 5;

/// Session idle timeout: 30 minutes without a refresh ends the session.
pub const DEFAULT_SESSION_IDLE_TIMEOUT_SECS: u64 = 1_800;

/// Session absolute lifetime: 8 hours, regardless of activity.
pub const DEFAULT_SESSION_ABSOLUTE_TIMEOUT_SECS: u64 = 28_800;

/// Number of token generations kept per session for reuse detection.
pub const DEFAULT_SESSION_HISTORY_SIZE: u32 = 10;

/// Window after a rotation in which the previous generation may still be
/// presented (concurrent refresh) and receives the current pair.
pub const DEFAULT_REFRESH_GRACE_SECS: u64 = 30;

/// Reject refreshes from an IP other than the session's creating IP.
pub const DEFAULT_IP_BINDING: bool = false;

/// Longest client `User-Agent` stored with a session, in bytes; longer
/// values are truncated.
pub const MAX_USER_AGENT_LEN: usize = 512;

/// Length of the random per-session secret mixed into refresh-token MACs.
pub const SESSION_SECRET_LEN: usize = 32;

/// Minimum length of the server-wide refresh-token HMAC key.
pub const MIN_REFRESH_SECRET_LEN: usize = 32;

/// Version prefix of the refresh-token format `v1.<sid>.<gen>.<mac>`.
pub const REFRESH_TOKEN_VERSION: &str = "v1";

/// How many times a refresh re-evaluates after losing a rotation race.
pub const REFRESH_ROTATE_ATTEMPTS: u32 = 3;

// ── Authentication methods (RFC 8176 `amr` values) ───────────────────────────

/// Password.
pub const AMR_PWD: &str = "pwd";
/// One-time password: TOTP, an emailed code or a recovery code.
pub const AMR_OTP: &str = "otp";
/// A code sent by SMS.
pub const AMR_SMS: &str = "sms";
/// More than one factor was used.
pub const AMR_MFA: &str = "mfa";
/// Signed in through an external identity provider (not an RFC 8176
/// value).
pub const AMR_FED: &str = "fed";

// ── External identities ──────────────────────────────────────────────────────

/// Linking an identity needs a login at most 10 minutes old.
pub const DEFAULT_EXTERNAL_LINK_MAX_AUTH_AGE_SECS: u64 = 600;

/// A sign-in waiting for the local password stays open 5 minutes.
pub const DEFAULT_EXTERNAL_LINK_CHALLENGE_TTL_SECS: u64 = 300;

/// Length of the random secret in a link-confirmation token.
pub const LINK_CHALLENGE_SECRET_LEN: usize = 32;

// ── Password policy ───────────────────────────────────────────────────────────

/// Minimum number of characters in a password.
pub const DEFAULT_PASSWORD_MIN_LENGTH: usize = 8;

/// Require at least one uppercase letter.
pub const DEFAULT_PASSWORD_REQUIRE_UPPERCASE: bool = true;

/// Require at least one ASCII digit.
pub const DEFAULT_PASSWORD_REQUIRE_DIGIT: bool = true;

// ── Authorization ─────────────────────────────────────────────────────────────

/// Default authorization model: `none` | `rbac` | `permissions` | `combined`.
pub const DEFAULT_AUTHZ_MODE: &str = "rbac";

/// Default cap on a `text` permission's value, in characters.
pub const DEFAULT_TEXT_PERMISSION_MAX_LEN: u32 = 64;

/// Longest role or permission code.  Codes match `^[a-z][a-z0-9_.:-]*$`.
pub const MAX_CODE_LEN: usize = 64;

// ── Environment variables (read by `config::EnvLoader`) ──────────────────────

/// Base64 Ed25519 signing seed (auth service only).
pub const ENV_JWT_SIGNING_KEY: &str = "AUTH_JWT_SIGNING_KEY";
/// Comma-separated base64 Ed25519 verifying keys (every verifying service).
pub const ENV_JWT_VERIFYING_KEYS: &str = "AUTH_JWT_VERIFYING_KEYS";
pub const ENV_JWT_ACCESS_TTL_SECS: &str = "AUTH_JWT_ACCESS_TTL_SECS";
pub const ENV_JWT_LEEWAY_SECS: &str = "AUTH_JWT_LEEWAY_SECS";
pub const ENV_JWT_ISSUER: &str = "AUTH_JWT_ISSUER";
/// Base64 refresh-token HMAC key (auth service only).
pub const ENV_REFRESH_SECRET: &str = "AUTH_REFRESH_SECRET";
pub const ENV_SESSION_IDLE_TIMEOUT_SECS: &str = "AUTH_SESSION_IDLE_TIMEOUT_SECS";
pub const ENV_SESSION_ABSOLUTE_TIMEOUT_SECS: &str = "AUTH_SESSION_ABSOLUTE_TIMEOUT_SECS";
pub const ENV_SESSION_HISTORY_SIZE: &str = "AUTH_SESSION_HISTORY_SIZE";
pub const ENV_REFRESH_GRACE_SECS: &str = "AUTH_REFRESH_GRACE_SECS";
pub const ENV_IP_BINDING: &str = "AUTH_IP_BINDING";
pub const ENV_MAX_SESSIONS_PER_USER: &str = "AUTH_MAX_SESSIONS_PER_USER";
pub const ENV_PASSWORD_MIN_LENGTH: &str = "AUTH_PASSWORD_MIN_LENGTH";
pub const ENV_PASSWORD_REQUIRE_UPPERCASE: &str = "AUTH_PASSWORD_REQUIRE_UPPERCASE";
pub const ENV_PASSWORD_REQUIRE_DIGIT: &str = "AUTH_PASSWORD_REQUIRE_DIGIT";
pub const ENV_AUTHZ_MODE: &str = "AUTH_AUTHZ_MODE";
pub const ENV_REFRESH_RETRY_MATCH: &str = "AUTH_REFRESH_RETRY_MATCH";
pub const ENV_EXTERNAL_LINK_MAX_AUTH_AGE_SECS: &str = "AUTH_EXTERNAL_LINK_MAX_AUTH_AGE_SECS";
pub const ENV_EXTERNAL_LINK_CHALLENGE_TTL_SECS: &str = "AUTH_EXTERNAL_LINK_CHALLENGE_TTL_SECS";

/// Path of the YAML configuration file read by `ConfigSource::standard`.
pub const ENV_CONFIG_FILE: &str = "AUTH_CONFIG_FILE";

// ── Configuration file (read by `config::SourceLoader`) ──────────────────────

/// The core's top-level section in the configuration file.
pub const SECTION: &str = "auth";

/// Every core setting: its environment variable and its path in the file.
pub const KEYS: &[Key] = &[
    Key::new(ENV_JWT_SIGNING_KEY, "auth.jwt.signing_key"),
    Key::new(ENV_JWT_VERIFYING_KEYS, "auth.jwt.verifying_keys"),
    Key::new(ENV_JWT_ACCESS_TTL_SECS, "auth.jwt.access_ttl_secs"),
    Key::new(ENV_JWT_LEEWAY_SECS, "auth.jwt.leeway_secs"),
    Key::new(ENV_JWT_ISSUER, "auth.jwt.issuer"),
    Key::new(ENV_REFRESH_SECRET, "auth.session.refresh_secret"),
    Key::new(
        ENV_SESSION_IDLE_TIMEOUT_SECS,
        "auth.session.idle_timeout_secs",
    ),
    Key::new(
        ENV_SESSION_ABSOLUTE_TIMEOUT_SECS,
        "auth.session.absolute_timeout_secs",
    ),
    Key::new(ENV_SESSION_HISTORY_SIZE, "auth.session.history_size"),
    Key::new(ENV_REFRESH_GRACE_SECS, "auth.session.refresh_grace_secs"),
    Key::new(ENV_IP_BINDING, "auth.session.ip_binding"),
    Key::new(ENV_REFRESH_RETRY_MATCH, "auth.session.retry_match"),
    Key::new(
        ENV_MAX_SESSIONS_PER_USER,
        "auth.session.max_sessions_per_user",
    ),
    Key::new(ENV_PASSWORD_MIN_LENGTH, "auth.password.min_length"),
    Key::new(
        ENV_PASSWORD_REQUIRE_UPPERCASE,
        "auth.password.require_uppercase",
    ),
    Key::new(ENV_PASSWORD_REQUIRE_DIGIT, "auth.password.require_digit"),
    Key::new(ENV_AUTHZ_MODE, "auth.authz.mode"),
    Key::new(
        ENV_EXTERNAL_LINK_MAX_AUTH_AGE_SECS,
        "auth.external.link_max_auth_age_secs",
    ),
    Key::new(
        ENV_EXTERNAL_LINK_CHALLENGE_TTL_SECS,
        "auth.external.link_challenge_ttl_secs",
    ),
];

// ── Config field names (used in configuration errors) ────────────────────────

pub const FIELD_JWT_SIGNING_KEY: &str = "jwt_signing_key";
pub const FIELD_JWT_VERIFYING_KEYS: &str = "jwt_verifying_keys";
pub const FIELD_REFRESH_SECRET: &str = "refresh_secret";

// ── HTTP status codes (used by `api::ApiError`) ──────────────────────────────

pub const HTTP_UNAUTHORIZED: u16 = 401;
pub const HTTP_FORBIDDEN: u16 = 403;
pub const HTTP_NOT_FOUND: u16 = 404;
pub const HTTP_CONFLICT: u16 = 409;
pub const HTTP_MISDIRECTED_REQUEST: u16 = 421;
pub const HTTP_UNPROCESSABLE_ENTITY: u16 = 422;
pub const HTTP_TOO_MANY_REQUESTS: u16 = 429;
pub const HTTP_INTERNAL_SERVER_ERROR: u16 = 500;
pub const HTTP_SERVICE_UNAVAILABLE: u16 = 503;

/// Message returned for every 5xx error — internal details are never exposed.
pub const INTERNAL_ERROR_MESSAGE: &str = "internal server error";
