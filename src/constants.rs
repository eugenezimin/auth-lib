//! Library-wide constants.
//!
//! Every default, limit and environment-variable name used by auth-lib lives
//! here — no other module should hard-code these values.

// ── Access tokens (JWT) ───────────────────────────────────────────────────────

/// Default access-token lifetime: 5 minutes.
pub const DEFAULT_ACCESS_TOKEN_TTL_SECS: u64 = 300;

/// Default clock-skew tolerance when checking `exp`.
pub const DEFAULT_JWT_LEEWAY_SECS: u64 = 30;

/// Default `iss` claim.
pub const DEFAULT_JWT_ISSUER: &str = "auth-lib";

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

// ── Cluster ───────────────────────────────────────────────────────────────────

/// Service name advertised to peers when none is configured.
pub const DEFAULT_CLUSTER_SERVICE: &str = "auth-lib";

/// Heartbeat interval — also how often the host should call `AuthLib::tick`.
pub const DEFAULT_CLUSTER_HEARTBEAT_MS: u64 = 2_000;

/// Missed heartbeats before a peer is marked `offline`.
pub const DEFAULT_CLUSTER_OFFLINE_AFTER: u32 = 1;
/// Further missed heartbeats before an offline peer is removed.
pub const DEFAULT_CLUSTER_REMOVE_AFTER: u32 = 1;
/// How long a removed peer is remembered (and still probed) in memory, so
/// it rejoins by itself if it was only cut off.
pub const DEFAULT_CLUSTER_TOMBSTONE_SECS: u64 = 1_800;
/// Removed peers are probed every this many heartbeats.
pub const CLUSTER_TOMBSTONE_PROBE_EVERY: u64 = 5;

/// Largest accepted difference between a message's `sent_at` and local time.
pub const DEFAULT_CLUSTER_MAX_SKEW_SECS: u64 = 30;

/// Minimum length of the shared cluster secret.
pub const MIN_CLUSTER_SECRET_LEN: usize = 32;

/// Failed sends are retried for this many ticks before giving up (the
/// heartbeat digest repairs anything still missing).
pub const CLUSTER_OUTBOX_MAX_ATTEMPTS: u32 = 5;

/// At most this many queued retries per instance.
pub const CLUSTER_OUTBOX_CAPACITY: usize = 10_000;

/// A peer that heartbeats with a different digest is asked for a snapshot
/// at most once per this many heartbeat intervals.
pub const CLUSTER_SNAPSHOT_COOLDOWN_BEATS: u32 = 5;

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
pub const ENV_CLUSTER_SERVICE: &str = "AUTH_CLUSTER_SERVICE";
pub const ENV_CLUSTER_ADVERTISE_IP: &str = "AUTH_CLUSTER_ADVERTISE_IP";
pub const ENV_CLUSTER_ADVERTISE_DNS: &str = "AUTH_CLUSTER_ADVERTISE_DNS";
pub const ENV_CLUSTER_ADVERTISE_PORT: &str = "AUTH_CLUSTER_ADVERTISE_PORT";
/// Base64 shared secret (≥ 32 bytes) authenticating cluster messages.
pub const ENV_CLUSTER_SECRET: &str = "AUTH_CLUSTER_SECRET";
pub const ENV_CLUSTER_HEARTBEAT_MS: &str = "AUTH_CLUSTER_HEARTBEAT_MS";
pub const ENV_CLUSTER_OFFLINE_AFTER: &str = "AUTH_CLUSTER_OFFLINE_AFTER";
pub const ENV_CLUSTER_REMOVE_AFTER: &str = "AUTH_CLUSTER_REMOVE_AFTER";
pub const ENV_CLUSTER_TOMBSTONE_SECS: &str = "AUTH_CLUSTER_TOMBSTONE_SECS";
pub const ENV_CLUSTER_MAX_SKEW_SECS: &str = "AUTH_CLUSTER_MAX_SKEW_SECS";

// ── Config field names (used in configuration errors) ────────────────────────

pub const FIELD_JWT_SIGNING_KEY: &str = "jwt_signing_key";
pub const FIELD_JWT_VERIFYING_KEYS: &str = "jwt_verifying_keys";
pub const FIELD_REFRESH_SECRET: &str = "refresh_secret";

// ── HTTP status codes (used by `api::ApiError`) ──────────────────────────────

pub const HTTP_UNAUTHORIZED: u16 = 401;
pub const HTTP_FORBIDDEN: u16 = 403;
pub const HTTP_NOT_FOUND: u16 = 404;
pub const HTTP_CONFLICT: u16 = 409;
pub const HTTP_UNPROCESSABLE_ENTITY: u16 = 422;
pub const HTTP_INTERNAL_SERVER_ERROR: u16 = 500;

/// Message returned for every 5xx error — internal details are never exposed.
pub const INTERNAL_ERROR_MESSAGE: &str = "internal server error";
