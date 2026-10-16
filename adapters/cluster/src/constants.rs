//! Cluster constants: defaults, protocol limits and the `AUTH_CLUSTER_*`,
//! `AUTH_LINK_*`, `AUTH_FEDERATION_*` and `AUTH_FORK_*` environment
//! variables read by [`ClusterEnvLoader`](crate::config::ClusterEnvLoader).

// ── Cluster ───────────────────────────────────────────────────────────────────

/// Service name advertised to peers when none is configured.
pub const DEFAULT_CLUSTER_SERVICE: &str = "z-auth";

/// Heartbeat interval — also how often the host should call `ZAuth::tick`.
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

/// Seeds are probed again every this many heartbeats while no peer is
/// alive (federation mode).
pub const CLUSTER_SEED_PROBE_EVERY: u64 = 5;

// ── Inter-cluster links (federation mode) ────────────────────────────────────

/// Attempts per inter-cluster request.
pub const DEFAULT_LINK_RETRY_ATTEMPTS: u32 = 3;
/// Base of the exponential backoff between attempts.
pub const DEFAULT_LINK_RETRY_BACKOFF_MS: u64 = 200;
/// Consecutive failed requests that open a target's circuit breaker.
pub const DEFAULT_LINK_BREAKER_FAILURES: u32 = 3;
/// How long an open breaker waits before a half-open probe.
pub const DEFAULT_LINK_BREAKER_COOLDOWN_SECS: u64 = 30;
/// How often a cluster marked dead is probed again.
pub const DEFAULT_LINK_DEAD_REPROBE_SECS: u64 = 60;

// ── Federation (federation mode) ─────────────────────────────────────────────────

/// `AUTH_DEPLOYMENT_MODE` values.
pub const DEPLOYMENT_STANDALONE: &str = "standalone";
pub const DEPLOYMENT_SHARED: &str = "shared";
pub const DEPLOYMENT_FEDERATION: &str = "federation";

/// Changes per pulled feed page.
pub const DEFAULT_FEDERATION_PULL_PAGE_SIZE: u32 = 500;
/// Incoming sessions already purgeable for this long are ignored.
pub const DEFAULT_FEDERATION_PURGE_HORIZON_SECS: u64 = 7 * 24 * 3_600;
/// Largest gap between two rotations of one generation for a benign retry.
pub const DEFAULT_FORK_WINDOW_MS: u64 = 5_000;
/// Benign forks a session may have per budget window.
pub const DEFAULT_FORK_MAX_BENIGN: u32 = 1;
pub const DEFAULT_FORK_BUDGET_WINDOW_SECS: u64 = 3_600;
/// Wire protocol version of federation mode; peers must match.
pub const FEDERATION_PROTOCOL_VERSION: u16 = 2;
/// How many times a session merge retries after losing its CAS.
pub const FEDERATION_MERGE_ATTEMPTS: u32 = 5;

// ── Environment variables (read by `config::ClusterEnvLoader`) ───────────────

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
/// Preferred names for `OFFLINE_AFTER` / `REMOVE_AFTER` / `TOMBSTONE_SECS`.
pub const ENV_CLUSTER_WARNING_AFTER: &str = "AUTH_CLUSTER_WARNING_AFTER";
pub const ENV_CLUSTER_MISSING_AFTER: &str = "AUTH_CLUSTER_MISSING_AFTER";
pub const ENV_CLUSTER_RETIRED_TTL_SECS: &str = "AUTH_CLUSTER_RETIRED_TTL_SECS";
/// Comma-separated `host:port` seeds (`[v6]:port` for IPv6).
pub const ENV_CLUSTER_SEEDS: &str = "AUTH_CLUSTER_SEEDS";
pub const ENV_CLUSTER_SELF_FENCE: &str = "AUTH_CLUSTER_SELF_FENCE";
pub const ENV_LINK_RETRY_ATTEMPTS: &str = "AUTH_LINK_RETRY_ATTEMPTS";
pub const ENV_LINK_RETRY_BACKOFF_MS: &str = "AUTH_LINK_RETRY_BACKOFF_MS";
pub const ENV_LINK_BREAKER_FAILURES: &str = "AUTH_LINK_BREAKER_FAILURES";
pub const ENV_LINK_BREAKER_COOLDOWN_SECS: &str = "AUTH_LINK_BREAKER_COOLDOWN_SECS";
pub const ENV_LINK_DEAD_REPROBE_SECS: &str = "AUTH_LINK_DEAD_REPROBE_SECS";
pub const ENV_DEPLOYMENT_MODE: &str = "AUTH_DEPLOYMENT_MODE";
pub const ENV_AUTHORITY_SERVICE: &str = "AUTH_AUTHORITY_SERVICE";
pub const ENV_SESSION_DISTRIBUTION: &str = "AUTH_SESSION_DISTRIBUTION";
pub const ENV_FEDERATION_MAX_STALENESS_SECS: &str = "AUTH_FEDERATION_MAX_STALENESS_SECS";
pub const ENV_FEDERATION_PULL_PAGE_SIZE: &str = "AUTH_FEDERATION_PULL_PAGE_SIZE";
pub const ENV_FEDERATION_PURGE_HORIZON_SECS: &str = "AUTH_FEDERATION_PURGE_HORIZON_SECS";
pub const ENV_FORK_WINDOW_MS: &str = "AUTH_FORK_WINDOW_MS";
pub const ENV_FORK_MAX_BENIGN: &str = "AUTH_FORK_MAX_BENIGN";
pub const ENV_FORK_BUDGET_WINDOW_SECS: &str = "AUTH_FORK_BUDGET_WINDOW_SECS";
