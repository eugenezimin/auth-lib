//! Cluster configuration data models: what [`ClusterEnvLoader`] reads from
//! `AUTH_CLUSTER_*`, `AUTH_LINK_*`, `AUTH_DEPLOYMENT_MODE`,
//! `AUTH_AUTHORITY_SERVICE`, `AUTH_SESSION_DISTRIBUTION`,
//! `AUTH_FEDERATION_*` and `AUTH_FORK_*`.
//!
//! [`ClusterEnvLoader`]: crate::config::ClusterEnvLoader

use std::net::IpAddr;
use std::time::Duration;

/// Everything a cluster needs beyond z-auth's own [`AuthConfig`].
///
/// [`AuthConfig`]: z_auth::conf::config::AuthConfig
#[derive(Debug, Clone)]
pub struct ClusterSettings {
    pub cluster: ClusterConfig,
    /// Explicit deployment mode; `None` lets the extension decide
    /// ([`Cluster::new`](crate::Cluster::new): shared).
    pub deployment: Option<DeploymentMode>,
    pub federation: FederationConfig,
}

/// How instances share z-auth state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    /// One instance (or instances that never talk to each other).
    Standalone,
    /// Every instance of every service shares one z-auth database; the
    /// cluster only syncs in-memory state.  `docs/cluster.md`.
    Shared,
    /// Database per service: the authority service (UMS) owns identity,
    /// every other service keeps a session store, and session state is
    /// synced between services.  `docs/replication.md`.
    Federation,
}

/// Which sessions a non-authority service stores in federation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionDistribution {
    /// Every session, so every refresh is local.
    #[default]
    All,
    /// Only sessions refreshed here at least once (fetched on first use).
    OnDemand,
}

/// Rules for refresh forks: two services rotating the same generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkPolicy {
    /// Largest gap between the competing rotations for a benign retry.
    pub window: Duration,
    /// Benign forks a session may have within `budget_window`; one more is
    /// treated as compromise.
    pub max_benign: u32,
    pub budget_window: Duration,
}

/// Federation-mode settings.  Ignored in the other modes.
#[derive(Debug, Clone)]
pub struct FederationConfig {
    /// Service name of the authority (UMS).  Required in federation mode.
    pub authority_service: Option<String>,
    pub session_distribution: SessionDistribution,
    /// Refuse refreshes when the last sync that reached the authority's
    /// head is older than this.  `None` = never (fail-open).
    pub max_staleness: Option<Duration>,
    /// Changes per pulled page.
    pub pull_page_size: u32,
    /// Incoming sessions that are already purgeable are ignored.
    pub purge_horizon: Duration,
    pub fork: ForkPolicy,
}

/// When an instance fences itself (stops serving) in federation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfFence {
    /// Never; liveness is only reported.
    Off,
    /// When its own cluster evicts it, or it loses the majority of its own
    /// cluster.
    Quorum,
}

/// Retry and circuit-breaker settings for links between clusters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkConfig {
    /// Attempts per inter-cluster request.
    pub retry_attempts: u32,
    /// Base of the exponential backoff between attempts.
    pub retry_backoff: Duration,
    /// Consecutive failed requests that open a target's breaker.
    pub breaker_failures: u32,
    /// How long a breaker stays open before a half-open probe.
    pub breaker_cooldown: Duration,
    /// How often a cluster marked dead is probed again.
    pub dead_reprobe: Duration,
}

/// Where a seed instance can be reached.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeedAddress {
    pub host: String,
    pub port: u16,
}

/// How this instance takes part in a cluster of z-auth instances.  Only
/// used when the host supplies a cluster transport.
#[derive(Clone)]
pub struct ClusterConfig {
    /// Service name advertised to peers.
    pub service: String,
    /// Address peers use to reach this instance — z-auth cannot discover
    /// it.  At least one of `advertise_ip` / `advertise_dns`.
    pub advertise_ip: Option<IpAddr>,
    pub advertise_dns: Option<String>,
    pub advertise_port: Option<u16>,
    /// Shared HMAC key authenticating every cluster message.
    pub secret: Option<Vec<u8>>,
    pub heartbeat: Duration,
    /// Missed heartbeats before a peer is marked `offline` (federation
    /// mode: `warning`).
    pub offline_after: u32,
    /// Further missed heartbeats before an offline peer is removed
    /// (federation mode: `missing`, evicted).
    pub remove_after: u32,
    /// How long removed peers are remembered and probed (federation mode:
    /// how long evicted node ids stay retired).
    pub tombstone_ttl: Duration,
    pub max_skew: Duration,
    /// Instances to contact at start (federation mode).
    pub seeds: Vec<SeedAddress>,
    /// `None` = the mode's default (`Quorum` federation, `Off` shared).
    pub self_fence: Option<SelfFence>,
    pub link: LinkConfig,
}

/// A flat, fully optional snapshot of every cluster knob.  Fields left as
/// `None` fall back to the defaults in [`crate::constants`].
#[derive(Clone, Default)]
pub struct RawClusterConfig {
    pub cluster_service: Option<String>,
    pub cluster_advertise_ip: Option<String>,
    pub cluster_advertise_dns: Option<String>,
    pub cluster_advertise_port: Option<u16>,
    /// Base64, ≥ 32 bytes.
    pub cluster_secret: Option<String>,
    pub cluster_heartbeat_ms: Option<u64>,
    pub cluster_offline_after: Option<u32>,
    pub cluster_remove_after: Option<u32>,
    pub cluster_tombstone_secs: Option<u64>,
    pub cluster_max_skew_secs: Option<u64>,
    /// `host:port` list; IPv6 as `[addr]:port`.
    pub cluster_seeds: Option<Vec<String>>,
    /// `quorum` | `off`.
    pub cluster_self_fence: Option<String>,
    pub link_retry_attempts: Option<u32>,
    pub link_retry_backoff_ms: Option<u64>,
    pub link_breaker_failures: Option<u32>,
    pub link_breaker_cooldown_secs: Option<u64>,
    pub link_dead_reprobe_secs: Option<u64>,

    /// `standalone` | `shared` | `federation`.
    pub deployment_mode: Option<String>,
    pub authority_service: Option<String>,
    /// `all` | `on_demand`.
    pub session_distribution: Option<String>,
    /// 0 = unlimited.
    pub federation_max_staleness_secs: Option<u64>,
    pub federation_pull_page_size: Option<u32>,
    pub federation_purge_horizon_secs: Option<u64>,
    pub fork_window_ms: Option<u64>,
    pub fork_max_benign: Option<u32>,
    pub fork_budget_window_secs: Option<u64>,
}
