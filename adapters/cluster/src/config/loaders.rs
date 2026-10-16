//! Cluster configuration loaders: [`ClusterEnvLoader`] (environment),
//! [`ClusterSourceLoader`] (the `cluster` section of a YAML file and / or
//! the environment) and [`ClusterDirectLoader`] (a pre-filled
//! [`RawClusterConfig`]), plus the parsing and validation behind
//! [`RawClusterConfig::build`].
//!
//! ```rust,no_run
//! use z_auth::conf::config::ConfigSource;
//! use z_auth_cluster::config::{ClusterConfigLoader, ClusterEnvLoader, ClusterSourceLoader};
//!
//! let settings = ClusterEnvLoader.load_settings().expect("cluster config");
//!
//! // AUTH_CONFIG_FILE's `cluster` section, with the environment on top.
//! let source = ConfigSource::standard().expect("config file");
//! let settings = ClusterSourceLoader::new(source).load_settings().expect("cluster config");
//! ```

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::config::model::{
    ClusterConfig, ClusterSettings, DeploymentMode, FederationConfig, ForkPolicy, LinkConfig,
    RawClusterConfig, SeedAddress, SelfFence, SessionDistribution,
};
use crate::constants::*;
use z_auth::conf::config::{ConfigError, ConfigSource, Section, Setting};

/// Any source of a [`RawClusterConfig`].
pub trait ClusterConfigLoader: Send + Sync {
    fn load(&self) -> Result<RawClusterConfig, ConfigError>;

    /// Load and validate into [`ClusterSettings`].
    fn load_settings(&self) -> Result<ClusterSettings, ConfigError> {
        self.load()?.build()
    }
}

/// Reads the cluster's environment variables.  Like z-auth's
/// `EnvLoader`, it never loads a `.env` file itself.  Same as
/// `ClusterSourceLoader::new(ConfigSource::env())`.
pub struct ClusterEnvLoader;

/// Reads the `cluster` section of a [`ConfigSource`]; the environment
/// overrides the file.
pub struct ClusterSourceLoader {
    pub source: ConfigSource,
}

impl ClusterSourceLoader {
    pub fn new(source: ConfigSource) -> Self {
        Self { source }
    }
}

/// A caller-supplied [`RawClusterConfig`].
pub struct ClusterDirectLoader {
    pub raw_config: RawClusterConfig,
}

impl ClusterDirectLoader {
    pub fn new(raw_config: RawClusterConfig) -> Self {
        Self { raw_config }
    }
}

impl ClusterConfigLoader for ClusterDirectLoader {
    fn load(&self) -> Result<RawClusterConfig, ConfigError> {
        Ok(self.raw_config.clone())
    }
}

impl ClusterConfigLoader for ClusterEnvLoader {
    fn load(&self) -> Result<RawClusterConfig, ConfigError> {
        ClusterSourceLoader::new(ConfigSource::env()).load()
    }
}

impl ClusterConfigLoader for ClusterSourceLoader {
    fn load(&self) -> Result<RawClusterConfig, ConfigError> {
        let s = self.source.section(SECTION, KEYS, &[])?;
        Ok(RawClusterConfig {
            cluster_service: env_str(&s, ENV_CLUSTER_SERVICE),
            cluster_advertise_ip: env_str(&s, ENV_CLUSTER_ADVERTISE_IP),
            cluster_advertise_dns: env_str(&s, ENV_CLUSTER_ADVERTISE_DNS),
            cluster_advertise_port: parse_opt(&s, ENV_CLUSTER_ADVERTISE_PORT)?,
            cluster_secret: env_str(&s, ENV_CLUSTER_SECRET),
            cluster_heartbeat_ms: parse_opt(&s, ENV_CLUSTER_HEARTBEAT_MS)?,
            cluster_offline_after: first_of(
                &s,
                ENV_CLUSTER_WARNING_AFTER,
                ENV_CLUSTER_OFFLINE_AFTER,
            )?,
            cluster_remove_after: first_of(
                &s,
                ENV_CLUSTER_MISSING_AFTER,
                ENV_CLUSTER_REMOVE_AFTER,
            )?,
            cluster_tombstone_secs: first_of(
                &s,
                ENV_CLUSTER_RETIRED_TTL_SECS,
                ENV_CLUSTER_TOMBSTONE_SECS,
            )?,
            cluster_max_skew_secs: parse_opt(&s, ENV_CLUSTER_MAX_SKEW_SECS)?,
            cluster_seeds: env_str(&s, ENV_CLUSTER_SEEDS).map(|v| split_list(&v)),
            cluster_self_fence: env_str(&s, ENV_CLUSTER_SELF_FENCE),
            link_retry_attempts: parse_opt(&s, ENV_LINK_RETRY_ATTEMPTS)?,
            link_retry_backoff_ms: parse_opt(&s, ENV_LINK_RETRY_BACKOFF_MS)?,
            link_breaker_failures: parse_opt(&s, ENV_LINK_BREAKER_FAILURES)?,
            link_breaker_cooldown_secs: parse_opt(&s, ENV_LINK_BREAKER_COOLDOWN_SECS)?,
            link_dead_reprobe_secs: parse_opt(&s, ENV_LINK_DEAD_REPROBE_SECS)?,
            deployment_mode: env_str(&s, ENV_DEPLOYMENT_MODE),
            authority_service: env_str(&s, ENV_AUTHORITY_SERVICE),
            session_distribution: env_str(&s, ENV_SESSION_DISTRIBUTION),
            federation_max_staleness_secs: parse_opt(&s, ENV_FEDERATION_MAX_STALENESS_SECS)?,
            federation_pull_page_size: parse_opt(&s, ENV_FEDERATION_PULL_PAGE_SIZE)?,
            federation_purge_horizon_secs: parse_opt(&s, ENV_FEDERATION_PURGE_HORIZON_SECS)?,
            fork_window_ms: parse_opt(&s, ENV_FORK_WINDOW_MS)?,
            fork_max_benign: parse_opt(&s, ENV_FORK_MAX_BENIGN)?,
            fork_budget_window_secs: parse_opt(&s, ENV_FORK_BUDGET_WINDOW_SECS)?,
        })
    }
}

fn env_str(s: &Section, key: &str) -> Option<String> {
    s.get(key).map(|v| v.value)
}

/// The preferred variable if set, else its legacy alias (environment only),
/// else the preferred setting's path in the file.
fn first_of<T>(s: &Section, preferred: &str, legacy: &str) -> Result<Option<T>, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let env = s.source();
    let setting = env
        .get_env(preferred)
        .or_else(|| env.get_env(legacy))
        .or_else(|| s.get(preferred));
    parse_setting(setting)
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

fn parse_opt<T>(s: &Section, key: &str) -> Result<Option<T>, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    parse_setting(s.get(key))
}

fn parse_setting<T>(setting: Option<Setting>) -> Result<Option<T>, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match setting {
        None => Ok(None),
        Some(v) => v
            .value
            .parse::<T>()
            .map(Some)
            .map_err(|e| ConfigError::Parse {
                key: v.origin,
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

fn secs(v: Option<u64>, default: u64) -> Duration {
    Duration::from_secs(v.unwrap_or(default))
}

fn at_least_one(key: &str, value: u32) -> Result<u32, ConfigError> {
    if value == 0 {
        return Err(ConfigError::Parse {
            key: key.into(),
            reason: "must be at least 1".into(),
        });
    }
    Ok(value)
}

// ── RawClusterConfig impls ────────────────────────────────────────────────────

impl RawClusterConfig {
    pub fn cluster_service(mut self, v: impl Into<String>) -> Self {
        self.cluster_service = Some(v.into());
        self
    }
    /// IP address peers use to reach this instance.
    pub fn cluster_advertise_ip(mut self, v: impl Into<String>) -> Self {
        self.cluster_advertise_ip = Some(v.into());
        self
    }
    /// DNS name peers use to reach this instance (preferred over the IP).
    pub fn cluster_advertise_dns(mut self, v: impl Into<String>) -> Self {
        self.cluster_advertise_dns = Some(v.into());
        self
    }
    pub fn cluster_advertise_port(mut self, v: u16) -> Self {
        self.cluster_advertise_port = Some(v);
        self
    }
    /// Base64 shared secret (≥ 32 bytes).
    pub fn cluster_secret(mut self, v: impl Into<String>) -> Self {
        self.cluster_secret = Some(v.into());
        self
    }
    pub fn cluster_heartbeat_ms(mut self, v: u64) -> Self {
        self.cluster_heartbeat_ms = Some(v);
        self
    }
    /// Missed heartbeats before a peer is marked offline (≥ 1).
    pub fn cluster_offline_after(mut self, v: u32) -> Self {
        self.cluster_offline_after = Some(v);
        self
    }
    /// Further missed heartbeats before an offline peer is removed (≥ 1).
    pub fn cluster_remove_after(mut self, v: u32) -> Self {
        self.cluster_remove_after = Some(v);
        self
    }
    pub fn cluster_tombstone_secs(mut self, v: u64) -> Self {
        self.cluster_tombstone_secs = Some(v);
        self
    }
    pub fn cluster_max_skew_secs(mut self, v: u64) -> Self {
        self.cluster_max_skew_secs = Some(v);
        self
    }
    /// `host:port` seeds (`[v6]:port` for IPv6).
    pub fn cluster_seeds<I, S>(mut self, seeds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.cluster_seeds = Some(seeds.into_iter().map(Into::into).collect());
        self
    }
    /// `quorum` | `off`.
    pub fn cluster_self_fence(mut self, v: impl Into<String>) -> Self {
        self.cluster_self_fence = Some(v.into());
        self
    }
    pub fn link_retry_attempts(mut self, v: u32) -> Self {
        self.link_retry_attempts = Some(v);
        self
    }
    pub fn link_retry_backoff_ms(mut self, v: u64) -> Self {
        self.link_retry_backoff_ms = Some(v);
        self
    }
    pub fn link_breaker_failures(mut self, v: u32) -> Self {
        self.link_breaker_failures = Some(v);
        self
    }
    pub fn link_breaker_cooldown_secs(mut self, v: u64) -> Self {
        self.link_breaker_cooldown_secs = Some(v);
        self
    }
    pub fn link_dead_reprobe_secs(mut self, v: u64) -> Self {
        self.link_dead_reprobe_secs = Some(v);
        self
    }
    /// `standalone` | `shared` | `federation`.
    pub fn deployment_mode(mut self, v: impl Into<String>) -> Self {
        self.deployment_mode = Some(v.into());
        self
    }
    /// Service name of the authority (UMS).
    pub fn authority_service(mut self, v: impl Into<String>) -> Self {
        self.authority_service = Some(v.into());
        self
    }
    /// `all` | `on_demand`.
    pub fn session_distribution(mut self, v: impl Into<String>) -> Self {
        self.session_distribution = Some(v.into());
        self
    }
    /// 0 = unlimited (fail-open).
    pub fn federation_max_staleness_secs(mut self, v: u64) -> Self {
        self.federation_max_staleness_secs = Some(v);
        self
    }
    pub fn federation_pull_page_size(mut self, v: u32) -> Self {
        self.federation_pull_page_size = Some(v);
        self
    }
    pub fn federation_purge_horizon_secs(mut self, v: u64) -> Self {
        self.federation_purge_horizon_secs = Some(v);
        self
    }
    pub fn fork_window_ms(mut self, v: u64) -> Self {
        self.fork_window_ms = Some(v);
        self
    }
    pub fn fork_max_benign(mut self, v: u32) -> Self {
        self.fork_max_benign = Some(v);
        self
    }
    pub fn fork_budget_window_secs(mut self, v: u64) -> Self {
        self.fork_budget_window_secs = Some(v);
        self
    }

    /// Validate and convert into [`ClusterSettings`].
    pub fn build(self) -> Result<ClusterSettings, ConfigError> {
        let cluster_secret = self
            .cluster_secret
            .as_deref()
            .map(|s| decode_b64(ENV_CLUSTER_SECRET, s))
            .transpose()?;
        if let Some(ref secret) = cluster_secret
            && secret.len() < MIN_CLUSTER_SECRET_LEN
        {
            return Err(ConfigError::Parse {
                key: ENV_CLUSTER_SECRET.into(),
                reason: format!(
                    "must be at least {MIN_CLUSTER_SECRET_LEN} bytes, got {}",
                    secret.len()
                ),
            });
        }
        let offline_after = self
            .cluster_offline_after
            .unwrap_or(DEFAULT_CLUSTER_OFFLINE_AFTER);
        let remove_after = self
            .cluster_remove_after
            .unwrap_or(DEFAULT_CLUSTER_REMOVE_AFTER);
        for (key, value) in [
            (ENV_CLUSTER_OFFLINE_AFTER, offline_after),
            (ENV_CLUSTER_REMOVE_AFTER, remove_after),
        ] {
            if value == 0 {
                return Err(ConfigError::Parse {
                    key: key.into(),
                    reason: "must be at least 1".into(),
                });
            }
        }
        let cluster = ClusterConfig {
            service: self
                .cluster_service
                .unwrap_or_else(|| DEFAULT_CLUSTER_SERVICE.into()),
            advertise_ip: self
                .cluster_advertise_ip
                .as_deref()
                .map(|ip| {
                    ip.trim().parse().map_err(|e| ConfigError::Parse {
                        key: ENV_CLUSTER_ADVERTISE_IP.into(),
                        reason: format!("{e}"),
                    })
                })
                .transpose()?,
            advertise_dns: self.cluster_advertise_dns,
            advertise_port: self.cluster_advertise_port,
            secret: cluster_secret,
            heartbeat: std::time::Duration::from_millis(
                self.cluster_heartbeat_ms
                    .unwrap_or(DEFAULT_CLUSTER_HEARTBEAT_MS),
            ),
            offline_after,
            remove_after,
            tombstone_ttl: secs(self.cluster_tombstone_secs, DEFAULT_CLUSTER_TOMBSTONE_SECS),
            max_skew: secs(self.cluster_max_skew_secs, DEFAULT_CLUSTER_MAX_SKEW_SECS),
            seeds: self
                .cluster_seeds
                .unwrap_or_default()
                .iter()
                .map(|s| s.parse())
                .collect::<Result<Vec<SeedAddress>, _>>()?,
            self_fence: self
                .cluster_self_fence
                .as_deref()
                .map(str::parse)
                .transpose()?,
            link: LinkConfig {
                retry_attempts: at_least_one(
                    ENV_LINK_RETRY_ATTEMPTS,
                    self.link_retry_attempts
                        .unwrap_or(DEFAULT_LINK_RETRY_ATTEMPTS),
                )?,
                retry_backoff: Duration::from_millis(
                    self.link_retry_backoff_ms
                        .unwrap_or(DEFAULT_LINK_RETRY_BACKOFF_MS),
                ),
                breaker_failures: at_least_one(
                    ENV_LINK_BREAKER_FAILURES,
                    self.link_breaker_failures
                        .unwrap_or(DEFAULT_LINK_BREAKER_FAILURES),
                )?,
                breaker_cooldown: secs(
                    self.link_breaker_cooldown_secs,
                    DEFAULT_LINK_BREAKER_COOLDOWN_SECS,
                ),
                dead_reprobe: secs(self.link_dead_reprobe_secs, DEFAULT_LINK_DEAD_REPROBE_SECS),
            },
        };

        let deployment = self
            .deployment_mode
            .as_deref()
            .map(str::parse::<DeploymentMode>)
            .transpose()?;
        let federation = FederationConfig {
            authority_service: self.authority_service.filter(|s| !s.trim().is_empty()),
            session_distribution: self
                .session_distribution
                .as_deref()
                .map(str::parse)
                .transpose()?
                .unwrap_or_default(),
            max_staleness: self
                .federation_max_staleness_secs
                .filter(|s| *s > 0)
                .map(Duration::from_secs),
            pull_page_size: at_least_one(
                ENV_FEDERATION_PULL_PAGE_SIZE,
                self.federation_pull_page_size
                    .unwrap_or(DEFAULT_FEDERATION_PULL_PAGE_SIZE),
            )?,
            purge_horizon: secs(
                self.federation_purge_horizon_secs,
                DEFAULT_FEDERATION_PURGE_HORIZON_SECS,
            ),
            fork: ForkPolicy {
                window: Duration::from_millis(
                    self.fork_window_ms.unwrap_or(DEFAULT_FORK_WINDOW_MS),
                ),
                max_benign: self.fork_max_benign.unwrap_or(DEFAULT_FORK_MAX_BENIGN),
                budget_window: secs(
                    self.fork_budget_window_secs,
                    DEFAULT_FORK_BUDGET_WINDOW_SECS,
                ),
            },
        };

        if deployment == Some(DeploymentMode::Federation) {
            let Some(authority) = federation.authority_service.as_deref() else {
                return Err(ConfigError::Missing(ENV_AUTHORITY_SERVICE.into()));
            };
            if cluster.secret.is_none() {
                return Err(ConfigError::Missing(ENV_CLUSTER_SECRET.into()));
            }
            if cluster.seeds.is_empty() && cluster.service != authority {
                return Err(ConfigError::Missing(format!(
                    "{ENV_CLUSTER_SEEDS} (required on every service except the authority '{authority}')"
                )));
            }
        }

        Ok(ClusterSettings {
            cluster,
            deployment,
            federation,
        })
    }
}

impl std::str::FromStr for DeploymentMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, ConfigError> {
        match s.trim() {
            DEPLOYMENT_STANDALONE => Ok(Self::Standalone),
            DEPLOYMENT_SHARED => Ok(Self::Shared),
            DEPLOYMENT_FEDERATION => Ok(Self::Federation),
            other => Err(ConfigError::Parse {
                key: ENV_DEPLOYMENT_MODE.into(),
                reason: format!("expected standalone | shared | federation, got '{other}'"),
            }),
        }
    }
}

/// The `AUTH_DEPLOYMENT_MODE` value that selects this mode.
impl std::fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Standalone => DEPLOYMENT_STANDALONE,
            Self::Shared => DEPLOYMENT_SHARED,
            Self::Federation => DEPLOYMENT_FEDERATION,
        })
    }
}

impl std::str::FromStr for SessionDistribution {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, ConfigError> {
        match s.trim() {
            "all" => Ok(Self::All),
            "on_demand" => Ok(Self::OnDemand),
            other => Err(ConfigError::Parse {
                key: ENV_SESSION_DISTRIBUTION.into(),
                reason: format!("expected all | on_demand, got '{other}'"),
            }),
        }
    }
}

impl std::str::FromStr for SelfFence {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, ConfigError> {
        match s.trim() {
            "off" => Ok(Self::Off),
            "quorum" => Ok(Self::Quorum),
            other => Err(ConfigError::Parse {
                key: ENV_CLUSTER_SELF_FENCE.into(),
                reason: format!("expected quorum | off, got '{other}'"),
            }),
        }
    }
}

impl std::str::FromStr for SeedAddress {
    type Err = ConfigError;

    /// `host:port`, `ip:port` or `[ipv6]:port`.
    fn from_str(s: &str) -> Result<Self, ConfigError> {
        let invalid = |reason: &str| ConfigError::Parse {
            key: ENV_CLUSTER_SEEDS.into(),
            reason: format!("'{s}': {reason}"),
        };
        let s = s.trim();
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (host, port) = rest
                .split_once("]:")
                .ok_or_else(|| invalid("expected [ipv6]:port"))?;
            (host, port)
        } else {
            s.rsplit_once(':')
                .ok_or_else(|| invalid("expected host:port"))?
        };
        if host.is_empty() {
            return Err(invalid("empty host"));
        }
        let port: u16 = port.parse().map_err(|_| invalid("invalid port"))?;
        if port == 0 {
            return Err(invalid("port must be 1-65535"));
        }
        Ok(SeedAddress {
            host: host.to_string(),
            port,
        })
    }
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for ClusterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterConfig")
            .field("service", &self.service)
            .field("advertise_ip", &self.advertise_ip)
            .field("advertise_dns", &self.advertise_dns)
            .field("advertise_port", &self.advertise_port)
            .field("secret", &self.secret.as_ref().map(|_| REDACTED))
            .field("heartbeat", &self.heartbeat)
            .field("offline_after", &self.offline_after)
            .field("remove_after", &self.remove_after)
            .field("tombstone_ttl", &self.tombstone_ttl)
            .field("max_skew", &self.max_skew)
            .field("seeds", &self.seeds)
            .field("self_fence", &self.self_fence)
            .field("link", &self.link)
            .finish()
    }
}

impl std::fmt::Debug for RawClusterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawClusterConfig")
            .field("cluster_service", &self.cluster_service)
            .field("cluster_advertise_ip", &self.cluster_advertise_ip)
            .field("cluster_advertise_dns", &self.cluster_advertise_dns)
            .field("cluster_advertise_port", &self.cluster_advertise_port)
            .field(
                "cluster_secret",
                &self.cluster_secret.as_ref().map(|_| REDACTED),
            )
            .field("deployment_mode", &self.deployment_mode)
            .field("authority_service", &self.authority_service)
            .finish_non_exhaustive()
    }
}
