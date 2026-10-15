//! Cluster config loading — `RawClusterConfig`, defaults and validation.

use std::time::Duration;

use z_auth::conf::config::ConfigError;
use z_auth_cluster::config::{
    ClusterConfigLoader, ClusterDirectLoader, DeploymentMode, RawClusterConfig, SeedAddress,
    SelfFence, SessionDistribution,
};
use z_auth_cluster::constants::*;

// 32 bytes of 0x07, base64.
const KEY_A: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

fn federation(service: &str) -> RawClusterConfig {
    RawClusterConfig::default()
        .deployment_mode("federation")
        .authority_service("ums")
        .cluster_service(service)
        .cluster_secret(KEY_A)
}

#[test]
fn federation_mode_parses_every_setting() {
    let cfg = ClusterDirectLoader::new(
        federation("orders")
            .cluster_seeds(["ums.internal:7000", "10.0.0.5:7001", "[::1]:7002"])
            .cluster_self_fence("off")
            .link_retry_attempts(4)
            .link_retry_backoff_ms(50)
            .link_breaker_failures(2)
            .link_breaker_cooldown_secs(10)
            .link_dead_reprobe_secs(20)
            .session_distribution("on_demand")
            .federation_max_staleness_secs(15)
            .federation_pull_page_size(7)
            .fork_window_ms(1500)
            .fork_max_benign(2)
            .fork_budget_window_secs(60),
    )
    .load_settings()
    .expect("valid federation config");

    assert_eq!(cfg.deployment, Some(DeploymentMode::Federation));
    assert_eq!(cfg.federation.authority_service.as_deref(), Some("ums"));
    assert_eq!(
        cfg.cluster.seeds,
        vec![
            SeedAddress {
                host: "ums.internal".into(),
                port: 7000
            },
            SeedAddress {
                host: "10.0.0.5".into(),
                port: 7001
            },
            SeedAddress {
                host: "::1".into(),
                port: 7002
            },
        ]
    );
    assert_eq!(cfg.cluster.self_fence, Some(SelfFence::Off));
    assert_eq!(cfg.cluster.link.retry_attempts, 4);
    assert_eq!(cfg.cluster.link.retry_backoff, Duration::from_millis(50));
    assert_eq!(cfg.cluster.link.breaker_failures, 2);
    assert_eq!(cfg.cluster.link.breaker_cooldown, Duration::from_secs(10));
    assert_eq!(cfg.cluster.link.dead_reprobe, Duration::from_secs(20));
    assert_eq!(
        cfg.federation.session_distribution,
        SessionDistribution::OnDemand
    );
    assert_eq!(cfg.federation.max_staleness, Some(Duration::from_secs(15)));
    assert_eq!(cfg.federation.pull_page_size, 7);
    assert_eq!(cfg.federation.fork.window, Duration::from_millis(1500));
    assert_eq!(cfg.federation.fork.max_benign, 2);
    assert_eq!(cfg.federation.fork.budget_window, Duration::from_secs(60));
}

#[test]
fn federation_defaults() {
    let cfg = federation("ums").build().expect("authority needs no seeds");
    assert!(cfg.cluster.seeds.is_empty());
    assert_eq!(cfg.cluster.self_fence, None, "mode default applies later");
    assert_eq!(
        cfg.federation.session_distribution,
        SessionDistribution::All
    );
    assert_eq!(cfg.federation.max_staleness, None, "fail-open by default");
    assert_eq!(
        cfg.federation.fork.window,
        Duration::from_millis(DEFAULT_FORK_WINDOW_MS)
    );
    assert_eq!(cfg.cluster.link.retry_attempts, DEFAULT_LINK_RETRY_ATTEMPTS);
}

#[test]
fn shared_mode_defaults() {
    let cfg = RawClusterConfig::default().build().unwrap();
    assert_eq!(cfg.deployment, None);
    assert_eq!(cfg.cluster.service, DEFAULT_CLUSTER_SERVICE);
    assert_eq!(
        cfg.cluster.heartbeat,
        Duration::from_millis(DEFAULT_CLUSTER_HEARTBEAT_MS)
    );
    assert!(cfg.cluster.secret.is_none());
}

#[test]
fn federation_validation() {
    // Every non-authority service needs a seed.
    assert!(matches!(
        federation("orders").build(),
        Err(ConfigError::Missing(ref k)) if k.starts_with(ENV_CLUSTER_SEEDS)
    ));
    // The authority name is required.
    assert!(matches!(
        RawClusterConfig::default()
            .deployment_mode("federation")
            .cluster_secret(KEY_A)
            .build(),
        Err(ConfigError::Missing(ref k)) if k == ENV_AUTHORITY_SERVICE
    ));
    // So is the cluster secret.
    assert!(matches!(
        RawClusterConfig::default()
            .deployment_mode("federation")
            .authority_service("ums")
            .cluster_service("ums")
            .build(),
        Err(ConfigError::Missing(ref k)) if k == ENV_CLUSTER_SECRET
    ));

    for bad in [
        federation("ums").deployment_mode("mesh"),
        federation("ums").session_distribution("some"),
        federation("ums").cluster_self_fence("always"),
        federation("ums").cluster_seeds(["no-port"]),
        federation("ums").cluster_seeds(["host:0"]),
        federation("ums").cluster_seeds(["[::1]7000"]),
        federation("ums").cluster_secret("c2hvcnQ="),
        federation("ums").cluster_offline_after(0),
        federation("ums").link_retry_attempts(0),
        federation("ums").federation_pull_page_size(0),
    ] {
        assert!(
            matches!(bad.build(), Err(ConfigError::Parse { .. })),
            "should be rejected"
        );
    }
}

#[test]
fn debug_redacts_the_cluster_secret() {
    let raw = federation("ums");
    assert!(!format!("{raw:?}").contains(KEY_A));
    let cfg = raw.build().unwrap();
    assert!(!format!("{cfg:?}").contains("[7, 7"));
}
