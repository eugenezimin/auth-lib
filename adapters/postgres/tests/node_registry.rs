//! Integration tests — z-auth-cluster's node registry against Postgres
//! (feature `shared`): the guarded state machine, eviction, addresses.
//!
//! Run with:
//!   cargo test -p z-auth-postgres --features shared --test node_registry

mod helpers;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use z_auth_cluster::shared::{
    EvictOutcome, HeartbeatStatus, NodeInfo, NodeRepository, NodeState, NodeTransition,
};
use z_auth_postgres::PgNodeRepository;
use chrono::Utc;
use uuid::Uuid;

use crate::helpers::cluster_pool as pool;

#[tokio::test]
async fn test_node_registry_is_a_guarded_state_machine() {
    let repo = PgNodeRepository::new(pool().await);
    let node = NodeInfo {
        node_id: Uuid::new_v4(),
        service: "it-cluster".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        dns_name: Some("auth-1.internal".into()),
        port: 8443,
        version: "test".into(),
        started_at: Utc::now(),
    };
    let row = || async {
        repo.list()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.info.node_id == node.node_id)
    };
    let id = node.node_id;
    use NodeTransition::*;

    // register → joining / online; activate is applied once.
    repo.register(&node).await.unwrap();
    let r = row().await.unwrap();
    assert_eq!(
        (r.state, r.heartbeat),
        (NodeState::Joining, HeartbeatStatus::Online)
    );
    assert_eq!(r.info.dns_name, node.dns_name);
    assert!(repo.transition(id, Activate).await.unwrap());
    assert!(!repo.transition(id, Activate).await.unwrap(), "guarded");
    assert_eq!(row().await.unwrap().state, NodeState::Active);

    // heartbeat: online → offline (once) → online (once).
    assert!(
        !repo.transition(id, MarkOnline).await.unwrap(),
        "already online"
    );
    assert!(
        !repo.transition(id, Expire).await.unwrap(),
        "only offline rows expire"
    );
    assert!(repo.transition(id, MarkOffline).await.unwrap());
    assert!(
        !repo.transition(id, MarkOffline).await.unwrap(),
        "second observer: no-op"
    );
    assert_eq!(row().await.unwrap().heartbeat, HeartbeatStatus::Offline);
    assert!(repo.transition(id, MarkOnline).await.unwrap());

    // offline and still silent → deleted; heard again → restored.
    assert!(repo.transition(id, MarkOffline).await.unwrap());
    assert!(repo.transition(id, Expire).await.unwrap());
    assert!(row().await.is_none());
    assert!(!repo.transition(id, Expire).await.unwrap(), "gone");
    assert!(repo.restore(&node, NodeState::Active).await.unwrap());
    assert!(
        !repo.restore(&node, NodeState::Active).await.unwrap(),
        "already online"
    );
    let r = row().await.unwrap();
    assert_eq!(
        (r.state, r.heartbeat),
        (NodeState::Active, HeartbeatStatus::Online)
    );

    // graceful leave: → leaving → removed (remove needs leaving).
    assert!(
        !repo.transition(id, Remove).await.unwrap(),
        "not leaving yet"
    );
    assert!(repo.transition(id, BeginLeave).await.unwrap());
    assert!(!repo.transition(id, BeginLeave).await.unwrap());
    assert!(repo.transition(id, Remove).await.unwrap());
    assert!(row().await.is_none());
}

fn federation_node(service: &str) -> NodeInfo {
    NodeInfo {
        node_id: Uuid::new_v4(),
        service: service.into(),
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))),
        dns_name: None,
        port: 7000,
        version: "test".into(),
        started_at: Utc::now(),
    }
}

async fn heartbeat(repo: &PgNodeRepository, id: Uuid) -> Option<HeartbeatStatus> {
    repo.list()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.info.node_id == id)
        .map(|r| r.heartbeat)
}

#[tokio::test]
async fn test_eviction_is_witnessed_by_the_registry() {
    let repo = PgNodeRepository::new(pool().await);
    let service = format!("it-evict-{}", Uuid::new_v4());
    let (a, b, c) = (
        federation_node(&service),
        federation_node(&service),
        federation_node(&service),
    );
    for n in [&a, &b, &c] {
        repo.register(n).await.unwrap();
    }

    assert_eq!(
        repo.evict(c.node_id, a.node_id).await.unwrap(),
        EvictOutcome::Evicted
    );
    assert_eq!(
        heartbeat(&repo, c.node_id).await,
        Some(HeartbeatStatus::Missing)
    );
    assert_eq!(
        repo.evict(c.node_id, b.node_id).await.unwrap(),
        EvictOutcome::AlreadyMissing,
        "a second observer changes nothing"
    );
    assert_eq!(
        repo.evict(a.node_id, c.node_id).await.unwrap(),
        EvictOutcome::ObserverMissing,
        "the evicted one lost"
    );
    assert!(
        !repo
            .transition(c.node_id, NodeTransition::MarkOnline)
            .await
            .unwrap(),
        "a missing row is not revived by liveness writes"
    );
    // Retired rows are kept until the TTL passes.
    assert_eq!(
        repo.purge_retired(Duration::from_secs(3600)).await.unwrap(),
        0
    );
    assert_eq!(
        heartbeat(&repo, c.node_id).await,
        Some(HeartbeatStatus::Missing)
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(repo.purge_retired(Duration::from_millis(1)).await.unwrap() >= 1);
    assert_eq!(heartbeat(&repo, c.node_id).await, None);
}

#[tokio::test]
async fn test_two_instances_evicting_each_other_one_wins() {
    let repo = Arc::new(PgNodeRepository::new(pool().await));
    for _ in 0..20 {
        let service = format!("it-split-{}", Uuid::new_v4());
        let (a, b) = (federation_node(&service), federation_node(&service));
        repo.register(&a).await.unwrap();
        repo.register(&b).await.unwrap();
        let (x, y) = tokio::join!(
            repo.evict(b.node_id, a.node_id),
            repo.evict(a.node_id, b.node_id)
        );
        let outcomes = [x.unwrap(), y.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == EvictOutcome::Evicted)
                .count(),
            1,
            "exactly one side wins: {outcomes:?}"
        );
        assert!(outcomes.contains(&EvictOutcome::ObserverMissing));
    }
}

#[tokio::test]
async fn test_address_update_only_writes_on_change() {
    let repo = PgNodeRepository::new(pool().await);
    let mut node = federation_node("it-address");
    repo.register(&node).await.unwrap();
    assert!(!repo.update_address(&node).await.unwrap(), "unchanged");
    node.dns_name = Some("moved.internal".into());
    node.port = 7001;
    assert!(repo.update_address(&node).await.unwrap());
    let row = repo
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.info.node_id == node.node_id)
        .unwrap();
    assert_eq!(row.info.dns_name.as_deref(), Some("moved.internal"));
    assert_eq!(row.info.port, 7001);
}
