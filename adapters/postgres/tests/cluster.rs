//! Integration tests — cluster ports against Postgres: revocation
//! enforcement CAS, node registry, published verifying keys.
//!
//! Run with:
//!   cargo test -p auth-lib-postgres --test cluster

mod helpers;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use auth_lib::cluster::{HeartbeatStatus, NodeInfo, NodeRepository, NodeState, NodeTransition};
use auth_lib::token::{
    KeyRepository, KeyStatus, NewRevocation, NewVerifyingKey, RevocationReason,
    RevocationRepository, RevocationScope, RevocationStatus,
};
use auth_lib_postgres::{PgKeyRepository, PgNodeRepository, PgRevocationRepository};
use chrono::Utc;
use uuid::Uuid;

use crate::helpers::pool;

#[tokio::test]
async fn test_exactly_one_instance_enforces_a_revocation() {
    let repo = Arc::new(PgRevocationRepository::new(pool().await));
    let stored = repo
        .insert(&NewRevocation {
            scope: RevocationScope::Session(Uuid::new_v4()),
            reason: RevocationReason::Administrative,
            ttl: Duration::from_secs(60),
            origin_node: Uuid::new_v4(),
        })
        .await
        .unwrap();
    assert_eq!(stored.status, RevocationStatus::Pending);
    assert!(stored.enforced_at.is_none());

    let (n1, n2) = (Uuid::new_v4(), Uuid::new_v4());
    let (a, b) = tokio::join!(
        repo.mark_enforced(stored.id, n1),
        repo.mark_enforced(stored.id, n2)
    );
    let winners: Vec<_> = [a.unwrap(), b.unwrap()].into_iter().flatten().collect();
    assert_eq!(winners.len(), 1, "compare-and-swap: one winner");
    let won = &winners[0];
    assert_eq!(won.status, RevocationStatus::Enforced);
    assert!(won.enforced_at.is_some());
    assert!(won.enforced_by == Some(n1) || won.enforced_by == Some(n2));
    assert!(repo.mark_enforced(stored.id, n1).await.unwrap().is_none());
}

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

#[tokio::test]
async fn test_verifying_keys_publish_idempotently_and_revoke_for_good() {
    let repo = PgKeyRepository::new(pool().await);
    let kid = Uuid::new_v4().simple().to_string()[..16].to_string();
    let key = NewVerifyingKey {
        kid: kid.clone(),
        public_key: [9; 32],
        published_by: Uuid::new_v4(),
    };

    let first = repo.publish(&key).await.unwrap();
    assert_eq!(first.status, KeyStatus::Active);
    assert_eq!(first.public_key, [9; 32]);
    let again = repo.publish(&key).await.unwrap();
    assert_eq!(again, first, "idempotent per kid");

    let revoked = repo.revoke(&kid).await.unwrap().unwrap();
    assert_eq!(revoked.status, KeyStatus::Revoked);
    assert!(revoked.revoked_at.is_some());
    assert_eq!(
        repo.publish(&key).await.unwrap().status,
        KeyStatus::Revoked,
        "a revoked key stays revoked"
    );
    assert!(repo.list().await.unwrap().iter().any(|k| k.kid == kid));
    assert!(repo.revoke("unknown-kid").await.unwrap().is_none());
}
