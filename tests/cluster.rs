//! Cluster sync between auth-lib instances over an in-memory transport:
//! membership, immediate push of revocations and key / catalog events,
//! enforcement on first use, anti-entropy repair and message security.

// The facade's defaults need the `argon2` and `crypto` features.
#![cfg(all(feature = "argon2", feature = "cluster"))]

mod support;

use std::sync::Arc;
use std::time::Duration;

use auth_lib::prelude::*;
use auth_lib::token::RevocationStatus;
use uuid::Uuid;

use crate::support::cluster::{cluster_node, started_cluster};
use crate::support::{IP_A, MockClock, credentials, ctx, raw_config, register_and_login};

const BEAT: Duration = Duration::from_secs(2);

fn statuses(node: &AuthLib) -> Vec<(Uuid, HeartbeatStatus)> {
    node.cluster()
        .unwrap()
        .peers()
        .into_iter()
        .map(|p| (p.info.node_id, p.heartbeat))
        .collect()
}

fn alive_peers(node: &AuthLib) -> usize {
    statuses(node)
        .iter()
        .filter(|(_, s)| *s == HeartbeatStatus::Online)
        .count()
}

/// Everyone heartbeats once, `BEAT` apart.
async fn round(clock: &MockClock, nodes: &[&Arc<AuthLib>]) {
    clock.advance(BEAT);
    for n in nodes {
        n.tick().await.unwrap();
    }
}

fn is_revoked(node: &AuthLib, token: &str) -> bool {
    matches!(node.verifier().verify(token), Err(AuthError::TokenRevoked))
}

// ── membership ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn nodes_find_each_other_through_the_registry() {
    let (_net, _db, _clock, nodes) = started_cluster(3).await;
    for n in &nodes {
        n.tick().await.unwrap();
    }
    for n in &nodes {
        assert_eq!(alive_peers(n), 2, "every node sees the other two alive");
        let local = n.cluster().unwrap().local();
        assert!(local.port >= 9000);
        assert_eq!(local.ip.map(|ip| ip.to_string()), Some("127.0.0.1".into()));
    }
}

#[tokio::test]
async fn heartbeats_gossip_members_the_registry_missed() {
    let clock = MockClock::new();
    let db = Arc::new(support::InMemoryDb::new(clock.clone()));
    let net = support::cluster::InMemoryNetwork::new();
    let a = cluster_node(&net, &db, &clock, raw_config(), 9001);
    let b = cluster_node(&net, &db, &clock, raw_config(), 9002);
    a.start().await.unwrap();
    b.start().await.unwrap();
    db.drop_node(b.node_id()); // C will not find B in the registry

    let c = cluster_node(&net, &db, &clock, raw_config(), 9003);
    c.start().await.unwrap();
    assert_eq!(statuses(&c).len(), 1, "C only knows A");

    a.tick().await.unwrap(); // A's heartbeat lists B as a member
    c.tick().await.unwrap(); // C heartbeats B, introducing itself
    b.tick().await.unwrap(); // B heartbeats C
    assert_eq!(alive_peers(&c), 2);
    assert_eq!(alive_peers(&b), 2);
}

// ── registry state machine ────────────────────────────────────────────────────

#[tokio::test]
async fn started_nodes_are_active_and_online_in_the_registry() {
    let (_net, db, _clock, nodes) = started_cluster(2).await;
    for n in &nodes {
        let row = db.node(n.node_id()).unwrap();
        assert_eq!(row.state, NodeState::Active, "joining → active after start");
        assert_eq!(row.heartbeat, HeartbeatStatus::Online);
    }
}

#[tokio::test]
async fn steady_heartbeats_never_write_to_the_registry() {
    let (_net, db, clock, nodes) = started_cluster(3).await;
    let all: Vec<&Arc<AuthLib>> = nodes.iter().collect();
    round(&clock, &all).await;
    let writes = db.node_writes();
    for _ in 0..10 {
        round(&clock, &all).await;
    }
    assert_eq!(db.node_writes(), writes, "no state change, no write");
    for n in &nodes {
        assert_eq!(alive_peers(n), 2);
    }
}

#[tokio::test]
async fn one_missed_heartbeat_marks_offline_and_the_next_removes() {
    let (net, db, clock, nodes) = started_cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    net.partition(b.node_id());

    clock.advance(BEAT + BEAT / 2); // one heartbeat missed
    a.tick().await.unwrap();
    assert_eq!(statuses(a), vec![(b.node_id(), HeartbeatStatus::Offline)]);
    assert_eq!(
        db.node(b.node_id()).unwrap().heartbeat,
        HeartbeatStatus::Offline
    );

    clock.advance(BEAT); // not back by the next one
    let report = a.tick().await.unwrap().cluster.unwrap();
    assert_eq!(report.removed, 1);
    assert!(statuses(a).is_empty());
    assert!(db.node(b.node_id()).is_none(), "row deleted");

    // It was only cut off: once reachable it is re-added (and re-inserted).
    net.heal(b.node_id());
    b.tick().await.unwrap();
    assert_eq!(statuses(a), vec![(b.node_id(), HeartbeatStatus::Online)]);
    let row = db.node(b.node_id()).unwrap();
    assert_eq!(
        (row.state, row.heartbeat),
        (NodeState::Active, HeartbeatStatus::Online)
    );
}

#[tokio::test]
async fn a_node_back_before_the_next_heartbeat_is_online_again() {
    let (net, db, clock, nodes) = started_cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    net.partition(b.node_id());
    clock.advance(BEAT + BEAT / 2);
    a.tick().await.unwrap();
    assert_eq!(
        db.node(b.node_id()).unwrap().heartbeat,
        HeartbeatStatus::Offline
    );

    net.heal(b.node_id());
    b.tick().await.unwrap(); // its heartbeat arrives in time
    assert_eq!(
        db.node(b.node_id()).unwrap().heartbeat,
        HeartbeatStatus::Online
    );
    clock.advance(BEAT);
    a.tick().await.unwrap();
    assert_eq!(statuses(a), vec![(b.node_id(), HeartbeatStatus::Online)]);
}

#[tokio::test]
async fn every_observer_tries_but_each_change_is_written_once() {
    let (net, db, clock, nodes) = started_cluster(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    net.partition(b.node_id());
    let writes = db.node_writes();
    round(&clock, &[a, c]).await; // A and C keep heartbeating; B is silent
    assert_eq!(db.node_writes(), writes, "one beat late is not missed yet");

    round(&clock, &[a, c]).await; // B missed one: both observers notice
    assert_eq!(
        db.node_writes(),
        writes + 1,
        "online → offline written once"
    );
    assert_eq!(
        db.node(b.node_id()).unwrap().heartbeat,
        HeartbeatStatus::Offline
    );

    round(&clock, &[a, c]).await; // and the next one
    assert_eq!(db.node_writes(), writes + 2, "deleted once");
    assert!(db.node(b.node_id()).is_none());
}

#[tokio::test]
async fn stale_registry_rows_from_crashed_processes_clean_themselves_up() {
    let clock = MockClock::new();
    let db = Arc::new(support::InMemoryDb::new(clock.clone()));
    let net = support::cluster::InMemoryNetwork::new();
    // A process that registered and then crashed: nothing answers for it.
    let ghost = NodeInfo {
        node_id: Uuid::new_v4(),
        service: "ghost".into(),
        ip: Some("127.0.0.9".parse().unwrap()),
        dns_name: None,
        port: 9999,
        version: "0".into(),
        started_at: clock.now(),
    };
    NodeRepository::register(db.as_ref(), &ghost).await.unwrap();

    let a = cluster_node(&net, &db, &clock, raw_config(), 9400);
    a.start().await.unwrap();
    assert!(db.node(ghost.node_id).is_some());
    clock.advance(BEAT + BEAT / 2);
    a.tick().await.unwrap();
    assert_eq!(
        db.node(ghost.node_id).unwrap().heartbeat,
        HeartbeatStatus::Offline
    );
    clock.advance(BEAT);
    a.tick().await.unwrap();
    assert!(db.node(ghost.node_id).is_none());
}

#[tokio::test]
async fn leaving_nodes_are_forgotten_and_removed() {
    let (_net, db, _clock, nodes) = started_cluster(2).await;
    nodes[1].shutdown().await.unwrap();
    assert!(statuses(&nodes[0]).is_empty());
    assert!(db.node(nodes[1].node_id()).is_none(), "leaving → removed");
}

// ── revocation: push, then enforce on first use ───────────────────────────────

#[tokio::test]
async fn revocations_reach_every_instance_immediately_and_are_enforced_on_use() {
    let (_net, db, clock, nodes) = started_cluster(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let (_, pair) = register_and_login(a, "a@example.com", IP_A).await;
    for n in [b, c] {
        n.verifier().verify(&pair.access_token).unwrap(); // A's key was distributed
    }

    a.revocation()
        .revoke(
            RevokeTarget::Session(pair.session_id),
            RevocationReason::Administrative,
        )
        .await
        .unwrap();
    // The session ended at once; the revocation is pending everywhere.
    let session = SessionRepository::find(db.as_ref(), pair.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.status, SessionStatus::Revoked);

    // Pushed — no tick, and verification never touches the store.
    let calls = db.calls();
    assert!(is_revoked(b, &pair.access_token));
    assert!(is_revoked(c, &pair.access_token));
    assert_eq!(db.calls(), calls, "no store access on verification");

    // B saw the token in use → its tick enforces the revocation.
    let report = b.tick().await.unwrap();
    assert_eq!(report.enforced, 1);
    let session = SessionRepository::find(db.as_ref(), pair.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.status, SessionStatus::Compromised);
    assert_eq!(session.end_reason, Some(RevocationReason::RevokedTokenUsed));

    // Everyone learned it is enforced; C's own hit loses the race.
    let now = clock.now();
    for n in [a, c] {
        let entries = n.denylist().entries(now);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, RevocationStatus::Enforced);
        assert_eq!(entries[0].enforced_by, Some(b.node_id()));
    }
    assert_eq!(c.tick().await.unwrap().enforced, 0);
    assert_eq!(
        db.revocation(a.denylist().entries(now)[0].id)
            .unwrap()
            .status,
        RevocationStatus::Enforced
    );
}

#[tokio::test]
async fn a_partitioned_node_repairs_itself_through_the_heartbeat_digest() {
    let (net, _db, _clock, nodes) = started_cluster(3).await;
    let (a, c) = (&nodes[0], &nodes[2]);
    let (_, pair) = register_and_login(a, "a@example.com", IP_A).await;

    net.partition(c.node_id());
    a.authentication().logout(&pair.access_token).await.unwrap();
    assert!(!is_revoked(c, &pair.access_token), "C missed the push");
    for _ in 0..5 {
        a.tick().await.unwrap(); // retries to C fail, then give up
    }

    net.heal(c.node_id());
    a.tick().await.unwrap(); // heartbeat digest ≠ C's → C wants a snapshot
    let report = c.tick().await.unwrap();
    assert!(report.cluster.unwrap().snapshots_merged >= 1);
    assert!(is_revoked(c, &pair.access_token));
}

#[tokio::test]
async fn events_from_a_node_peers_do_not_know_yet_are_retried_after_its_heartbeat() {
    let (net, db, clock, nodes) = started_cluster(1).await;
    let a = &nodes[0];

    // X joins while cut off, so A never hears its Join.
    let x = cluster_node(&net, &db, &clock, raw_config(), 9100);
    net.partition(x.node_id());
    x.start().await.unwrap();
    net.heal(x.node_id());

    let before = a.denylist().len();
    x.revocation()
        .revoke(
            RevokeTarget::User(Uuid::new_v4()),
            RevocationReason::Administrative,
        )
        .await
        .unwrap();
    assert_eq!(a.denylist().len(), before, "rejected: unknown sender");

    x.tick().await.unwrap(); // heartbeat introduces X, then the retry lands
    assert_eq!(a.denylist().len(), before + 1);
}

// ── message security ──────────────────────────────────────────────────────────

#[tokio::test]
async fn forged_replayed_and_stale_messages_are_rejected() {
    let (net, _db, clock, nodes) = started_cluster(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let rejected = |r: Result<Option<ClusterEnvelope>, AuthError>| {
        matches!(r, Err(AuthError::ClusterMessageRejected(_)))
    };

    // Forged: right shape, wrong MAC.
    let forged = ClusterEnvelope {
        message_id: Uuid::new_v4(),
        from: a.node_id(),
        sent_at: clock.now(),
        payload: auth_lib::cluster::ClusterMessage::SnapshotRequest,
        mac: "AAAA".into(),
    };
    assert!(rejected(b.cluster().unwrap().receive(forged).await));

    // Replayed: a genuine envelope delivered a second time.
    a.tick().await.unwrap();
    let (to, genuine) = net
        .log()
        .into_iter()
        .rev()
        .find(|(to, e)| e.from == a.node_id() && *to == b.node_id())
        .unwrap();
    assert_eq!(to, b.node_id());
    assert!(rejected(
        b.cluster().unwrap().receive(genuine.clone()).await
    ));

    // Tampered: genuine MAC, altered payload.
    let mut tampered = genuine.clone();
    tampered.message_id = Uuid::new_v4();
    assert!(rejected(c.cluster().unwrap().receive(tampered).await));

    // Stale: genuine, unseen by C, but older than the skew window.
    clock.advance(Duration::from_secs(31));
    assert!(rejected(c.cluster().unwrap().receive(genuine).await));
}

// ── keys ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn verifying_keys_are_distributed_and_signing_keys_revoked_everywhere() {
    let (net, db, clock, nodes) = started_cluster(1).await;
    let b = &nodes[0];

    // A has its own signing key; B does not know it before A starts.
    let a = cluster_node(&net, &db, &clock, raw_config(), 9200);
    let (_, pair) = register_and_login(&a, "a@example.com", IP_A).await;
    assert!(matches!(
        b.verifier().verify(&pair.access_token),
        Err(AuthError::InvalidToken(_))
    ));
    a.start().await.unwrap(); // publishes A's verifying key
    b.verifier().verify(&pair.access_token).unwrap();

    // Revoke A's signing key: every token it signed dies everywhere.
    let kid = a
        .keys()
        .keys()
        .into_iter()
        .find(|k| k.published_by == Some(a.node_id()))
        .unwrap()
        .kid;
    assert!(a.keys().revoke_signing_key(&kid).await.unwrap());
    for n in [&a, b] {
        assert!(matches!(
            n.verifier().verify(&pair.access_token),
            Err(AuthError::InvalidToken(m)) if m.contains("revoked")
        ));
    }
    // …and A refuses to mint with it.
    let err = a
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::Config(_)), "got {err:?}");
}

// ── catalog ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn catalog_changes_are_pushed_to_every_instance() {
    let clock = MockClock::new();
    let db = Arc::new(support::InMemoryDb::new(clock.clone()));
    let net = support::cluster::InMemoryNetwork::new();
    let cfg = || raw_config().authz_mode("permissions");
    let a = cluster_node(&net, &db, &clock, cfg(), 9301);
    let b = cluster_node(&net, &db, &clock, cfg(), 9302);
    a.start().await.unwrap();
    b.start().await.unwrap();

    a.permissions()
        .define(&NewPermission {
            code: "reports.view".into(),
            kind: PermissionKind::Bool,
            description: None,
            options: vec![],
        })
        .await
        .unwrap();
    let catalog = b.permissions().catalog().unwrap();
    assert!(catalog.permissions.iter().any(|p| p.code == "reports.view"));
}
