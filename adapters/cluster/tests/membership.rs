//! Federation mode — membership: seeds, per-cluster registry, liveness
//! (healthy → warning → missing), eviction with the registry as witness,
//! self-fencing, and single links between clusters with retry, circuit
//! breaker and failover.

#![cfg(feature = "federation")]

mod support;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use support::cluster::*;
use support::federation::*;
use support::*;
use uuid::Uuid;
use z_auth::prelude::*;
use z_auth_cluster::prelude::*;

fn cluster_of(n: &Node) -> &Arc<FederationClusterService> {
    n.federation_cluster().expect("federation mode")
}

fn sibling_ids(n: &Node) -> HashSet<Uuid> {
    let me = n.cluster().unwrap().local().service;
    n.cluster()
        .unwrap()
        .peers()
        .into_iter()
        .filter(|p| p.info.service == me)
        .map(|p| p.info.node_id)
        .collect()
}

fn heartbeat_of(n: &Node, id: Uuid) -> Option<HeartbeatStatus> {
    n.cluster()
        .unwrap()
        .peers()
        .into_iter()
        .find(|p| p.info.node_id == id)
        .map(|p| p.heartbeat)
}

/// ums ×2 (no seeds) ← orders ×2 (seed: ums) ← billing ×1 (seed: orders).
async fn three_clusters() -> World {
    let mut w = World::new();
    w.add("ums", 9100, &[]).await;
    w.add("ums", 9101, &[]).await;
    w.add("orders", 9200, &[9100]).await;
    w.add("orders", 9201, &[9100]).await;
    w.add("billing", 9300, &[9200]).await;
    w.rounds(2).await;
    w
}

// ── Bootstrap and registry ───────────────────────────────────────────────────

#[tokio::test]
async fn one_seed_is_enough_mesh_inside_single_link_between() {
    let w = three_clusters().await;

    for c in &w.clusters {
        for n in &c.nodes {
            let others: HashSet<Uuid> = c
                .nodes
                .iter()
                .map(|x| x.node_id())
                .filter(|id| *id != n.node_id())
                .collect();
            assert_eq!(sibling_ids(n), others, "{}: full mesh inside", c.name);
            let mut known = cluster_of(n).remote_clusters();
            known.sort();
            let mut expected: Vec<String> = w
                .clusters
                .iter()
                .filter(|o| o.name != c.name)
                .map(|o| o.name.to_string())
                .collect();
            expected.sort();
            assert_eq!(known, expected, "{}: every other cluster is known", c.name);
        }
    }

    // One round: exactly one sender per (from-cluster, to-cluster) pair.
    w.network.clear_log();
    w.rounds(1).await;
    let service = w.service_of();
    let mut senders: HashMap<(&str, &str), HashSet<Uuid>> = HashMap::new();
    for (to, env) in w.network.log() {
        if let ClusterMessage::LinkHeartbeat(_) = env.payload
            && let (Some(from_c), Some(to_c)) = (service.get(&env.from), service.get(&to))
            && from_c != to_c
        {
            senders.entry((from_c, to_c)).or_default().insert(env.from);
        }
    }
    assert_eq!(
        senders.len(),
        6,
        "every ordered pair of clusters has a link"
    );
    for (pair, from) in &senders {
        assert_eq!(from.len(), 1, "{pair:?}: a single link, not a mesh");
    }
    // Siblings agree on the owner.
    for c in &w.clusters {
        for other in w.clusters.iter().filter(|o| o.name != c.name) {
            let owners: HashSet<Option<Uuid>> = c
                .nodes
                .iter()
                .map(|n| cluster_of(n).link_owner(other.name))
                .collect();
            assert_eq!(owners.len(), 1, "{} → {}", c.name, other.name);
        }
    }
}

#[tokio::test]
async fn registry_is_read_only_when_empty_and_written_only_on_changes() {
    let mut w = three_clusters().await;
    let orders = w.cluster("orders").db.clone();
    assert_eq!(
        orders.node_reads(),
        2,
        "each instance read it once, at start"
    );
    // register + activate, per instance.
    assert_eq!(orders.node_writes(), 4);

    w.rounds(5).await;
    assert_eq!(orders.node_reads(), 2, "no reads while running");
    assert_eq!(orders.node_writes(), 4, "heartbeats never write");

    // A new instance writes itself and reads once; the others learn about
    // it directly, without reading.
    let third = w.add("orders", 9202, &[9100]).await;
    assert_eq!(orders.node_reads(), 3);
    assert_eq!(orders.node_writes(), 6);
    w.rounds(1).await;
    for n in &w.cluster("orders").nodes {
        if n.node_id() != third.node_id() {
            assert!(sibling_ids(n).contains(&third.node_id()));
        }
    }
    assert_eq!(orders.node_reads(), 3);
    // The other clusters' registries know nothing about orders.
    assert!(
        w.cluster("ums")
            .db
            .nodes()
            .iter()
            .all(|r| r.info.service == "ums")
    );
}

#[tokio::test]
async fn address_change_is_stored_and_announced() {
    let w = three_clusters().await;
    let orders = w.cluster("orders");
    let (a, b) = (&orders.nodes[0], &orders.nodes[1]);
    let reads = orders.db.node_reads();
    cluster_of(a)
        .update_address(None, Some("orders-a.internal".into()), 9999)
        .await
        .unwrap();
    let row = orders.db.node(a.node_id()).unwrap();
    assert_eq!(row.info.dns_name.as_deref(), Some("orders-a.internal"));
    assert_eq!(row.info.port, 9999);
    let seen_by_b = b
        .cluster()
        .unwrap()
        .peers()
        .into_iter()
        .find(|p| p.info.node_id == a.node_id())
        .unwrap();
    assert_eq!(seen_by_b.info.port, 9999, "announced directly");
    assert_eq!(orders.db.node_reads(), reads, "without a registry read");
}

// ── Liveness ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn one_missed_beat_is_a_warning_and_the_next_beat_repairs_it() {
    let w = three_clusters().await;
    let orders = w.cluster("orders");
    let (a, b) = (orders.nodes[0].clone(), orders.nodes[1].clone());

    w.network.partition_pair(a.node_id(), b.node_id());
    // 1.5 beats of silence.
    w.clock.advance(BEAT);
    w.clock.advance(BEAT / 2);
    a.tick().await.unwrap();
    assert_eq!(
        heartbeat_of(&a, b.node_id()),
        Some(HeartbeatStatus::Offline)
    );
    assert_eq!(
        orders.db.node(b.node_id()).unwrap().heartbeat,
        HeartbeatStatus::Offline,
        "warning stored in the cluster's database"
    );

    w.network.heal_pair(a.node_id(), b.node_id());
    b.tick().await.unwrap();
    assert_eq!(heartbeat_of(&a, b.node_id()), Some(HeartbeatStatus::Online));
    assert_eq!(
        orders.db.node(b.node_id()).unwrap().heartbeat,
        HeartbeatStatus::Online
    );
    assert!(!a.is_fenced() && !b.is_fenced());
}

#[tokio::test]
async fn a_missing_instance_is_evicted_retired_and_fences_itself() {
    let mut w = World::new();
    w.add("ums", 9100, &[]).await;
    let (a, b, c) = (
        w.add("ums", 9101, &[]).await,
        w.add("ums", 9102, &[]).await,
        w.add("ums", 9103, &[]).await,
    );
    w.rounds(1).await;
    let ums_db = w.cluster("ums").db.clone();

    // c is cut off from its siblings (the database is still reachable).
    for other in w
        .cluster("ums")
        .nodes
        .iter()
        .filter(|n| n.node_id() != c.node_id())
    {
        w.network.partition_pair(c.node_id(), other.node_id());
    }
    let majority: Vec<Arc<Node>> = w
        .cluster("ums")
        .nodes
        .iter()
        .filter(|n| n.node_id() != c.node_id())
        .cloned()
        .collect();
    // Everyone keeps ticking every beat, c on its own side of the cut.
    let all = w.cluster("ums").nodes.clone();
    w.round_of(&all).await; // 2 s silent: nothing yet
    w.round_of(&all).await; // 4 s: warning
    w.round_of(&all).await; // 6 s: missing — the majority evicts first
    assert_eq!(
        ums_db.node(c.node_id()).unwrap().heartbeat,
        HeartbeatStatus::Missing,
        "evicted by the majority"
    );
    for n in &majority {
        assert!(cluster_of(n).retired().contains(&c.node_id()));
        assert!(!sibling_ids(n).contains(&c.node_id()));
        assert!(!n.is_fenced());
    }
    // c, alone against three, waited for them; now it loses at the registry.
    w.round_of(&all).await;
    assert!(c.is_fenced(), "the registry says it is missing");
    assert_eq!(w.fenced.load(Ordering::SeqCst), 1, "hook called once");
    w.round_of(&all).await;
    assert_eq!(w.fenced.load(Ordering::SeqCst), 1);

    // A fenced instance serves nothing.
    assert!(matches!(
        c.verifier().verify("whatever"),
        Err(AuthError::NodeFenced)
    ));
    assert!(matches!(
        c.authentication().refresh("a", "b", ctx(IP_A)).await,
        Err(AuthError::NodeFenced)
    ));
    let proof = SecondFactorProof {
        challenge_token: "mfa1.x.y".into(),
        method: None,
        code: "123456".into(),
    };
    assert!(matches!(
        c.authentication().complete_login(proof, ctx(IP_A)).await,
        Err(AuthError::NodeFenced)
    ));
    let _ = (a, b);
}

#[tokio::test]
async fn frozen_instance_that_missed_the_eviction_notice_fences_on_retired_reply() {
    let mut w = World::new();
    let a = w.add("ums", 9100, &[]).await;
    let b = w.add("ums", 9101, &[]).await;
    let c = w.add("ums", 9102, &[]).await;
    w.rounds(1).await;

    w.network.partition(c.node_id());
    for _ in 0..3 {
        w.round_of(&[a.clone(), b.clone()]).await;
    }
    assert!(cluster_of(&a).retired().contains(&c.node_id()));
    assert!(!c.is_fenced(), "it did not hear about it");
    w.network.heal(c.node_id());
    c.tick().await.unwrap();
    assert!(c.is_fenced(), "its heartbeats are answered with Retired");
}

#[tokio::test]
async fn other_clusters_never_evict() {
    let w = three_clusters().await;
    let billing = w.cluster("billing").nodes[0].clone();
    let orders: Vec<Uuid> = w
        .cluster("orders")
        .nodes
        .iter()
        .map(|n| n.node_id())
        .collect();
    w.network.partition_groups(&[billing.node_id()], &orders);
    w.rounds(10).await;
    for id in &orders {
        let row = w.cluster("orders").db.node(*id).unwrap();
        assert_ne!(row.heartbeat, HeartbeatStatus::Missing);
    }
    assert!(w.all().iter().all(|n| !n.is_fenced()));
}

#[tokio::test]
async fn partition_three_two_only_the_minority_fences() {
    let mut w = World::new();
    for port in 9100..9105 {
        w.add("ums", port, &[]).await;
    }
    w.rounds(1).await;
    let nodes = w.cluster("ums").nodes.clone();
    let (left, right) = nodes.split_at(3);
    let ids = |ns: &[Arc<Node>]| ns.iter().map(|n| n.node_id()).collect::<Vec<_>>();
    w.network.partition_groups(&ids(left), &ids(right));
    w.rounds(5).await;
    assert!(
        left.iter().all(|n| !n.is_fenced()),
        "majority keeps serving"
    );
    assert!(right.iter().all(|n| n.is_fenced()), "minority fences");
    w.network.heal_all();
    w.rounds(2).await;
    assert!(
        left.iter().all(|n| !n.is_fenced()),
        "no eviction storm on heal"
    );
}

#[tokio::test]
async fn even_split_the_side_with_the_lowest_id_survives() {
    let mut w = World::new();
    for port in 9100..9104 {
        w.add("ums", port, &[]).await;
    }
    w.rounds(1).await;
    let mut nodes = w.cluster("ums").nodes.clone();
    nodes.sort_by_key(|n| n.node_id());
    // The lowest id is on the left.
    let left = vec![nodes[0].clone(), nodes[3].clone()];
    let right = vec![nodes[1].clone(), nodes[2].clone()];
    let ids = |ns: &[Arc<Node>]| ns.iter().map(|n| n.node_id()).collect::<Vec<_>>();
    w.network.partition_groups(&ids(&left), &ids(&right));
    w.rounds(5).await;
    assert!(left.iter().all(|n| !n.is_fenced()));
    assert!(right.iter().all(|n| n.is_fenced()));
}

#[tokio::test]
async fn two_instances_survive_a_crash_of_either_one() {
    for crash_lowest in [true, false] {
        let mut w = World::new();
        let x = w.add("ums", 9100, &[]).await;
        let y = w.add("ums", 9101, &[]).await;
        w.rounds(1).await;
        let (low, high) = if x.node_id() < y.node_id() {
            (x, y)
        } else {
            (y, x)
        };
        let (crashed, survivor) = if crash_lowest {
            (low, high)
        } else {
            (high, low)
        };
        w.network.detach(crashed.node_id());
        for _ in 0..5 {
            w.round_of(std::slice::from_ref(&survivor)).await;
        }
        assert!(
            !survivor.is_fenced(),
            "the registry lets the survivor evict (crash_lowest = {crash_lowest})"
        );
        assert!(cluster_of(&survivor).retired().contains(&crashed.node_id()));
    }
}

#[tokio::test]
async fn a_single_instance_cluster_never_fences() {
    let w = three_clusters().await;
    let billing = w.cluster("billing").nodes[0].clone();
    w.network.partition(billing.node_id());
    for _ in 0..20 {
        w.round_of(std::slice::from_ref(&billing)).await;
    }
    assert!(!billing.is_fenced());
}

// ── Links between clusters ───────────────────────────────────────────────────

fn owner_of(w: &World, from: &str, to: &str) -> Arc<Node> {
    let c = w.cluster(from);
    let id = cluster_of(&c.nodes[0]).link_owner(to).expect("an owner");
    c.nodes.iter().find(|n| n.node_id() == id).unwrap().clone()
}

#[tokio::test]
async fn the_owner_moves_to_another_target_when_one_fails() {
    let w = three_clusters().await;
    let owner = owner_of(&w, "ums", "orders");
    let orders: Vec<Uuid> = w
        .cluster("orders")
        .nodes
        .iter()
        .map(|n| n.node_id())
        .collect();
    // Cut the owner from one orders instance.
    w.network.partition_pair(owner.node_id(), orders[0]);
    w.network.clear_log();
    w.rounds(4).await;
    assert!(!cluster_of(&owner).is_cluster_dead("orders"));
    assert_eq!(
        cluster_of(&owner).link_owner("orders"),
        Some(owner.node_id())
    );
    let reached: HashSet<Uuid> = w
        .network
        .log()
        .into_iter()
        .filter(|(to, env)| {
            env.from == owner.node_id()
                && matches!(env.payload, ClusterMessage::LinkHeartbeat(_))
                && orders.contains(to)
        })
        .map(|(to, _)| to)
        .collect();
    assert_eq!(reached, HashSet::from([orders[1]]));
}

#[tokio::test]
async fn the_link_is_handed_over_to_the_next_sibling() {
    let w = three_clusters().await;
    let owner = owner_of(&w, "ums", "orders");
    let orders: Vec<Uuid> = w
        .cluster("orders")
        .nodes
        .iter()
        .map(|n| n.node_id())
        .collect();
    w.network.partition_groups(&[owner.node_id()], &orders);
    // Breakers open after 3 failed requests (one per round).
    w.rounds(4).await;
    let next = cluster_of(&owner)
        .link_owner("orders")
        .expect("a new owner");
    assert_ne!(next, owner.node_id(), "handed over");
    for n in &w.cluster("ums").nodes {
        assert_eq!(cluster_of(n).link_owner("orders"), Some(next));
        assert!(!cluster_of(n).is_cluster_dead("orders"));
    }
    assert!(w.all().iter().all(|n| !n.is_fenced()));
}

#[tokio::test]
async fn unreachable_cluster_is_marked_dead_then_recovers() {
    let w = three_clusters().await;
    let ums: Vec<Uuid> = w.cluster("ums").nodes.iter().map(|n| n.node_id()).collect();
    let orders: Vec<Uuid> = w
        .cluster("orders")
        .nodes
        .iter()
        .map(|n| n.node_id())
        .collect();
    w.network.partition_groups(&ums, &orders);
    w.rounds(10).await;
    for n in &w.cluster("ums").nodes {
        assert!(
            cluster_of(n).is_cluster_dead("orders"),
            "all ums instances tried"
        );
    }
    for n in &w.cluster("orders").nodes {
        assert!(cluster_of(n).is_cluster_dead("ums"));
    }
    assert!(
        w.all().iter().all(|n| !n.is_fenced()),
        "nobody fences over it"
    );
    assert!(!cluster_of(&w.cluster("ums").nodes[0]).is_cluster_dead("billing"));

    w.network.heal_all();
    // Re-probed every AUTH_LINK_DEAD_REPROBE_SECS (60 s).
    w.rounds(32).await;
    for n in &w.cluster("ums").nodes {
        assert!(!cluster_of(n).is_cluster_dead("orders"));
    }
    for n in &w.cluster("orders").nodes {
        assert!(!cluster_of(n).is_cluster_dead("ums"));
    }
}

#[tokio::test]
async fn events_cross_every_cluster_through_the_links() {
    let w = three_clusters().await;
    let billing = w.cluster("billing").nodes[0].clone();
    let user = Uuid::new_v4();
    billing
        .revocation()
        .end_all_for_user(user, RevocationReason::Administrative)
        .await
        .unwrap();
    let now = w.clock.now();
    for n in w.all() {
        let denied = n
            .denylist()
            .entries(now)
            .iter()
            .any(|r| r.scope == RevocationScope::User(user));
        assert!(
            denied,
            "instance of {} got it",
            n.cluster().unwrap().local().service
        );
    }
}

#[tokio::test]
async fn mode_must_match_the_extension() {
    let db = Arc::new(InMemoryDb::new(MockClock::new()));
    let cluster = || {
        RawClusterConfig::default()
            .authority_service("ums")
            .cluster_service("ums")
            .cluster_secret(CLUSTER_SECRET)
            .cluster_advertise_ip("127.0.0.1")
            .cluster_advertise_port(1)
    };
    let adapters = || ClusterAdapters {
        transport: InMemoryNetwork::new(),
        nodes: db.clone(),
        sync_store: None,
        delay: None,
        on_fenced: None,
    };
    let config = || raw_config().build().unwrap();

    // The federation extension refuses an explicit other mode.
    let shared_mode = cluster().deployment_mode("shared").build().unwrap();
    let federation = Arc::new(Federation::new(
        shared_mode,
        InMemoryNetwork::new(),
        db.clone(),
        db.clone(),
    ));
    assert!(matches!(
        ZAuth::builder(config(), repositories(&db))
            .extension(federation)
            .build(),
        Err(AuthError::Config(_))
    ));
    // So does the shared one.
    let federation_mode = cluster().deployment_mode("federation").build().unwrap();
    assert!(matches!(
        ZAuth::builder(config(), repositories(&db))
            .extension(Arc::new(SharedCluster::new(
                federation_mode.clone(),
                InMemoryNetwork::new(),
                db.clone()
            )))
            .build(),
        Err(AuthError::Config(_))
    ));
    // Picking by configuration: unset → shared, standalone → no cluster,
    // federation without a sync store → an error.
    let unset = cluster().build().unwrap();
    assert_eq!(
        z_auth_cluster::Cluster::new(unset, adapters())
            .unwrap()
            .mode(),
        DeploymentMode::Shared
    );
    let standalone = cluster().deployment_mode("standalone").build().unwrap();
    assert!(matches!(
        z_auth_cluster::Cluster::new(standalone, adapters()),
        Err(AuthError::Config(_))
    ));
    assert!(matches!(
        z_auth_cluster::Cluster::new(federation_mode, adapters()),
        Err(AuthError::Config(_))
    ));
}
