//! Federation mode — database per service: the authority (`ums`) owns
//! identity, `orders` and `billing` keep session stores, and session state
//! syncs between all three.

#![cfg(feature = "federation")]

mod support;

use std::sync::Arc;
use std::time::Duration;

use z_auth::prelude::*;
use z_auth::security::authorization::PermissionKind;
use z_auth_cluster::federation::SessionAggregate;
use support::cluster::Node;
use support::federation::*;
use support::*;

const ACCESS_TTL: Duration = Duration::from_secs(300);

/// ums ×2 ← orders ×2 (seed: ums) ← billing ×1 (seed: orders).
async fn three_with(configure: fn(RawConfig) -> RawConfig) -> World {
    let mut w = World::new();
    w.add_with("ums", 9100, &[], configure).await;
    w.add_with("ums", 9101, &[], configure).await;
    w.add_with("orders", 9200, &[9100], configure).await;
    w.add_with("orders", 9201, &[9100], configure).await;
    w.add_with("billing", 9300, &[9200], configure).await;
    w.rounds(2).await;
    w
}

async fn three() -> World {
    three_with(|c| c).await
}

/// Register and log in at the authority.
async fn login(w: &World, email: &str) -> (User, TokenPair) {
    register_and_login(&w.node(AUTHORITY), email, IP_A).await
}

async fn refresh_at(
    node: &ZAuth,
    pair: &TokenPair,
    ip: std::net::IpAddr,
) -> Result<TokenPair, AuthError> {
    node.authentication()
        .refresh(&pair.access_token, &pair.refresh_token, ctx(ip))
        .await
}

async fn settle(w: &World) {
    w.rounds(4).await;
}

fn stored(w: &World, cluster: &str, sid: uuid::Uuid) -> Option<SessionAggregate> {
    w.cluster(cluster)
        .db
        .session_aggregates()
        .into_iter()
        .find(|a| a.session.id == sid)
}

fn status_everywhere(w: &World, sid: uuid::Uuid) -> Vec<SessionStatus> {
    w.clusters
        .iter()
        .filter_map(|c| stored(w, c.name, sid).map(|a| a.session.status))
        .collect()
}

// ── Identity belongs to the authority ────────────────────────────────────────

#[tokio::test]
async fn identity_writes_are_refused_outside_the_authority() {
    let w = three().await;
    let orders = w.node("orders");
    let not_authority = |e: AuthError| match e {
        AuthError::NotAuthority { service, addresses } => {
            assert_eq!(service, AUTHORITY);
            assert_eq!(addresses.len(), 2, "both ums instances named");
            true
        }
        _ => false,
    };
    let err = orders
        .users()
        .register(register_request("a@example.com", None))
        .await
        .unwrap_err();
    assert_eq!(ApiError::from(AuthError::ReplicaBehind).status, 503);
    let api = ApiError::from(match &err {
        AuthError::NotAuthority { service, addresses } => AuthError::NotAuthority {
            service: service.clone(),
            addresses: addresses.clone(),
        },
        _ => panic!("{err:?}"),
    });
    assert_eq!((api.status, api.code), (421, "not_authority"));
    assert!(not_authority(err));
    assert!(not_authority(
        orders
            .authentication()
            .login(credentials("a@example.com"), ctx(IP_A))
            .await
            .unwrap_err()
    ));
    assert!(not_authority(
        orders
            .users()
            .deactivate(uuid::Uuid::new_v4())
            .await
            .unwrap_err()
    ));
    assert!(not_authority(
        orders.roles().create(&new_role("Admin")).await.unwrap_err()
    ));
}

#[tokio::test]
async fn session_stores_keep_sessions_and_snapshots_but_no_users() {
    let w = three().await;
    let (user, pair) = login(&w, "a@example.com").await;
    settle(&w).await;
    assert_eq!(w.cluster(AUTHORITY).db.user_count(), 1);
    for store in ["orders", "billing"] {
        let db = &w.cluster(store).db;
        assert_eq!(db.user_count(), 0, "{store}: no users, no password hashes");
        let account = db.account(user.id).expect("account snapshot");
        assert!(account.is_active && !account.deleted);
        assert!(db.has_session(pair.session_id), "{store}: session synced");
    }
}

// ── Refresh anywhere ─────────────────────────────────────────────────────────

#[tokio::test]
async fn refresh_works_at_every_service_and_rotations_sync() {
    let w = three().await;
    let (_, first) = login(&w, "a@example.com").await;
    settle(&w).await;
    w.clock.advance(ACCESS_TTL);

    let second = refresh_at(&w.node("orders"), &first, IP_A).await.unwrap();
    for n in w.all() {
        n.verifier()
            .verify(&second.access_token)
            .expect("verifies everywhere");
    }
    settle(&w).await;
    w.clock.advance(ACCESS_TTL);
    let third = refresh_at(&w.node("billing"), &second, IP_A).await.unwrap();
    settle(&w).await;
    for c in &w.clusters {
        let a = stored(&w, c.name, first.session_id).unwrap();
        assert_eq!(a.session.current_generation, 3, "{}", c.name);
        assert_eq!(a.session.status, SessionStatus::Active);
    }
    // The old pair is now reuse — wherever it is presented.
    w.clock.advance(Duration::from_secs(60));
    assert!(matches!(
        refresh_at(&w.node("ums"), &second, IP_A).await,
        Err(AuthError::SessionCompromised)
    ));
    settle(&w).await;
    assert!(
        status_everywhere(&w, first.session_id)
            .iter()
            .all(|s| *s == SessionStatus::Compromised)
    );
    assert!(
        w.node("orders")
            .verifier()
            .verify(&third.access_token)
            .is_err()
    );
}

#[tokio::test]
async fn refresh_right_after_login_elsewhere_fetches_the_session() {
    let w = three().await;
    let (_, first) = login(&w, "a@example.com").await;
    // No sync round yet: orders has neither the session nor the account.
    assert!(!w.cluster("orders").db.has_session(first.session_id));
    let next = refresh_at(&w.node("orders"), &first, IP_A)
        .await
        .expect("pulled on miss");
    w.node("billing")
        .verifier()
        .verify(&next.access_token)
        .unwrap();
}

#[tokio::test]
async fn a_generation_not_synced_yet_is_retryable_never_theft() {
    let w = three().await;
    let (_, first) = login(&w, "a@example.com").await;
    settle(&w).await;
    let second = refresh_at(&w.node("orders"), &first, IP_A).await.unwrap();

    // Billing can reach neither orders nor (yet) a ums that has it.
    let billing = w.node("billing");
    let orders: Vec<_> = w
        .cluster("orders")
        .nodes
        .iter()
        .map(|n| n.node_id())
        .collect();
    w.network.partition_groups(&[billing.node_id()], &orders);
    let err = refresh_at(&billing, &second, IP_A).await.unwrap_err();
    assert!(matches!(err, AuthError::ReplicaBehind), "{err:?}");
    assert_eq!(ApiError::from(err).status, 503);
    assert_eq!(
        stored(&w, "billing", first.session_id)
            .unwrap()
            .session
            .status,
        SessionStatus::Active,
        "not compromised"
    );

    w.network.heal_all();
    settle(&w).await;
    refresh_at(&billing, &second, IP_A)
        .await
        .expect("synced now");
}

// ── Forks: two services rotate the same generation ───────────────────────────

#[tokio::test]
async fn a_benign_fork_converges_and_the_loser_refreshes_once_into_the_winner() {
    let w = three().await;
    let (_, first) = login(&w, "a@example.com").await;
    settle(&w).await;
    w.clock.advance(ACCESS_TTL);
    // The client retries at another service before the first one synced.
    let a = refresh_at(&w.node("orders"), &first, IP_A).await.unwrap();
    let b = refresh_at(&w.node("billing"), &first, IP_A).await.unwrap();
    assert_ne!(a.access_token, b.access_token);
    assert_eq!(
        a.refresh_token, b.refresh_token,
        "refresh tokens are deterministic"
    );
    settle(&w).await;

    let agg = stored(&w, AUTHORITY, first.session_id).unwrap();
    assert_eq!(agg.session.status, SessionStatus::Active);
    let g2 = agg.generations.iter().find(|g| g.generation == 2).unwrap();
    assert_eq!(g2.variants.len(), 2);
    for c in &w.clusters {
        assert_eq!(
            stored(&w, c.name, first.session_id).as_ref(),
            Some(&agg),
            "{}",
            c.name
        );
    }
    // The loser's access token is refused everywhere; the winner's is not.
    let (winner, loser) = if g2.variants[0].access_jti
        == w.node("orders")
            .verifier()
            .verify(&a.access_token)
            .map(|c| c.jti)
            .unwrap_or_default()
    {
        (a, b)
    } else {
        (b, a)
    };
    for n in w.all() {
        let svc = n.cluster().unwrap().local().service;
        let r = n.verifier().verify(&loser.access_token);
        assert!(matches!(r, Err(AuthError::TokenRevoked)), "{svc}: {r:?}");
        n.verifier().verify(&winner.access_token).unwrap();
    }
    // Its holder refreshes into the winning chain.
    let next = refresh_at(&w.node("ums"), &loser, IP_A)
        .await
        .expect("alias accepted");
    w.node("billing")
        .verifier()
        .verify(&next.access_token)
        .unwrap();
    for n in w.all() {
        assert_eq!(
            n.federation().unwrap().report().refused,
            Vec::<String>::new()
        );
    }
}

#[tokio::test]
async fn a_fork_from_another_client_compromises_the_session_everywhere() {
    let w = three().await;
    let (_, first) = login(&w, "a@example.com").await;
    settle(&w).await;
    w.clock.advance(ACCESS_TTL);
    let a = refresh_at(&w.node("orders"), &first, IP_A).await.unwrap();
    let b = refresh_at(&w.node("billing"), &first, IP_B).await.unwrap();
    settle(&w).await;
    assert_eq!(
        status_everywhere(&w, first.session_id),
        vec![SessionStatus::Compromised; 3]
    );
    for n in w.all() {
        assert!(n.verifier().verify(&a.access_token).is_err());
        assert!(n.verifier().verify(&b.access_token).is_err());
    }
    assert!(refresh_at(&w.node("ums"), &a, IP_A).await.is_err());
}

#[tokio::test]
async fn fork_criteria_follow_the_configuration() {
    // Match on the device fingerprint only: another network is still a retry.
    let w = three_with(|c| c.refresh_retry_match("fingerprint")).await;
    let ums = w.node(AUTHORITY);
    register(&ums, "a@example.com").await;
    let device = |ip| ctx(ip).with_fingerprint("device-1");
    let first = ums
        .authentication()
        .login(credentials("a@example.com"), device(IP_A))
        .await
        .unwrap();
    settle(&w).await;
    w.clock.advance(ACCESS_TTL);
    let refresh = |node: Arc<Node>, ip| {
        let pair = first.clone();
        async move {
            node.authentication()
                .refresh(&pair.access_token, &pair.refresh_token, device(ip))
                .await
        }
    };
    refresh(w.node("orders"), IP_A).await.unwrap();
    refresh(w.node("billing"), IP_B).await.unwrap();
    settle(&w).await;
    assert_eq!(
        status_everywhere(&w, first.session_id),
        vec![SessionStatus::Active; 3],
        "same device"
    );
}

// ── Revocation anywhere ──────────────────────────────────────────────────────

#[tokio::test]
async fn logout_at_a_session_store_blocks_everywhere_at_once() {
    let w = three().await;
    let (_, pair) = login(&w, "a@example.com").await;
    settle(&w).await;
    assert!(
        w.node("billing")
            .authentication()
            .logout(&pair.access_token)
            .await
            .unwrap()
    );
    // Immediately, through the event relay.  (Presenting the token would
    // count as theft and compromise the session, so only look.)
    let now = w.clock.now();
    for n in w.all() {
        assert!(
            n.denylist()
                .entries(now)
                .iter()
                .any(|r| r.scope == RevocationScope::Session(pair.session_id))
        );
    }
    settle(&w).await;
    assert_eq!(
        status_everywhere(&w, pair.session_id),
        vec![SessionStatus::Revoked; 3]
    );
    assert!(refresh_at(&w.node("orders"), &pair, IP_A).await.is_err());
}

#[tokio::test]
async fn deactivation_at_the_authority_ends_sessions_everywhere() {
    let w = three().await;
    let (user, pair) = login(&w, "a@example.com").await;
    settle(&w).await;
    w.node(AUTHORITY).users().deactivate(user.id).await.unwrap();
    settle(&w).await;
    for c in ["orders", "billing"] {
        assert!(!w.cluster(c).db.account(user.id).unwrap().is_active);
        assert_ne!(
            stored(&w, c, pair.session_id).unwrap().session.status,
            SessionStatus::Active
        );
    }
    w.clock.advance(ACCESS_TTL);
    assert!(refresh_at(&w.node("orders"), &pair, IP_A).await.is_err());
}

#[tokio::test]
async fn role_changes_reach_tokens_refreshed_elsewhere() {
    let w = three().await;
    let ums = w.node(AUTHORITY);
    let admin = ums.roles().create(&new_role("Admin")).await.unwrap();
    let (user, first) = login(&w, "a@example.com").await;
    ums.roles().assign(user.id, admin.id).await.unwrap();
    settle(&w).await;
    let next = refresh_at(&w.node("orders"), &first, IP_A).await.unwrap();
    let billing = w.node("billing");
    let claims = billing.verifier().verify(&next.access_token).unwrap();
    assert!(billing.authorizer().has_role(&claims, &admin.code));

    ums.roles().delete(admin.id).await.unwrap();
    settle(&w).await;
    w.clock.advance(ACCESS_TTL);
    let later = refresh_at(&billing, &next, IP_A).await.unwrap();
    let claims = billing.verifier().verify(&later.access_token).unwrap();
    assert!(
        !billing.authorizer().has_role(&claims, &admin.code),
        "holders republished"
    );
}

#[tokio::test]
async fn permissions_and_the_catalog_reach_session_stores() {
    let w = three_with(|c| c.authz_mode("permissions")).await;
    let ums = w.node(AUTHORITY);
    let (user, first) = login(&w, "a@example.com").await;
    ums.permissions()
        .define(&NewPermission {
            code: "reports.view".into(),
            kind: PermissionKind::Bool,
            description: None,
            options: vec![],
        })
        .await
        .unwrap();
    ums.permissions()
        .grant_to_user(user.id, "reports.view", &PermissionValue::Allow)
        .await
        .unwrap();
    settle(&w).await;
    let billing = w.node("billing");
    assert_eq!(
        billing.permissions().catalog().unwrap().permissions.len(),
        1
    );
    assert!(
        billing
            .permissions()
            .define(&NewPermission {
                code: "x".into(),
                kind: PermissionKind::Bool,
                description: None,
                options: vec![],
            })
            .await
            .is_err()
    );
    let next = refresh_at(&w.node("orders"), &first, IP_A).await.unwrap();
    let claims = billing.verifier().verify(&next.access_token).unwrap();
    assert!(
        billing
            .authorizer()
            .permissions(&claims)
            .allowed("reports.view")
    );
}

// ── Sync mechanics ───────────────────────────────────────────────────────────

#[tokio::test]
async fn nothing_bounces_between_clusters() {
    let w = three().await;
    let (_, first) = login(&w, "a@example.com").await;
    login(&w, "b@example.com").await;
    w.clock.advance(ACCESS_TTL);
    refresh_at(&w.node("orders"), &first, IP_A).await.unwrap();
    settle(&w).await;
    let before: Vec<(u64, usize)> = w
        .clusters
        .iter()
        .map(|c| (c.db.feed_seq(), c.db.applied()))
        .collect();
    w.rounds(6).await;
    let after: Vec<(u64, usize)> = w
        .clusters
        .iter()
        .map(|c| (c.db.feed_seq(), c.db.applied()))
        .collect();
    assert_eq!(
        before, after,
        "no writes once converged (two instances per cluster too)"
    );
}

#[tokio::test]
async fn on_demand_session_stores_hold_only_sessions_used_there() {
    let mut w = World::new();
    w.add("ums", 9100, &[]).await;
    w.add_with_cluster("orders", 9200, &[9100], |c| {
        c.session_distribution("on_demand")
    })
    .await;
    w.rounds(2).await;
    let (_, used) = login(&w, "a@example.com").await;
    let (_, unused) = login(&w, "b@example.com").await;
    settle(&w).await;
    let orders = w.cluster("orders");
    assert!(!orders.db.has_session(used.session_id));
    assert!(!orders.db.has_session(unused.session_id));
    let next = refresh_at(&w.node("orders"), &used, IP_A).await.unwrap();
    settle(&w).await;
    assert!(orders.db.has_session(used.session_id), "fetched and kept");
    assert!(!orders.db.has_session(unused.session_id));
    // Later changes to the held session still arrive; revocations always do.
    w.node(AUTHORITY)
        .authentication()
        .logout(&next.access_token)
        .await
        .unwrap();
    w.node(AUTHORITY)
        .authentication()
        .logout(&unused.access_token)
        .await
        .unwrap();
    settle(&w).await;
    assert_eq!(
        stored(&w, "orders", used.session_id)
            .unwrap()
            .session
            .status,
        SessionStatus::Revoked
    );
    assert!(!orders.db.has_session(unused.session_id));
    assert!(
        w.node("orders")
            .verifier()
            .verify(&unused.access_token)
            .is_err()
    );
}

#[tokio::test]
async fn staleness_guard_is_fail_open_by_default_and_closes_when_configured() {
    for (limit, expect_refused) in [(0u64, false), (10u64, true)] {
        let mut w = World::new();
        w.add("ums", 9100, &[]).await;
        w.add_with_cluster("orders", 9200, &[9100], move |c| {
            c.federation_max_staleness_secs(limit)
        })
        .await;
        w.rounds(2).await;
        let (_, pair) = login(&w, "a@example.com").await;
        settle(&w).await;
        let orders = w.node("orders");
        w.network
            .partition_groups(&[orders.node_id()], &[w.node(AUTHORITY).node_id()]);
        for _ in 0..7 {
            w.round_of(&w.all()).await; // 14 s apart from the authority
        }
        let result = refresh_at(&orders, &pair, IP_A).await;
        if expect_refused {
            assert!(matches!(result, Err(AuthError::ReplicaStale)), "{result:?}");
            w.network.heal_all();
            w.rounds(40).await; // the dead link is re-probed, then synced
            refresh_at(&orders, &pair, IP_A).await.expect("caught up");
        } else {
            result.expect("fail-open");
        }
    }
}

#[tokio::test]
async fn a_service_with_different_merge_settings_is_refused() {
    let mut w = World::new();
    w.add("ums", 9100, &[]).await;
    w.add_with("billing", 9300, &[9100], |c| {
        c.refresh_retry_match("user_agent")
    })
    .await;
    w.rounds(2).await;
    let (_, pair) = login(&w, "a@example.com").await;
    settle(&w).await;
    assert!(!w.cluster("billing").db.has_session(pair.session_id));
    let refused = w.node(AUTHORITY).federation().unwrap().report().refused;
    assert_eq!(refused, vec!["billing".to_string()]);
}

#[tokio::test]
async fn a_late_service_bootstraps_everything_in_pages() {
    let mut w = World::new();
    w.add("ums", 9100, &[]).await;
    w.rounds(1).await;
    let mut sessions = Vec::new();
    for i in 0..25 {
        sessions.push(login(&w, &format!("u{i}@example.com")).await.1.session_id);
    }
    w.add_with_cluster("reports", 9400, &[9100], |c| c.federation_pull_page_size(7))
        .await;
    w.rounds(6).await;
    let reports = w.cluster("reports");
    for sid in sessions {
        assert!(reports.db.has_session(sid));
    }
    assert!(w.node("reports").federation().unwrap().report().pulled >= 25);
}

#[tokio::test]
async fn converges_under_random_operations_and_partitions() {
    // A small deterministic generator.
    let mut seed: u64 = 0x5eed_1234_abcd;
    let mut next = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let w = three().await;
    let mut pairs = Vec::new();
    for i in 0..6 {
        pairs.push(login(&w, &format!("r{i}@example.com")).await.1);
    }
    settle(&w).await;
    let nodes = w.all();
    for _ in 0..60 {
        let node = &nodes[next(nodes.len() as u64) as usize];
        let i = next(pairs.len() as u64) as usize;
        match next(10) {
            0..=5 => {
                let ip = if next(10) == 0 { IP_B } else { IP_A };
                if let Ok(p) = refresh_at(node, &pairs[i], ip).await {
                    pairs[i] = p;
                }
            }
            6 => {
                let _ = node.authentication().logout(&pairs[i].access_token).await;
            }
            7 => {
                let a = &nodes[next(nodes.len() as u64) as usize];
                let b = &nodes[next(nodes.len() as u64) as usize];
                w.network.partition_pair(a.node_id(), b.node_id());
            }
            8 => w.network.heal_all(),
            _ => w.round_of(&nodes).await,
        }
        w.clock.advance(Duration::from_secs(next(40)));
    }
    w.network.heal_all();
    w.rounds(40).await;
    let reference = w.cluster(AUTHORITY).db.session_aggregates();
    for c in &w.clusters {
        assert_eq!(c.db.session_aggregates(), reference, "{} converged", c.name);
        // Long cuts inside a cluster may fence a minority; every cluster
        // keeps serving.
        assert!(c.nodes.iter().any(|n| !n.is_fenced()), "{}", c.name);
    }
}
