//! Integration tests — federation-mode sync store against Postgres: the
//! change feed, commit-order safety, session compare-and-swap, merges,
//! snapshots and cursors, on both schemas.
//!
//! Run with:
//!   cargo test -p z-auth-postgres --test sync

mod helpers;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use uuid::Uuid;
use z_auth::security::authentication::ClientContext;
use z_auth::security::session::RevocationReason;
use z_auth::security::session::{RotateOutcome, SessionLifetimes, SessionRepository};
use z_auth::security::token::{
    NewRevocation, RevocationRepository, RevocationScope, RevocationStatus,
};
use z_auth_cluster::federation::{
    AccountSnapshot, ApplyOutcome, FeedCursor, SessionAggregate, SiteId, SyncRecord, SyncStore,
};
use z_auth_postgres::{PgRevocationRepository, PgSessionRepository, PgSyncStore};

use crate::helpers::{
    cleanup_user_by_id, cluster_pool as pool, create_test_user, make_service, session_store_pool,
    unique_email,
};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));

fn lifetimes() -> SessionLifetimes {
    SessionLifetimes {
        idle_timeout: Duration::from_secs(1800),
        absolute_timeout: Duration::from_secs(28_800),
        access_ttl: Duration::from_secs(300),
        history_size: 10,
    }
}

/// Every record after `after`, following pages.
async fn drain(store: &PgSyncStore, mut after: FeedCursor) -> (Vec<SyncRecord>, FeedCursor) {
    let mut all = Vec::new();
    loop {
        let page = store.changes_since(after, 50).await.unwrap();
        all.extend(page.records);
        after = page.next;
        if !page.more {
            return (all, after);
        }
    }
}

/// Drain until `done` holds.  Other tests' open transactions hold the feed
/// back for a moment (by design: nothing still committing is skipped).
async fn drain_until(
    store: &PgSyncStore,
    after: FeedCursor,
    done: impl Fn(&[SyncRecord]) -> bool,
) -> (Vec<SyncRecord>, FeedCursor) {
    let mut seen = Vec::new();
    let mut cursor = after;
    for _ in 0..100 {
        let (records, next) = drain(store, cursor).await;
        seen.extend(records);
        cursor = next;
        if done(&seen) {
            return (seen, cursor);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("feed did not deliver in time");
}

fn has_revocation(records: &[SyncRecord], id: Uuid) -> bool {
    records
        .iter()
        .any(|r| matches!(r, SyncRecord::Revocation(x) if x.id == id))
}

fn new_revocation() -> NewRevocation {
    NewRevocation {
        scope: RevocationScope::Session(Uuid::new_v4()),
        reason: RevocationReason::Logout,
        ttl: Duration::from_secs(600),
        origin_node: Uuid::new_v4(),
    }
}

#[tokio::test]
async fn test_feed_pages_and_captures_writes() {
    let pool = pool().await;
    let store = PgSyncStore::new(pool.clone());
    let site = store.site_id().await.unwrap();
    assert_eq!(store.site_id().await.unwrap(), site, "created once");

    let start = store.head().await.unwrap();
    let repo = PgRevocationRepository::new(pool.clone());
    let mut ids = Vec::new();
    for _ in 0..5 {
        ids.push(repo.insert(&new_revocation()).await.unwrap().id);
    }
    // Direct SQL edits are captured too.
    sqlx::query(
        "UPDATE security_token_revocations SET expires_at = expires_at + interval '1 minute' WHERE id = $1",
    )
    .bind(ids[0])
    .execute(&pool)
    .await
    .unwrap();

    let (records, end) = drain_until(&store, start, |r| {
        ids.iter().all(|id| has_revocation(r, *id))
    })
    .await;
    assert!(end > start);
    // Not `>= end`: a feed row moves when its record changes again, so
    // while another test holds a transaction open, the newest row can be
    // hidden and head can sit behind a position already read.  Our own
    // rows stay put and are visible, so head is past them.
    assert!(store.head().await.unwrap() > start);
    // Pages of two.
    let first = store.changes_since(start, 2).await.unwrap();
    assert_eq!(first.site, site);
    assert!(first.records.len() <= 2);
    assert!(first.more);
    let _ = records;
}

#[tokio::test]
async fn test_feed_orders_transaction_ids_numerically() {
    // A fresh schema, so its feed holds only the rows below.
    let schema = format!("feed_order_{}", Uuid::new_v4().simple());
    let remote_pool = session_store_pool(&schema).await;
    let store = PgSyncStore::new(remote_pool.clone());
    store.site_id().await.unwrap();
    // Transaction ids 9 and 10: as text, '9' sorts after '10'.
    for (txid, seq) in [(9_i64, 1_i64), (10, 2)] {
        sqlx::query(
            "INSERT INTO cluster_change_feed (kind, key, seq, txid)
             VALUES ('revocation', $1, $2, $3::text::xid8)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(seq)
        .bind(txid.to_string())
        .execute(&remote_pool)
        .await
        .unwrap();
    }

    assert_eq!(store.head().await.unwrap(), FeedCursor { txid: 10, seq: 2 });
    let page = store.changes_since(FeedCursor::default(), 1).await.unwrap();
    assert_eq!(page.next, FeedCursor { txid: 9, seq: 1 });
    assert!(page.more);
    let page = store.changes_since(page.next, 1).await.unwrap();
    assert_eq!(page.next, FeedCursor { txid: 10, seq: 2 });
    assert!(!page.more);

    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool().await)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_a_change_still_committing_is_never_skipped() {
    let pool = pool().await;
    let store = PgSyncStore::new(pool.clone());
    store.site_id().await.unwrap();
    let (_, cursor) = drain(&store, FeedCursor::default()).await;

    // A: written but not committed yet.
    let mut slow = pool.begin().await.unwrap();
    let slow_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO security_token_revocations (id, scope, subject, reason, expires_at)
         VALUES ($1, 'session', $2, 'logout', now() + interval '10 minutes')",
    )
    .bind(slow_id)
    .bind(Uuid::new_v4())
    .execute(&mut *slow)
    .await
    .unwrap();
    // B: a later transaction, committed.
    let fast = PgRevocationRepository::new(pool.clone())
        .insert(&new_revocation())
        .await
        .unwrap();

    let (seen, after_b) = drain(&store, cursor).await;
    assert!(
        !has_revocation(&seen, fast.id),
        "B waits until A is done, so the cursor cannot pass A"
    );
    slow.commit().await.unwrap();
    drain_until(&store, after_b, |r| {
        has_revocation(r, slow_id) && has_revocation(r, fast.id)
    })
    .await;
}

#[tokio::test]
async fn test_merges_write_only_when_something_changes() {
    let pool = pool().await;
    let store = PgSyncStore::new(pool.clone());
    store.site_id().await.unwrap();
    let stored = PgRevocationRepository::new(pool.clone())
        .insert(&new_revocation())
        .await
        .unwrap();
    // Wait for the insert itself: another test's open transaction can hold
    // the feed back, and it must not surface in the no-op check below.
    let (_, cursor) = drain_until(&store, FeedCursor::default(), |r| {
        has_revocation(r, stored.id)
    })
    .await;

    assert_eq!(
        store.merge_revocation(&stored).await.unwrap(),
        ApplyOutcome::Unchanged
    );
    let (seen, cursor) = drain(&store, cursor).await;
    assert!(
        !has_revocation(&seen, stored.id),
        "a no-op apply leaves the feed alone"
    );

    let mut enforced = stored.clone();
    enforced.status = RevocationStatus::Enforced;
    enforced.enforced_at = Some(stored.revoked_at + chrono::Duration::seconds(5));
    enforced.enforced_by = Some(Uuid::new_v4());
    assert_eq!(
        store.merge_revocation(&enforced).await.unwrap(),
        ApplyOutcome::Applied
    );
    assert_eq!(
        store.merge_revocation(&stored).await.unwrap(),
        ApplyOutcome::Unchanged,
        "pending never overrides enforced"
    );
    drain_until(&store, cursor, |r| has_revocation(r, stored.id)).await;

    // A revocation from another cluster, with its id.
    let mut foreign = stored.clone();
    foreign.id = Uuid::new_v4();
    foreign.scope = RevocationScope::Token(Uuid::new_v4());
    assert_eq!(
        store.merge_revocation(&foreign).await.unwrap(),
        ApplyOutcome::Applied
    );
    assert_eq!(
        store.merge_revocation(&foreign).await.unwrap(),
        ApplyOutcome::Unchanged
    );
}

#[tokio::test]
async fn test_session_round_trip_cas_and_session_store_schema() {
    let service = make_service().await;
    let user = create_test_user(
        &service,
        z_auth::identity::user::RegisterUser {
            email: unique_email("sync"),
            password: "Blablabla1!".into(),
            username: None,
            first_name: None,
            last_name: None,
        },
    )
    .await;
    let pool = pool().await;
    let store = PgSyncStore::new(pool.clone());
    let sessions = PgSessionRepository::new(pool.clone());
    let pair = service
        .authentication()
        .login(
            z_auth::security::authentication::Credentials {
                email: user.email.clone(),
                password: "Blablabla1!".into(),
            },
            ClientContext::new(IP).with_fingerprint("device"),
        )
        .await
        .unwrap();
    let sid = pair.session_id;

    let (agg, rev) = store.load_session(sid).await.unwrap().unwrap();
    assert_eq!(agg.session.user_id, user.id);
    assert_eq!(agg.generations.len(), 1);
    assert_eq!(agg.session.amr, ["pwd"]);

    // A local rotation moves the revision: a merge based on the old one
    // must not overwrite it.
    let issued =
        ClientContext::new(IP).issue_context(Some(agg.generations[0].variants[0].access_jti));
    assert!(matches!(
        sessions
            .rotate(sid, 1, &issued, &lifetimes())
            .await
            .unwrap(),
        RotateOutcome::Rotated { .. }
    ));
    assert_eq!(
        store.store_session(&agg, Some(rev)).await.unwrap(),
        ApplyOutcome::Conflict
    );
    let (current, rev2) = store.load_session(sid).await.unwrap().unwrap();
    assert!(rev2 > rev);
    assert_eq!(current.session.current_generation, 2);

    // Into a session store (no users there), and back out identically.
    let schema = format!("ss_{}", Uuid::new_v4().simple());
    let remote_pool = session_store_pool(&schema).await;
    let remote = PgSyncStore::new(remote_pool.clone());
    remote.site_id().await.unwrap();
    assert_eq!(
        remote.store_session(&current, None).await.unwrap(),
        ApplyOutcome::Applied
    );
    let (copy, remote_rev) = remote.load_session(sid).await.unwrap().unwrap();
    assert_eq!(copy, current);
    assert_eq!(
        remote.store_session(&current, None).await.unwrap(),
        ApplyOutcome::Conflict,
        "it exists now"
    );
    // The session store's repositories work on the copy.
    let remote_sessions = PgSessionRepository::new(remote_pool.clone());
    let snapshot = remote_sessions
        .load_for_refresh(sid, 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.presented.unwrap().fingerprint_hash,
        issued.fingerprint_hash
    );
    // The copy enters the store's own feed (once no other transaction holds
    // the feed back).
    drain_until(&remote, FeedCursor::default(), |r| {
        r.iter()
            .any(|r| matches!(r, SyncRecord::Session(a) if a.session.id == sid))
    })
    .await;
    // A merge that changes `amr` writes it.
    let mut upgraded = copy.clone();
    upgraded.session.amr = vec!["mfa".into(), "otp".into(), "pwd".into()];
    assert_eq!(
        remote
            .store_session(&upgraded, Some(remote_rev))
            .await
            .unwrap(),
        ApplyOutcome::Applied
    );
    let (merged, _) = remote.load_session(sid).await.unwrap().unwrap();
    assert_eq!(merged.session.amr, upgraded.session.amr);

    // The authority drops sessions of users it deleted (FK).
    let mut orphan: SessionAggregate = current.clone();
    orphan.session.id = Uuid::new_v4();
    orphan.session.user_id = Uuid::new_v4();
    for g in &mut orphan.generations {
        for v in &mut g.variants {
            v.access_jti = Uuid::new_v4();
            v.parent_jti = None;
        }
    }
    assert_eq!(
        store.store_session(&orphan, None).await.unwrap(),
        ApplyOutcome::Dropped
    );

    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .unwrap();
    let _ = cleanup_user_by_id(&service, user.id).await;
}

#[tokio::test]
async fn test_snapshots_keep_the_newest_version_and_cursors_only_move_forward() {
    let pool = pool().await;
    let store = PgSyncStore::new(pool.clone());
    let user = Uuid::new_v4();
    let v1 = store.next_account_version().await.unwrap();
    let v2 = store.next_account_version().await.unwrap();
    assert!(v2 > v1);
    let snap = |version, is_active| AccountSnapshot {
        user_id: user,
        version,
        is_active,
        deleted: false,
        authz: None,
    };
    assert_eq!(
        store.apply_account(&snap(v2, false)).await.unwrap(),
        ApplyOutcome::Applied
    );
    assert_eq!(
        store.apply_account(&snap(v1, true)).await.unwrap(),
        ApplyOutcome::Unchanged
    );
    assert!(!store.load_account(user).await.unwrap().unwrap().is_active);

    let site = SiteId(Uuid::new_v4());
    assert_eq!(store.cursor(site).await.unwrap(), FeedCursor::default());
    let ahead = FeedCursor { txid: 10, seq: 5 };
    store.advance_cursor(site, ahead).await.unwrap();
    store
        .advance_cursor(site, FeedCursor { txid: 9, seq: 99 })
        .await
        .unwrap();
    assert_eq!(store.cursor(site).await.unwrap(), ahead);
    store.reset_cursor(site).await.unwrap();
    assert_eq!(store.cursor(site).await.unwrap(), FeedCursor::default());
}
