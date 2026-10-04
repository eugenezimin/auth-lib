//! Revocation on a single instance (no cluster): pending → blocked on use →
//! enforced on the next tick, bootstrap from the store at start, expiry.

// The facade's defaults need the `argon2` and `crypto` features.
#![cfg(all(feature = "argon2", feature = "crypto"))]

mod support;

use std::sync::Arc;
use std::time::Duration;

use auth_lib::prelude::*;

use crate::support::{IP_A, InMemoryDb, MockClock, register_and_login, server_with, test_config};

#[tokio::test]
async fn revoked_tokens_are_blocked_then_enforced_on_the_next_tick() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let s = server_with(db.clone(), clock, test_config());
    let (_, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;

    s.auth
        .revocation()
        .revoke(
            RevokeTarget::AccessToken(pair.access_token.clone()),
            RevocationReason::Administrative,
        )
        .await
        .unwrap();
    let entry = &s.auth.denylist().entries(s.clock.now())[0];
    assert_eq!(entry.status, RevocationStatus::Pending);
    assert_eq!(entry.origin_node, s.auth.node_id());

    // Nothing presented yet → nothing to enforce.
    assert_eq!(s.auth.tick().await.unwrap().enforced, 0);

    assert!(matches!(
        s.auth.verifier().verify(&pair.access_token),
        Err(AuthError::TokenRevoked)
    ));
    assert_eq!(s.auth.tick().await.unwrap().enforced, 1);
    assert_eq!(
        db.revocation(entry.id).unwrap().status,
        RevocationStatus::Enforced
    );
    let session = SessionRepository::find(db.as_ref(), pair.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.status, SessionStatus::Compromised);
    assert_eq!(session.end_reason, Some(RevocationReason::RevokedTokenUsed));

    // Enforced once; later presentations are still rejected, never re-enforced.
    assert!(s.auth.verifier().verify(&pair.access_token).is_err());
    assert_eq!(s.auth.tick().await.unwrap().enforced, 0);
}

#[tokio::test]
async fn a_restarting_instance_loads_active_revocations_at_start() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let config = test_config();
    let a = server_with(db.clone(), clock.clone(), config.clone());
    let (_, pair) = register_and_login(&a.auth, "a@example.com", IP_A).await;
    a.auth
        .authentication()
        .logout(&pair.access_token)
        .await
        .unwrap();

    // A fresh instance over the same store (same keys, no cluster).
    let b = server_with(db, clock, config);
    b.auth.verifier().verify(&pair.access_token).unwrap();
    let report = b.auth.start().await.unwrap();
    assert_eq!(report.revocations_loaded, 1);
    assert!(matches!(
        b.auth.verifier().verify(&pair.access_token),
        Err(AuthError::TokenRevoked)
    ));
}

#[tokio::test]
async fn user_scope_revocation_denies_older_tokens_only() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let s = server_with(db, clock, test_config());
    let (user, old) = register_and_login(&s.auth, "a@example.com", IP_A).await;

    s.auth
        .revocation()
        .revoke(
            RevokeTarget::User(user.id),
            RevocationReason::Administrative,
        )
        .await
        .unwrap();
    assert!(s.auth.verifier().verify(&old.access_token).is_err());

    s.clock.advance(Duration::from_secs(1));
    let fresh = s
        .auth
        .authentication()
        .login(support::credentials("a@example.com"), support::ctx(IP_A))
        .await
        .unwrap();
    s.auth.verifier().verify(&fresh.access_token).unwrap();
}

#[tokio::test]
async fn revoking_a_refresh_token_ends_its_session() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let s = server_with(db, clock, test_config());
    let (_, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;

    let ended = s
        .auth
        .revocation()
        .revoke_many(
            vec![
                RevokeTarget::RefreshToken(pair.refresh_token.clone()),
                RevokeTarget::AccessToken("garbage".into()), // skipped
            ],
            RevocationReason::Compromised,
        )
        .await
        .unwrap();
    assert_eq!(ended, 1);
    let session = SessionRepository::find(s.db.as_ref(), pair.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.status, SessionStatus::Compromised);
}

#[tokio::test]
async fn entries_expire_after_access_ttl_plus_leeway() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let s = server_with(db.clone(), clock.clone(), test_config());
    let (_, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.auth
        .authentication()
        .logout(&pair.access_token)
        .await
        .unwrap();
    assert_eq!(s.auth.denylist().len(), 1);

    // access TTL (300 s) + leeway (30 s)
    clock.advance(Duration::from_secs(331));
    assert_eq!(s.auth.tick().await.unwrap().pruned, 1);
    assert!(s.auth.denylist().is_empty());
    assert_eq!(s.auth.revocation().purge_expired().await.unwrap(), 1);
    assert!(db.revocations().is_empty());

    // The old token is expired anyway, and its session can't be refreshed.
    assert!(s.auth.verifier().verify(&pair.access_token).is_err());
}
