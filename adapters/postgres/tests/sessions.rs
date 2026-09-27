//! Integration tests — sessions, rotation and revocations against Postgres.
//!
//! The schema is applied by `helpers::pool()` (idempotent migrations).
//! Every timestamp asserted here was assigned by the database.
//!
//! Run with:
//!   cargo test -p auth-lib-postgres --test sessions

mod helpers;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use auth_lib::authentication::{
    ClientContext, Credentials, RotateOutcome, SessionLifetimes, SessionRepository, SessionStatus,
};
use auth_lib::token::{
    NewRevocation, Revocation, RevocationReason, RevocationRepository, RevocationScope,
};
use auth_lib::user::{RegisterUser, UpdateUser};
use auth_lib_postgres::{PgRevocationRepository, PgSessionRepository};
use uuid::Uuid;

use crate::helpers::{cleanup_user_by_id, create_test_user, make_service, pool, unique_email};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
const PASSWORD: &str = "Blablabla1!";

/// auth-lib defaults: 5 min access, 30 min idle, 8 h absolute.
const ACCESS_TTL: Duration = Duration::from_secs(300);
const IDLE_TIMEOUT: Duration = Duration::from_secs(1_800);
const ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(28_800);

/// `std` → `chrono` duration, to compare against timestamp differences.
fn delta(d: Duration) -> chrono::TimeDelta {
    chrono::TimeDelta::from_std(d).unwrap()
}

fn lifetimes(history_size: u32) -> SessionLifetimes {
    SessionLifetimes {
        idle_timeout: IDLE_TIMEOUT,
        absolute_timeout: ABSOLUTE_TIMEOUT,
        access_ttl: ACCESS_TTL,
        history_size,
    }
}

async fn login(service: &auth_lib::AuthLib) -> (Uuid, auth_lib::authentication::TokenPair) {
    let email = unique_email("session");
    let user = create_test_user(
        service,
        RegisterUser {
            email: email.clone(),
            password: PASSWORD.into(),
            username: None,
            first_name: None,
            last_name: None,
        },
    )
    .await;
    let pair = service
        .authentication()
        .login(
            Credentials {
                email,
                password: PASSWORD.into(),
            },
            ClientContext {
                ip: IP,
                user_agent: Some("integration-test".into()),
            },
        )
        .await
        .expect("login");
    (user.id, pair)
}

#[tokio::test]
async fn test_login_persists_session_and_first_generation() {
    let service = make_service().await;
    let repo = PgSessionRepository::new(pool().await);
    let (user_id, pair) = login(&service).await;

    let session = repo
        .find(pair.session_id)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.status, SessionStatus::Active);
    assert_eq!(session.created_ip, IP);
    assert_eq!(session.current_generation, 1);
    assert_eq!(session.secret.len(), 32);

    let first = repo
        .find_generation(pair.session_id, 1)
        .await
        .unwrap()
        .expect("generation 1");
    assert_eq!(first.issued_ip, IP);
    assert!(first.superseded_at.is_none());

    cleanup_user_by_id(&service, user_id).await.unwrap();
}

#[tokio::test]
async fn test_database_assigns_ids_and_timestamps() {
    let service = make_service().await;
    let pool = pool().await;
    let repo = PgSessionRepository::new(pool.clone());
    let (user_id, pair) = login(&service).await;

    let session = repo.find(pair.session_id).await.unwrap().unwrap();
    let first = repo
        .find_generation(pair.session_id, 1)
        .await
        .unwrap()
        .unwrap();

    // One transaction → one now().
    assert_eq!(first.issued_at, session.created_at);
    assert_eq!(
        session.idle_expires_at - session.created_at,
        delta(IDLE_TIMEOUT)
    );
    assert_eq!(
        session.absolute_expires_at - session.created_at,
        delta(ABSOLUTE_TIMEOUT)
    );
    assert_eq!(first.access_expires_at - first.issued_at, delta(ACCESS_TTL));

    // The token carries the database's values; jti is the generation row id.
    let claims = service.verifier().verify(&pair.access_token).unwrap();
    assert_eq!(claims.jti, first.access_jti);
    assert_eq!(claims.iat, first.issued_at.timestamp());
    assert_eq!(claims.exp, first.access_expires_at.timestamp());
    assert_eq!(pair.access_expires_at, first.access_expires_at);

    // Bookkeeping created_at is stamped alongside the event columns.
    let (same,): (bool,) =
        sqlx::query_as("SELECT created_at = issued_at FROM session_generations WHERE id = $1")
            .bind(first.access_jti)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(same);

    cleanup_user_by_id(&service, user_id).await.unwrap();
}

#[tokio::test]
async fn test_rotate_is_compare_and_swap_and_trims_history() {
    let service = make_service().await;
    let repo = PgSessionRepository::new(pool().await);
    let (user_id, pair) = login(&service).await;
    let sid = pair.session_id;

    // A stale expected generation loses.
    let stale = repo.rotate(sid, 7, IP, &lifetimes(3)).await.unwrap();
    assert!(matches!(stale, RotateOutcome::Conflict));

    for g in 2..=5 {
        let RotateOutcome::Rotated {
            session,
            generation,
        } = repo.rotate(sid, g - 1, IP, &lifetimes(3)).await.unwrap()
        else {
            panic!("rotation to {g} should win");
        };
        assert_eq!(session.current_generation, g);
        assert_eq!(generation.generation, g);
        assert_eq!(
            session.idle_expires_at - generation.issued_at,
            delta(IDLE_TIMEOUT)
        );
        let previous = repo.find_generation(sid, g - 1).await.unwrap();
        if let Some(previous) = previous {
            assert_eq!(previous.superseded_at, Some(generation.issued_at));
        }
    }
    assert_eq!(repo.find(sid).await.unwrap().unwrap().current_generation, 5);
    // history_size = 3 → generations 3, 4, 5 remain
    assert!(repo.find_generation(sid, 2).await.unwrap().is_none());
    assert!(
        repo.find_generation(sid, 5)
            .await
            .unwrap()
            .unwrap()
            .superseded_at
            .is_none()
    );

    cleanup_user_by_id(&service, user_id).await.unwrap();
}

#[tokio::test]
async fn test_concurrent_rotations_have_one_winner() {
    let service = make_service().await;
    let repo = Arc::new(PgSessionRepository::new(pool().await));
    let (user_id, pair) = login(&service).await;

    let lt = lifetimes(10);
    let (a, b) = tokio::join!(
        repo.rotate(pair.session_id, 1, IP, &lt),
        repo.rotate(pair.session_id, 1, IP, &lt),
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    let won = outcomes
        .iter()
        .filter(|o| matches!(o, RotateOutcome::Rotated { .. }))
        .count();
    assert_eq!(won, 1);

    cleanup_user_by_id(&service, user_id).await.unwrap();
}

#[tokio::test]
async fn test_load_for_refresh_reads_everything_in_one_go() {
    let service = make_service().await;
    let repo = PgSessionRepository::new(pool().await);
    let (user_id, pair) = login(&service).await;
    let sid = pair.session_id;
    repo.rotate(sid, 1, IP, &lifetimes(10)).await.unwrap();

    let snap = repo.load_for_refresh(sid, 1).await.unwrap().unwrap();
    assert_eq!(snap.session.current_generation, 2);
    assert_eq!(snap.presented.as_ref().map(|g| g.generation), Some(1));
    assert_eq!(snap.current.as_ref().map(|g| g.generation), Some(2));
    assert!(snap.now >= snap.current.unwrap().issued_at);

    let unknown_gen = repo.load_for_refresh(sid, 99).await.unwrap().unwrap();
    assert!(unknown_gen.presented.is_none());
    assert!(unknown_gen.current.is_some());

    assert!(
        repo.load_for_refresh(Uuid::new_v4(), 1)
            .await
            .unwrap()
            .is_none()
    );

    cleanup_user_by_id(&service, user_id).await.unwrap();
}

#[tokio::test]
async fn test_refresh_flow_against_postgres() {
    let service = make_service().await;
    let (user_id, first) = login(&service).await;
    let ctx = ClientContext {
        ip: IP,
        user_agent: None,
    };

    let second = service
        .authentication()
        .refresh(&first.access_token, &first.refresh_token, ctx.clone())
        .await
        .expect("rotation");
    // Immediate retry of the old pair = concurrent refresh → same latest pair.
    let again = service
        .authentication()
        .refresh(&first.access_token, &first.refresh_token, ctx)
        .await
        .expect("grace window");
    assert_eq!(again, second);

    cleanup_user_by_id(&service, user_id).await.unwrap();
}

#[tokio::test]
async fn test_end_session_and_end_all_for_user() {
    let service = make_service().await;
    let repo = PgSessionRepository::new(pool().await);
    let (user_id, pair) = login(&service).await;

    assert!(
        repo.end(
            pair.session_id,
            SessionStatus::Compromised,
            RevocationReason::TokenReuse,
        )
        .await
        .unwrap()
    );
    assert!(
        !repo
            .end(
                pair.session_id,
                SessionStatus::Revoked,
                RevocationReason::Logout,
            )
            .await
            .unwrap(),
        "already ended"
    );
    let ended = repo.find(pair.session_id).await.unwrap().unwrap();
    assert_eq!(ended.status, SessionStatus::Compromised);
    assert_eq!(ended.end_reason, Some(RevocationReason::TokenReuse));
    assert!(ended.ended_at.is_some_and(|at| at >= ended.created_at));

    let ids = repo
        .end_all_for_user(user_id, SessionStatus::Revoked, RevocationReason::LogoutAll)
        .await
        .unwrap();
    assert!(ids.is_empty(), "no active sessions left");

    cleanup_user_by_id(&service, user_id).await.unwrap();
}

#[tokio::test]
async fn test_ended_session_check_constraint() {
    let service = make_service().await;
    let pool = pool().await;
    let (user_id, pair) = login(&service).await;

    // Ending without ended_at / end_reason violates chk_sessions_ended.
    let err = sqlx::query("UPDATE sessions SET status = 'revoked' WHERE id = $1")
        .bind(pair.session_id)
        .execute(&pool)
        .await
        .expect_err("half-ended session must be rejected");
    assert!(err.to_string().contains("chk_sessions_ended"), "got: {err}");

    cleanup_user_by_id(&service, user_id).await.unwrap();
}

#[tokio::test]
async fn test_purge_removes_sessions_past_retention() {
    let service = make_service().await;
    let pool = pool().await;
    let repo = PgSessionRepository::new(pool.clone());
    let (user_id, pair) = login(&service).await;

    // Backdate the end by two hours (the only way to time-travel the DB).
    sqlx::query(
        "UPDATE sessions
         SET status = 'revoked', end_reason = 'logout', ended_at = now() - interval '2 hours'
         WHERE id = $1",
    )
    .bind(pair.session_id)
    .execute(&pool)
    .await
    .unwrap();

    assert!(repo.purge(Duration::from_secs(3 * 3600)).await.is_ok());
    assert!(
        repo.find(pair.session_id).await.unwrap().is_some(),
        "within retention"
    );
    assert!(repo.purge(Duration::from_secs(3600)).await.unwrap() >= 1);
    assert!(
        repo.find(pair.session_id).await.unwrap().is_none(),
        "purged"
    );
    assert!(
        repo.find_generation(pair.session_id, 1)
            .await
            .unwrap()
            .is_none(),
        "generations cascade"
    );

    cleanup_user_by_id(&service, user_id).await.unwrap();
}

#[tokio::test]
async fn test_every_revocation_reason_round_trips_through_the_enum() {
    let repo = PgRevocationRepository::new(pool().await);
    let reasons = [
        RevocationReason::Logout,
        RevocationReason::LogoutAll,
        RevocationReason::Evicted,
        RevocationReason::TokenReuse,
        RevocationReason::IpMismatch,
        RevocationReason::Compromised,
        RevocationReason::Administrative,
        RevocationReason::PasswordChanged,
        RevocationReason::AccountDisabled,
        RevocationReason::AccountDeleted,
    ];
    let ttl = Duration::from_secs(60);

    for (i, reason) in reasons.into_iter().enumerate() {
        let subject = Uuid::new_v4();
        let scope = if i % 2 == 0 {
            RevocationScope::Session(subject)
        } else {
            RevocationScope::User(subject)
        };
        let stored = repo
            .insert(&NewRevocation { scope, reason, ttl })
            .await
            .unwrap();
        assert_eq!(stored.scope, scope);
        assert_eq!(stored.reason, reason);
        assert_eq!(stored.expires_at - stored.revoked_at, delta(ttl));
        assert!(repo.list_active().await.unwrap().contains(&stored));
    }
}

#[tokio::test]
async fn test_revocations_expire_and_purge() {
    let pool = pool().await;
    let repo = PgRevocationRepository::new(pool.clone());
    let stale_subject = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO revocations (scope, subject, reason, revoked_at, expires_at)
         VALUES ('user', $1, 'logout_all',
                 now() - interval '1000 seconds', now() - interval '600 seconds')",
    )
    .bind(stale_subject)
    .execute(&pool)
    .await
    .unwrap();

    let active = repo.list_active().await.unwrap();
    assert!(
        !active
            .iter()
            .any(|r| r.scope == RevocationScope::User(stale_subject))
    );
    assert!(repo.purge_expired().await.unwrap() >= 1);
}

/// The newest active user-scope revocation for `user_id`.
async fn user_revocation(user_id: Uuid) -> Option<Revocation> {
    PgRevocationRepository::new(pool().await)
        .list_active()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.scope == RevocationScope::User(user_id))
        .max_by_key(|r| r.revoked_at)
}

#[tokio::test]
async fn test_deactivate_and_delete_end_sessions() {
    let service = make_service().await;
    let repo = PgSessionRepository::new(pool().await);
    let (user_id, pair) = login(&service).await;

    assert!(service.users().deactivate(user_id).await.unwrap());
    let ended = repo.find(pair.session_id).await.unwrap().unwrap();
    assert_eq!(ended.status, SessionStatus::Revoked);
    assert_eq!(ended.end_reason, Some(RevocationReason::AccountDisabled));
    assert_eq!(
        user_revocation(user_id).await.map(|r| r.reason),
        Some(RevocationReason::AccountDisabled)
    );

    // Distinct revoked_at so the newest entry is unambiguous.
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        service.users().delete(user_id).await.unwrap(),
        Some(user_id)
    );
    assert!(
        repo.find(pair.session_id).await.unwrap().is_none(),
        "cascaded"
    );
    assert_eq!(
        user_revocation(user_id).await.map(|r| r.reason),
        Some(RevocationReason::AccountDeleted)
    );
}

#[tokio::test]
async fn test_password_change_ends_sessions() {
    let service = make_service().await;
    let repo = PgSessionRepository::new(pool().await);
    let (user_id, pair) = login(&service).await;

    service
        .users()
        .update(
            user_id,
            UpdateUser {
                password: Some("N3wBlablabla1!".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .expect("user exists");

    let ended = repo.find(pair.session_id).await.unwrap().unwrap();
    assert_eq!(ended.status, SessionStatus::Revoked);
    assert_eq!(ended.end_reason, Some(RevocationReason::PasswordChanged));
    assert_eq!(
        user_revocation(user_id).await.map(|r| r.reason),
        Some(RevocationReason::PasswordChanged)
    );

    cleanup_user_by_id(&service, user_id).await.unwrap();
}
