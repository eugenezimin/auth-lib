//! Login / refresh / logout flows — the scenarios agreed for the session
//! design, against in-memory adapters and a controllable clock.
//!
//! 1. A valid access token is verified with **no** storage access.
//! 2. Expired access + matching refresh → rotation.
//! 3. A concurrent refresh already rotated → the previous pair (within grace,
//!    same IP) receives the current pair.
//! 4. Reuse of an older pair, or an IP mismatch with IP binding on → only that
//!    session is compromised; tokens outside history just require login.
//! 5. History is capped at 10 generations; the creating IP is recorded.

// The facade's defaults need the `argon2` and `crypto` features.
#![cfg(all(feature = "argon2", feature = "crypto"))]

mod support;

use std::sync::Arc;
use std::time::Duration;

use auth_lib::prelude::*;

use crate::support::{
    IP_A, IP_B, InMemoryDb, MockClock, credentials, ctx, raw_config, register_and_login, server,
    server_with, test_config,
};

const ACCESS_TTL: Duration = Duration::from_secs(300);

async fn refresh(
    s: &support::Server,
    pair: &TokenPair,
    ip: std::net::IpAddr,
) -> Result<TokenPair, AuthError> {
    s.auth
        .authentication()
        .refresh(&pair.access_token, &pair.refresh_token, ctx(ip))
        .await
}

async fn session(s: &support::Server, id: uuid::Uuid) -> Session {
    SessionRepository::find(s.db.as_ref(), id)
        .await
        .unwrap()
        .unwrap()
}

// ── Scenario 1 ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn valid_access_token_is_verified_without_storage_access() {
    let s = server(test_config());
    let (user, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;

    let calls_before = s.db.calls();
    for _ in 0..100 {
        let claims = s.auth.verifier().verify(&pair.access_token).unwrap();
        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.sid, pair.session_id);
        s.auth
            .authentication()
            .verify_access_token(&pair.access_token)
            .await
            .unwrap();
    }
    assert_eq!(
        s.db.calls(),
        calls_before,
        "verification must not touch storage"
    );
}

#[tokio::test]
async fn expired_access_token_fails_verification() {
    let s = server(test_config());
    let (_, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.clock.advance(ACCESS_TTL + Duration::from_secs(31)); // past TTL + leeway
    let err = s.auth.verifier().verify(&pair.access_token).unwrap_err();
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

// ── Scenario 2 ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn expired_access_with_matching_refresh_rotates() {
    let s = server(test_config());
    let (_, first) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.clock.advance(ACCESS_TTL + Duration::from_secs(60));

    let second = refresh(&s, &first, IP_A).await.expect("refresh");
    assert_eq!(second.session_id, first.session_id);
    assert_ne!(second.access_token, first.access_token);
    assert_ne!(second.refresh_token, first.refresh_token);

    let claims = s.auth.verifier().verify(&second.access_token).unwrap();
    assert_eq!(claims.generation, 2);
    let stored = session(&s, first.session_id).await;
    assert_eq!(stored.current_generation, 2);
    assert_eq!(stored.created_ip, IP_A);
    assert_eq!(s.db.generation_numbers(first.session_id), [1, 2]);
}

#[tokio::test]
async fn refresh_extends_idle_timeout_but_not_absolute() {
    let s = server(test_config());
    let (_, mut pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    let absolute = session(&s, pair.session_id).await.absolute_expires_at;

    // Refresh every 20 minutes: idle (30 min) never lapses...
    for _ in 0..23 {
        s.clock.advance(Duration::from_secs(20 * 60));
        pair = refresh(&s, &pair, IP_A)
            .await
            .expect("idle window keeps sliding");
    }
    // ...but the 8 h absolute cap still ends the session.
    s.clock.advance(Duration::from_secs(20 * 60));
    let err = refresh(&s, &pair, IP_A).await.unwrap_err();
    assert!(matches!(err, AuthError::SessionExpired), "{err:?}");
    assert!(s.clock.now() >= absolute);
}

#[tokio::test]
async fn idle_session_expires() {
    let s = server(test_config());
    let (_, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.clock.advance(Duration::from_secs(30 * 60));
    let err = refresh(&s, &pair, IP_A).await.unwrap_err();
    assert!(matches!(err, AuthError::SessionExpired), "{err:?}");
}

// ── Scenario 3 ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn previous_pair_within_grace_receives_current_pair() {
    let s = server(test_config());
    let (_, first) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.clock.advance(ACCESS_TTL);

    let winner = refresh(&s, &first, IP_A).await.unwrap();
    s.clock.advance(Duration::from_secs(5));
    let loser = refresh(&s, &first, IP_A).await.expect("grace window");

    assert_eq!(loser, winner, "the same (latest) pair is handed out again");
    assert_eq!(session(&s, first.session_id).await.current_generation, 2);
    assert_eq!(
        session(&s, first.session_id).await.status,
        SessionStatus::Active
    );
}

#[tokio::test]
async fn concurrent_refreshes_get_the_same_pair() {
    let s = server(test_config());
    let (_, first) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.clock.advance(ACCESS_TTL);

    let (a, b) = tokio::join!(refresh(&s, &first, IP_A), refresh(&s, &first, IP_A));
    assert_eq!(a.unwrap(), b.unwrap());
    assert_eq!(s.db.generation_numbers(first.session_id), [1, 2]);
}

// ── Scenario 4 ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn previous_pair_after_grace_compromises_only_that_session() {
    let s = server(test_config());
    let (_, first) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    let other_device = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_B))
        .await
        .unwrap();
    s.clock.advance(ACCESS_TTL);
    let current = refresh(&s, &first, IP_A).await.unwrap();

    // The stolen first pair is replayed long after rotation.
    s.clock.advance(Duration::from_secs(60));
    let err = refresh(&s, &first, IP_A).await.unwrap_err();
    assert!(matches!(err, AuthError::SessionCompromised), "{err:?}");

    let compromised = session(&s, first.session_id).await;
    assert_eq!(compromised.status, SessionStatus::Compromised);
    assert_eq!(compromised.end_reason, Some(RevocationReason::TokenReuse));

    // Both the thief's and the owner's tokens are dead: login required.
    let err = s.auth.verifier().verify(&current.access_token).unwrap_err();
    assert!(matches!(err, AuthError::TokenRevoked), "{err:?}");
    let err = refresh(&s, &current, IP_A).await.unwrap_err();
    assert!(matches!(err, AuthError::TokenRevoked), "{err:?}");

    // The user's other device is untouched and keeps refreshing.
    let renewed = refresh(&s, &other_device, IP_B)
        .await
        .expect("other session unaffected");
    s.auth.verifier().verify(&renewed.access_token).unwrap();
    assert_eq!(
        session(&s, other_device.session_id).await.status,
        SessionStatus::Active
    );
}

#[tokio::test]
async fn previous_pair_from_another_ip_within_grace_is_reuse() {
    let s = server(test_config());
    let (_, first) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.clock.advance(ACCESS_TTL);
    refresh(&s, &first, IP_A).await.unwrap();

    let err = refresh(&s, &first, IP_B).await.unwrap_err();
    assert!(matches!(err, AuthError::SessionCompromised), "{err:?}");
}

#[tokio::test]
async fn tokens_older_than_history_just_require_login() {
    let s = server(test_config());
    let (_, first) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    let mut pair = first.clone();
    for _ in 0..10 {
        s.clock.advance(ACCESS_TTL);
        pair = refresh(&s, &pair, IP_A).await.unwrap();
    }
    // History = 10 → generation 1 has been trimmed.
    assert_eq!(
        s.db.generation_numbers(first.session_id),
        (2..=11).collect::<Vec<_>>()
    );

    let err = refresh(&s, &first, IP_A).await.unwrap_err();
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    assert_eq!(
        session(&s, first.session_id).await.status,
        SessionStatus::Active
    );
    refresh(&s, &pair, IP_A)
        .await
        .expect("current pair still works");
}

#[tokio::test]
async fn ip_binding_off_allows_roaming() {
    let s = server(test_config());
    let (_, first) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.clock.advance(ACCESS_TTL);
    refresh(&s, &first, IP_B)
        .await
        .expect("IP binding is off by default");
}

#[tokio::test]
async fn ip_binding_on_compromises_on_ip_change() {
    let s = server(raw_config().ip_binding(true).build().unwrap());
    let (_, first) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.clock.advance(ACCESS_TTL);

    let err = refresh(&s, &first, IP_B).await.unwrap_err();
    assert!(matches!(err, AuthError::SessionCompromised), "{err:?}");
    let ended = session(&s, first.session_id).await;
    assert_eq!(ended.status, SessionStatus::Compromised);
    assert_eq!(ended.end_reason, Some(RevocationReason::IpMismatch));
}

#[tokio::test]
async fn mixed_or_forged_pairs_are_rejected() {
    let s = server(test_config());
    let (_, a) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    let b = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap();

    // Access token of one session with the refresh token of another.
    let err = s
        .auth
        .authentication()
        .refresh(&a.access_token, &b.refresh_token, ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");

    // A refresh token with a forged MAC.
    let forged = format!("{}AAAA", &a.refresh_token[..a.refresh_token.len() - 4]);
    let err = s
        .auth
        .authentication()
        .refresh(&a.access_token, &forged, ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    assert_eq!(
        session(&s, a.session_id).await.status,
        SessionStatus::Active
    );
}

// ── Login / logout ────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_rejects_bad_credentials_and_disabled_accounts() {
    let s = server(test_config());
    let (user, _) = register_and_login(&s.auth, "a@example.com", IP_A).await;

    let err = s
        .auth
        .authentication()
        .login(
            Credentials {
                email: "a@example.com".into(),
                password: "Wr0ngPassword".into(),
            },
            ctx(IP_A),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidCredentials));

    let err = s
        .auth
        .authentication()
        .login(credentials("nobody@example.com"), ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidCredentials));

    s.auth.users().deactivate(user.id).await.unwrap();
    let err = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::AccountDisabled));
}

#[tokio::test]
async fn login_evicts_oldest_session_beyond_limit() {
    let s = server(raw_config().max_sessions_per_user(2).build().unwrap());
    let (_, oldest) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.clock.advance(Duration::from_secs(1));
    let middle = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap();
    s.clock.advance(Duration::from_secs(1));
    let newest = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap();

    let evicted = session(&s, oldest.session_id).await;
    assert_eq!(evicted.status, SessionStatus::Revoked);
    assert_eq!(evicted.end_reason, Some(RevocationReason::Evicted));
    assert!(s.auth.verifier().verify(&oldest.access_token).is_err());
    s.auth.verifier().verify(&middle.access_token).unwrap();
    s.auth.verifier().verify(&newest.access_token).unwrap();
}

#[tokio::test]
async fn logout_ends_only_its_own_session() {
    let s = server(test_config());
    let (_, a) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    let b = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap();

    assert!(
        s.auth
            .authentication()
            .logout(&a.access_token)
            .await
            .unwrap()
    );
    assert!(
        !s.auth
            .authentication()
            .logout(&a.access_token)
            .await
            .unwrap(),
        "idempotent"
    );

    assert!(matches!(
        s.auth.verifier().verify(&a.access_token),
        Err(AuthError::TokenRevoked)
    ));
    s.auth.verifier().verify(&b.access_token).unwrap();
}

#[tokio::test]
async fn logout_all_ends_every_session_but_allows_new_login() {
    let s = server(test_config());
    let (user, a) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    let b = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_B))
        .await
        .unwrap();

    assert_eq!(
        s.auth.authentication().logout_all(user.id).await.unwrap(),
        2
    );
    assert!(s.auth.verifier().verify(&a.access_token).is_err());
    assert!(s.auth.verifier().verify(&b.access_token).is_err());

    s.clock.advance(Duration::from_secs(1));
    let fresh = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap();
    s.auth
        .verifier()
        .verify(&fresh.access_token)
        .expect("tokens issued after logout-all are valid");
}

#[tokio::test]
async fn purge_removes_ended_sessions_after_retention() {
    let s = server(test_config());
    let (_, a) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.auth
        .authentication()
        .logout(&a.access_token)
        .await
        .unwrap();

    let retention = Duration::from_secs(3600);
    assert_eq!(
        s.auth
            .authentication()
            .purge_sessions(retention)
            .await
            .unwrap(),
        0
    );
    s.clock.advance(retention + Duration::from_secs(1));
    assert_eq!(
        s.auth
            .authentication()
            .purge_sessions(retention)
            .await
            .unwrap(),
        1
    );
}

// ── Shared store across servers ───────────────────────────────────────────────

#[tokio::test]
async fn refresh_works_on_any_server() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let config = test_config();
    let a = server_with(db.clone(), clock.clone(), config.clone());
    let b = server_with(db, clock, config);

    let (_, pair) = register_and_login(&a.auth, "a@example.com", IP_A).await;
    a.clock.advance(ACCESS_TTL);
    let next = refresh(&b, &pair, IP_A)
        .await
        .expect("server B refreshes server A's session");
    a.auth.verifier().verify(&next.access_token).unwrap();
}

// ── User lifecycle ends sessions ──────────────────────────────────────────────

#[tokio::test]
async fn login_email_is_case_insensitive() {
    let s = server(test_config());
    let (user, _) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    let pair = s
        .auth
        .authentication()
        .login(credentials("  A@Example.COM"), ctx(IP_A))
        .await
        .expect("login ignores email case");
    assert_eq!(
        s.auth.verifier().verify(&pair.access_token).unwrap().sub,
        user.id
    );
}

#[tokio::test]
async fn deactivate_ends_sessions_and_revokes_tokens() {
    let s = server(test_config());
    let (user, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;

    assert!(s.auth.users().deactivate(user.id).await.unwrap());

    let ended = session(&s, pair.session_id).await;
    assert_eq!(ended.status, SessionStatus::Revoked);
    assert_eq!(ended.end_reason, Some(RevocationReason::AccountDisabled));
    assert!(matches!(
        s.auth.verifier().verify(&pair.access_token),
        Err(AuthError::TokenRevoked)
    ));
    assert!(refresh(&s, &pair, IP_A).await.is_err());
}

#[tokio::test]
async fn password_change_ends_every_session() {
    let s = server(test_config());
    let (user, laptop) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    let phone = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_B))
        .await
        .unwrap();

    let new_password = "N3wS3cur3P@ss!";
    s.auth
        .users()
        .update(
            user.id,
            UpdateUser {
                password: Some(new_password.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .expect("user exists");

    for pair in [&laptop, &phone] {
        let ended = session(&s, pair.session_id).await;
        assert_eq!(ended.status, SessionStatus::Revoked);
        assert_eq!(ended.end_reason, Some(RevocationReason::PasswordChanged));
        assert!(s.auth.verifier().verify(&pair.access_token).is_err());
        assert!(refresh(&s, pair, IP_A).await.is_err());
    }

    // The user-wide denylist cutoff has second resolution.
    s.clock.advance(Duration::from_secs(1));
    let fresh = s
        .auth
        .authentication()
        .login(
            Credentials {
                email: "a@example.com".into(),
                password: new_password.into(),
            },
            ctx(IP_A),
        )
        .await
        .expect("login with the new password");
    s.auth.verifier().verify(&fresh.access_token).unwrap();
}

#[tokio::test]
async fn profile_update_without_password_keeps_sessions() {
    let s = server(test_config());
    let (user, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;

    s.auth
        .users()
        .update(
            user.id,
            UpdateUser {
                first_name: Some("Alice".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(
        session(&s, pair.session_id).await.status,
        SessionStatus::Active
    );
    s.auth.verifier().verify(&pair.access_token).unwrap();
}

#[tokio::test]
async fn delete_revokes_outstanding_access_tokens() {
    let s = server(test_config());
    let (user, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;

    assert_eq!(s.auth.users().delete(user.id).await.unwrap(), Some(user.id));

    assert!(matches!(
        s.auth.verifier().verify(&pair.access_token),
        Err(AuthError::TokenRevoked)
    ));
    assert!(refresh(&s, &pair, IP_A).await.is_err());
}

#[tokio::test]
async fn refresh_rejects_user_disabled_directly_in_storage() {
    let s = server(test_config());
    let (user, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;

    // Bypass the service: the flag flips but no session is ended.
    UserRepository::deactivate(s.db.as_ref(), user.id)
        .await
        .unwrap();
    s.clock.advance(ACCESS_TTL);

    let err = refresh(&s, &pair, IP_A).await.unwrap_err();
    assert!(matches!(err, AuthError::AccountDisabled), "got: {err:?}");
}

#[tokio::test]
async fn long_user_agent_is_truncated_on_a_char_boundary() {
    let s = server(test_config());
    register_and_login(&s.auth, "a@example.com", IP_A).await;
    // 3-byte chars: 512 is not a multiple of 3, so the cut must back off.
    let pair = s
        .auth
        .authentication()
        .login(
            credentials("a@example.com"),
            ClientContext {
                ip: IP_A,
                user_agent: Some("€".repeat(400)),
            },
        )
        .await
        .unwrap();
    let stored = session(&s, pair.session_id).await.user_agent.unwrap();
    assert_eq!(stored.len(), 510);
    assert!(stored.chars().all(|c| c == '€'));
}
