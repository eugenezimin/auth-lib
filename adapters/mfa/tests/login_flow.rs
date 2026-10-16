//! Logging in with TOTP and recovery codes, against the in-memory store.
//!
//! Invariants checked here:
//! - users with a factor get a challenge, never tokens, from the password;
//! - a challenge takes `AUTH_MFA_CHALLENGE_MAX_ATTEMPTS` codes, once;
//! - a TOTP step and a recovery code are accepted once;
//! - failures across challenges lock the user out for a while;
//! - the enforcement policy decides what users without a factor get.

mod support;

use std::time::Duration;

use z_auth::prelude::*;
use z_auth_mfa::config::RawMfaConfig;

use crate::support::*;

#[tokio::test]
async fn totp_users_are_challenged_and_their_sessions_carry_mfa() {
    let s = mfa_server(mfa_raw_config());
    let (user, enrollment, recovery) = with_totp(&s, "totp@example.com").await;
    assert_eq!(recovery.len(), 10, "issued with the first factor");

    let c = challenge(&s, "totp@example.com", IP_A).await;
    assert_eq!(c.methods, ["totp", "recovery_code"]);
    assert!(c.delivery.is_none(), "nothing to send for TOTP");
    assert!(c.challenge_token.starts_with("mfa1."));

    next_step(&s);
    let code = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);
    let pair = complete(&s, &c, Some("totp"), &code).await.unwrap();
    let first = claims(&s, &pair);
    assert_eq!(first.sub, user.id);
    assert_eq!(first.amr, ["mfa", "otp", "pwd"]);
    assert!(s.auth().authorizer().require_mfa(&first).is_ok());

    // Refreshes keep it.
    s.server.clock.advance(Duration::from_secs(301));
    let next = s
        .auth()
        .authentication()
        .refresh(&pair.access_token, &pair.refresh_token, ctx(IP_A))
        .await
        .unwrap();
    assert_eq!(claims(&s, &next).amr, ["mfa", "otp", "pwd"]);

    // The challenge was single-use.
    assert!(matches!(
        complete(&s, &c, Some("totp"), &code).await,
        Err(AuthError::ChallengeExpired)
    ));
}

#[tokio::test]
async fn a_totp_code_works_once_and_neighbouring_steps_are_accepted() {
    let s = mfa_server(mfa_raw_config());
    let (_, enrollment, _) = with_totp(&s, "replay@example.com").await;
    next_step(&s);
    let code = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);

    let c = challenge(&s, "replay@example.com", IP_A).await;
    complete(&s, &c, None, &code).await.unwrap();

    // Replaying the same code on a new challenge fails.
    let c = challenge(&s, "replay@example.com", IP_A).await;
    assert!(matches!(
        complete(&s, &c, None, &code).await,
        Err(AuthError::InvalidSecondFactor)
    ));
    // The next step's code (a phone clock running ahead) is fine.
    let ahead = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 1);
    complete(&s, &c, None, &ahead).await.unwrap();
    // …which also burns the current step: no going back.
    let c = challenge(&s, "replay@example.com", IP_A).await;
    let current = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);
    assert!(matches!(
        complete(&s, &c, None, &current).await,
        Err(AuthError::InvalidSecondFactor)
    ));
}

#[tokio::test]
async fn a_challenge_takes_a_bounded_number_of_attempts() {
    let s = mfa_server(mfa_raw_config().challenge_max_attempts(3));
    let (_, enrollment, _) = with_totp(&s, "attempts@example.com").await;
    let c = challenge(&s, "attempts@example.com", IP_A).await;
    for _ in 0..3 {
        assert!(matches!(
            complete(&s, &c, Some("totp"), "000000").await,
            Err(AuthError::InvalidSecondFactor)
        ));
    }
    next_step(&s);
    let good = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);
    assert!(matches!(
        complete(&s, &c, Some("totp"), &good).await,
        Err(AuthError::ChallengeExpired)
    ));
    // A new login gets a new challenge.
    let c = challenge(&s, "attempts@example.com", IP_A).await;
    complete(&s, &c, Some("totp"), &good).await.unwrap();
}

#[tokio::test]
async fn failures_across_challenges_lock_the_user_out_for_a_while() {
    let s = mfa_server(
        mfa_raw_config()
            .lockout_threshold(4)
            .lockout_secs(600)
            .challenge_max_attempts(2),
    );
    let (_, enrollment, _) = with_totp(&s, "lock@example.com").await;
    let mut last = None;
    for _ in 0..2 {
        let c = challenge(&s, "lock@example.com", IP_A).await;
        for _ in 0..2 {
            last = Some(complete(&s, &c, Some("totp"), "000000").await.unwrap_err());
        }
    }
    assert!(matches!(last, Some(AuthError::SecondFactorLocked)));

    // Locked: even the password step is refused, and a correct code too.
    let err = s
        .auth()
        .authentication()
        .login(credentials("lock@example.com"), ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::SecondFactorLocked));

    s.server.clock.advance(Duration::from_secs(601));
    let c = challenge(&s, "lock@example.com", IP_A).await;
    let code = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);
    complete(&s, &c, Some("totp"), &code).await.unwrap();
}

#[tokio::test]
async fn recovery_codes_work_once_and_in_any_spelling() {
    let s = mfa_server(mfa_raw_config());
    let (_, _, recovery) = with_totp(&s, "recover@example.com").await;
    let code = &recovery[3];

    let c = challenge(&s, "recover@example.com", IP_A).await;
    let typed = code.to_lowercase().replace('-', " ");
    let pair = complete(&s, &c, None, &typed).await.unwrap();
    assert_eq!(claims(&s, &pair).amr, ["mfa", "otp", "pwd"]);

    let c = challenge(&s, "recover@example.com", IP_A).await;
    assert!(matches!(
        complete(&s, &c, Some("recovery_code"), code).await,
        Err(AuthError::InvalidSecondFactor)
    ));
    let status = s.service().status(pair_user(&s, &pair)).await.unwrap();
    assert_eq!(status.recovery_codes_left, 9);
}

fn pair_user(s: &MfaServer, pair: &TokenPair) -> uuid::Uuid {
    claims(s, pair).sub
}

#[tokio::test]
async fn challenges_expire_and_can_be_bound_to_the_client() {
    let s = mfa_server(
        mfa_raw_config()
            .challenge_ttl_secs(60)
            .challenge_match("ip"),
    );
    let (_, enrollment, _) = with_totp(&s, "bound@example.com").await;
    next_step(&s);
    let code = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);

    let c = challenge(&s, "bound@example.com", IP_A).await;
    let from_elsewhere = s
        .auth()
        .authentication()
        .complete_login(proof(&c, None, &code), ctx(IP_B))
        .await;
    assert!(matches!(from_elsewhere, Err(AuthError::ChallengeExpired)));

    s.server.clock.advance(Duration::from_secs(61));
    let code = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);
    assert!(matches!(
        complete(&s, &c, None, &code).await,
        Err(AuthError::ChallengeExpired)
    ));

    // Garbage and forged tokens look the same.
    let forged = LoginChallenge {
        challenge_token: format!("{}AAAA", &c.challenge_token[..c.challenge_token.len() - 4]),
        ..c.clone()
    };
    for bad in [
        &forged,
        &LoginChallenge {
            challenge_token: "nonsense".into(),
            ..c.clone()
        },
    ] {
        assert!(matches!(
            complete(&s, bad, None, &code).await,
            Err(AuthError::ChallengeExpired)
        ));
    }
}

#[tokio::test]
async fn a_pending_login_evicts_no_session_and_rechecks_the_account() {
    let config = raw_config().max_sessions_per_user(1).build().unwrap();
    let s = mfa_server_with(mfa_raw_config(), config);
    let (user, enrollment, _) = with_totp(&s, "evict@example.com").await;
    next_step(&s);
    let c = challenge(&s, "evict@example.com", IP_A).await;
    let code = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);
    let pair = complete(&s, &c, None, &code).await.unwrap();

    // Someone with only the password: the session survives.
    let _ = challenge(&s, "evict@example.com", IP_B).await;
    assert!(s.auth().verifier().verify(&pair.access_token).is_ok());

    // Deactivated between the two steps: no session.
    next_step(&s);
    let c = challenge(&s, "evict@example.com", IP_A).await;
    s.auth().users().deactivate(user.id).await.unwrap();
    let code = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);
    assert!(matches!(
        complete(&s, &c, None, &code).await,
        Err(AuthError::AccountDisabled)
    ));
}

// ── Enforcement ──────────────────────────────────────────────────────────────

async fn password_login(s: &MfaServer, email: &str) -> Result<LoginOutcome, AuthError> {
    s.auth()
        .authentication()
        .login(credentials(email), ctx(IP_A))
        .await
}

#[tokio::test]
async fn optional_lets_unenrolled_users_in_with_password_tokens() {
    let s = mfa_server(mfa_raw_config());
    register(s.auth(), "plain@example.com").await;
    let pair = password_login(&s, "plain@example.com")
        .await
        .unwrap()
        .into_tokens()
        .unwrap();
    let c = claims(&s, &pair);
    assert_eq!(c.amr, ["pwd"]);
    assert!(matches!(
        s.auth().authorizer().require_mfa(&c),
        Err(AuthError::SecondFactorRequired)
    ));
    let status = s.service().status(c.sub).await.unwrap();
    assert!(!status.required && status.factors.is_empty());
}

#[tokio::test]
async fn required_allows_or_denies_unenrolled_users() {
    let allow = mfa_server(mfa_raw_config().enforcement("required"));
    let user = register(allow.auth(), "allow@example.com").await;
    let outcome = password_login(&allow, "allow@example.com").await.unwrap();
    assert!(
        matches!(outcome, LoginOutcome::Tokens(_)),
        "so they can enroll"
    );
    assert!(allow.service().status(user.id).await.unwrap().required);

    let deny = mfa_server(mfa_raw_config().enforcement("required").unenrolled("deny"));
    register(deny.auth(), "deny@example.com").await;
    assert!(matches!(
        password_login(&deny, "deny@example.com").await,
        Err(AuthError::SecondFactorNotEnrolled)
    ));
}

#[tokio::test]
async fn roles_enforcement_only_requires_listed_roles() {
    let s = mfa_server(
        mfa_raw_config()
            .enforcement("roles")
            .required_roles(["admin"])
            .unenrolled("deny"),
    );
    let admin = register(s.auth(), "admin@example.com").await;
    register(s.auth(), "user@example.com").await;
    let role = s.auth().roles().create(&new_role("Admin")).await.unwrap();
    s.auth().roles().assign(admin.id, role.id).await.unwrap();

    assert!(matches!(
        password_login(&s, "admin@example.com").await,
        Err(AuthError::SecondFactorNotEnrolled)
    ));
    assert!(matches!(
        password_login(&s, "user@example.com").await,
        Ok(LoginOutcome::Tokens(_))
    ));
    // Enrolled non-admins are still challenged.
    let (_, _, _) = with_totp(&s, "enrolled@example.com").await;
    assert!(matches!(
        password_login(&s, "enrolled@example.com").await,
        Ok(LoginOutcome::SecondFactor(_))
    ));
}

#[tokio::test]
async fn enforcement_off_never_challenges() {
    let s = mfa_server(mfa_raw_config().enforcement("off"));
    with_totp(&s, "off@example.com").await;
    assert!(matches!(
        password_login(&s, "off@example.com").await,
        Ok(LoginOutcome::Tokens(_))
    ));
}

// ── Housekeeping ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn tick_purges_expired_challenges_now_and_then() {
    let s = mfa_server(
        mfa_raw_config()
            .challenge_ttl_secs(60)
            .purge_retention_secs(0)
            .purge_interval_secs(300),
    );
    with_totp(&s, "purge@example.com").await;
    let _ = challenge(&s, "purge@example.com", IP_A).await;
    let _ = challenge(&s, "purge@example.com", IP_A).await;
    assert_eq!(s.server.db.mfa_challenges().len(), 2);

    // The first tick purges (nothing expired yet), the next ones wait.
    let report = s.auth().tick().await.unwrap();
    assert_eq!(
        report
            .extension::<z_auth_mfa::MfaTickReport>()
            .unwrap()
            .purged,
        0
    );
    s.server.clock.advance(Duration::from_secs(120));
    let report = s.auth().tick().await.unwrap();
    assert!(report.extension::<z_auth_mfa::MfaTickReport>().is_none());

    s.server.clock.advance(Duration::from_secs(300));
    let report = s.auth().tick().await.unwrap();
    assert_eq!(
        report
            .extension::<z_auth_mfa::MfaTickReport>()
            .unwrap()
            .purged,
        2
    );
    assert!(s.server.db.mfa_challenges().is_empty());
}

#[tokio::test]
async fn deleting_a_user_deletes_their_factors() {
    let s = mfa_server(
        RawMfaConfig::default()
            .hash_key(HASH_KEY)
            .encryption_key(ENCRYPTION_KEY),
    );
    let (user, _, _) = with_totp(&s, "gone@example.com").await;
    assert_eq!(s.server.db.mfa_factors().len(), 1);
    s.auth().users().delete(user.id).await.unwrap();
    assert!(s.server.db.mfa_factors().is_empty());
}
