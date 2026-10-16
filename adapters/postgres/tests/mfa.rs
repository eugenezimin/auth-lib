//! Integration tests — z-auth-mfa's store against Postgres (feature `mfa`).
//!
//! Every compare-and-swap is raced from several tasks: exactly one (or
//! exactly `max`) may win.  Timestamps and expiry come from the database.
//!
//! Run with:
//!   cargo test -p z-auth-postgres --features mfa --test mfa

mod helpers;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;
use z_auth::AuthError;
use z_auth::ZAuth;
use z_auth::conf::config::RawConfig;
use z_auth::identity::user::{RegisterUser, User};
use z_auth::security::authentication::{
    ClientContext, Credentials, LoginOutcome, SecondFactorProof,
};
use z_auth::security::token::keys::{generate_refresh_secret, generate_signing_key};
use z_auth_mfa::config::RawMfaConfig;
use z_auth_mfa::crypto::{base32, totp};
use z_auth_mfa::model::{
    FactorStatus, MfaMethod, NewChallenge, NewCode, NewFactor, SendOutcome, TotpAlgorithm,
    TotpParams,
};
use z_auth_mfa::repository::{CodeLimits, MfaRepository};
use z_auth_mfa::{CodeDelivery, CodeSender, Mfa};
use z_auth_postgres::{PgMfaRepository, repositories};

use crate::helpers::{cleanup_user_by_id, create_test_user, mfa_pool, unique_email};

const PASSWORD: &str = "Blablabla1!";
const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
const HOUR: Duration = Duration::from_secs(3_600);

/// Base64 of 32 bytes of 0x01 / 0x02.
const ENCRYPTION_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const HASH_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

const TOTP: TotpParams = TotpParams {
    algorithm: TotpAlgorithm::Sha1,
    digits: 6,
    period_secs: 30,
};

#[derive(Default)]
struct Outbox(Mutex<Vec<CodeDelivery>>);

#[async_trait]
impl CodeSender for Outbox {
    async fn send(&self, delivery: CodeDelivery) -> Result<(), AuthError> {
        self.0.lock().unwrap().push(delivery);
        Ok(())
    }
}

struct Setup {
    auth: ZAuth,
    mfa: Arc<Mfa>,
    repo: Arc<PgMfaRepository>,
    outbox: Arc<Outbox>,
}

async fn setup() -> Setup {
    let pool = mfa_pool().await;
    let keys = generate_signing_key().unwrap();
    let config = RawConfig::default()
        .jwt_signing_key(keys.signing_key)
        .jwt_issuer("z-auth-test")
        .refresh_secret(generate_refresh_secret().unwrap())
        .build()
        .unwrap();
    let repo = Arc::new(PgMfaRepository::new(pool.clone()));
    let outbox = Arc::new(Outbox::default());
    let settings = RawMfaConfig::default()
        .encryption_key(ENCRYPTION_KEY)
        .hash_key(HASH_KEY)
        .methods(["totp", "email"])
        .build()
        .unwrap();
    let mfa = Arc::new(Mfa::new(settings, repo.clone()).with_code_sender(outbox.clone()));
    let auth = ZAuth::builder(config, repositories(&pool))
        .extension(mfa.clone())
        .build()
        .unwrap();
    Setup {
        auth,
        mfa,
        repo,
        outbox,
    }
}

async fn user(s: &Setup) -> User {
    create_test_user(
        &s.auth,
        RegisterUser {
            email: unique_email("mfa"),
            password: PASSWORD.into(),
            username: None,
            first_name: None,
            last_name: None,
        },
    )
    .await
}

fn now_code(secret_b32: &str, offset_steps: i64) -> String {
    let key = base32::decode(secret_b32).unwrap();
    let at = chrono::Utc::now().timestamp() + offset_steps * 30;
    totp::totp(&key, at, &TOTP)
}

fn delivered_factor(user_id: Uuid) -> NewFactor {
    NewFactor {
        id: Uuid::new_v4(),
        user_id,
        method: MfaMethod::Email,
        label: None,
        secret_sealed: None,
        totp: None,
        destination_sealed: Some(vec![1, 2, 3]),
        destination_hint: Some("a***@b.io".into()),
    }
}

fn new_challenge(user_id: Uuid) -> NewChallenge {
    NewChallenge {
        id: Uuid::new_v4(),
        user_id,
        secret_hash: [7; 32],
        created_ip: IP,
        user_agent: Some("pg-test".into()),
        fingerprint_hash: Some([9; 32]),
    }
}

#[tokio::test]
async fn test_totp_login_end_to_end_against_postgres() {
    let s = setup().await;
    let user = user(&s).await;
    let service = s.mfa.service().unwrap();

    let e = service
        .begin_totp_enrollment(user.id, Some("phone".into()))
        .await
        .unwrap();
    // The previous step: the login below uses the current one.
    let confirmed = service
        .confirm_enrollment(user.id, e.factor_id, &now_code(&e.secret, -1))
        .await
        .unwrap();
    assert_eq!(confirmed.recovery_codes.as_ref().unwrap().len(), 10);
    let stored = s.repo.list_factors(user.id).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].status, FactorStatus::Active);
    assert_eq!(stored[0].totp, Some(TOTP));
    assert_eq!(stored[0].label.as_deref(), Some("phone"));

    let ctx = ClientContext::new(IP);
    let LoginOutcome::SecondFactor(challenge) = s
        .auth
        .authentication()
        .login(
            Credentials {
                email: user.email.clone(),
                password: PASSWORD.into(),
            },
            ctx.clone(),
        )
        .await
        .unwrap()
    else {
        panic!("expected a challenge");
    };
    let pair = s
        .auth
        .authentication()
        .complete_login(
            SecondFactorProof {
                challenge_token: challenge.challenge_token.clone(),
                method: Some("totp".into()),
                code: now_code(&e.secret, 0),
            },
            ctx.clone(),
        )
        .await
        .unwrap();
    let claims = s.auth.verifier().verify(&pair.access_token).unwrap();
    assert_eq!(claims.amr, ["mfa", "otp", "pwd"]);

    // A recovery code, once.
    let code = confirmed.recovery_codes.unwrap()[0].clone();
    for expect_ok in [true, false] {
        let LoginOutcome::SecondFactor(challenge) = s
            .auth
            .authentication()
            .login(
                Credentials {
                    email: user.email.clone(),
                    password: PASSWORD.into(),
                },
                ctx.clone(),
            )
            .await
            .unwrap()
        else {
            panic!("expected a challenge");
        };
        let result = s
            .auth
            .authentication()
            .complete_login(
                SecondFactorProof {
                    challenge_token: challenge.challenge_token,
                    method: None,
                    code: code.clone(),
                },
                ctx.clone(),
            )
            .await;
        assert_eq!(result.is_ok(), expect_ok);
    }
    assert_eq!(s.repo.count_recovery_codes(user.id).await.unwrap(), 9);

    // Deleting the user cascades.
    cleanup_user_by_id(&s.auth, user.id).await.unwrap();
    assert!(s.repo.list_factors(user.id).await.unwrap().is_empty());
    assert_eq!(s.repo.count_recovery_codes(user.id).await.unwrap(), 0);
}

#[tokio::test]
async fn test_email_codes_are_sent_and_rate_limited() {
    let s = setup().await;
    let user = user(&s).await;
    let service = s.mfa.service().unwrap();
    let pending = service
        .begin_delivered_enrollment(user.id, MfaMethod::Email, None, None)
        .await
        .unwrap();
    assert!(matches!(
        service
            .resend_enrollment_code(user.id, pending.factor_id)
            .await,
        Err(AuthError::CodeResendTooSoon)
    ));
    let code = s.outbox.0.lock().unwrap().last().unwrap().code.clone();
    service
        .confirm_enrollment(user.id, pending.factor_id, &code)
        .await
        .unwrap();
    assert!(matches!(
        service
            .begin_delivered_enrollment(user.id, MfaMethod::Email, None, None)
            .await,
        Err(AuthError::SecondFactorAlreadyEnrolled)
    ));
    cleanup_user_by_id(&s.auth, user.id).await.unwrap();
}

#[tokio::test]
async fn test_factor_lifecycle_and_unique_active_method() {
    let s = setup().await;
    let user = user(&s).await;

    // Expired at birth: cannot be activated.
    let stale = s
        .repo
        .insert_pending_factor(delivered_factor(user.id), Duration::ZERO)
        .await
        .unwrap();
    assert!(
        !s.repo
            .activate_factor(stale.id, user.id, None)
            .await
            .unwrap()
    );

    // A new pending enrollment of the method replaces the old one.
    let first = s
        .repo
        .insert_pending_factor(delivered_factor(user.id), HOUR)
        .await
        .unwrap();
    assert!(s.repo.find_factor(stale.id).await.unwrap().is_none());
    assert_eq!(first.status, FactorStatus::Pending);
    assert!(first.expires_at.unwrap() > first.created_at);
    assert!(
        !s.repo
            .activate_factor(first.id, Uuid::new_v4(), None)
            .await
            .unwrap()
    );
    assert!(
        s.repo
            .activate_factor(first.id, user.id, None)
            .await
            .unwrap()
    );
    assert!(
        !s.repo
            .activate_factor(first.id, user.id, None)
            .await
            .unwrap(),
        "once"
    );

    let second = s
        .repo
        .insert_pending_factor(delivered_factor(user.id), HOUR)
        .await
        .unwrap();
    assert!(matches!(
        s.repo.activate_factor(second.id, user.id, None).await,
        Err(AuthError::SecondFactorAlreadyEnrolled)
    ));

    let (active, _) = s.repo.find_factor(first.id).await.unwrap().unwrap();
    assert!(active.confirmed_at.is_some() && active.expires_at.is_none());
    assert!(
        !s.repo
            .delete_factor(first.id, Uuid::new_v4())
            .await
            .unwrap()
    );
    assert!(s.repo.delete_factor(first.id, user.id).await.unwrap());
    cleanup_user_by_id(&s.auth, user.id).await.unwrap();
}

#[tokio::test]
async fn test_compare_and_swaps_have_one_winner() {
    let s = setup().await;
    let user = user(&s).await;
    let factor = s
        .repo
        .insert_pending_factor(delivered_factor(user.id), HOUR)
        .await
        .unwrap();
    s.repo
        .activate_factor(factor.id, user.id, None)
        .await
        .unwrap();

    // TOTP steps.
    let wins = race(
        8,
        |repo| async move { repo.advance_totp_step(factor.id, 42).await },
        &s,
    )
    .await;
    assert_eq!(wins.iter().filter(|w| **w).count(), 1);
    assert!(
        !s.repo.advance_totp_step(factor.id, 41).await.unwrap(),
        "no going back"
    );
    assert!(s.repo.advance_totp_step(factor.id, 43).await.unwrap());

    // Recovery codes.
    s.repo
        .replace_recovery_codes(user.id, &[[1; 32], [2; 32]])
        .await
        .unwrap();
    let wins = race(
        8,
        |repo| async move { repo.consume_recovery_code(user.id, &[1; 32]).await },
        &s,
    )
    .await;
    assert_eq!(wins.iter().filter(|w| **w).count(), 1);
    assert_eq!(s.repo.count_recovery_codes(user.id).await.unwrap(), 1);
    s.repo.replace_recovery_codes(user.id, &[]).await.unwrap();
    assert_eq!(s.repo.count_recovery_codes(user.id).await.unwrap(), 0);

    // Challenge attempts and consumption.
    let challenge = s
        .repo
        .create_challenge(new_challenge(user.id), HOUR)
        .await
        .unwrap();
    let attempts = race(
        10,
        |repo| async move { repo.record_challenge_attempt(challenge.id, 3).await },
        &s,
    )
    .await;
    let mut counted: Vec<u32> = attempts.into_iter().flatten().collect();
    counted.sort();
    assert_eq!(counted, [1, 2, 3]);
    let wins = race(
        8,
        |repo| async move { repo.consume_challenge(challenge.id).await },
        &s,
    )
    .await;
    assert_eq!(wins.iter().filter(|w| **w).count(), 1);
    assert!(
        s.repo
            .record_challenge_attempt(challenge.id, 10)
            .await
            .unwrap()
            .is_none(),
        "consumed"
    );
    cleanup_user_by_id(&s.auth, user.id).await.unwrap();
}

/// Run `n` copies of `f` concurrently.
async fn race<T, F, Fut>(n: usize, f: F, s: &Setup) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(Arc<PgMfaRepository>) -> Fut,
    Fut: std::future::Future<Output = Result<T, AuthError>> + Send + 'static,
{
    let tasks: Vec<_> = (0..n).map(|_| tokio::spawn(f(s.repo.clone()))).collect();
    let mut out = Vec::with_capacity(n);
    for t in tasks {
        out.push(t.await.unwrap().unwrap());
    }
    out
}

#[tokio::test]
async fn test_codes_respect_cooldown_send_limit_and_attempts() {
    let s = setup().await;
    let user = user(&s).await;
    let challenge = s
        .repo
        .create_challenge(new_challenge(user.id), HOUR)
        .await
        .unwrap();
    let (stored, now) = s.repo.find_challenge(challenge.id).await.unwrap().unwrap();
    assert_eq!(stored.fingerprint_hash, Some([9; 32]));
    assert_eq!(stored.created_ip, IP);
    assert!(stored.expires_at > now);

    let factor_id = Uuid::new_v4();
    let code = |hash: u8| NewCode {
        code_hash: [hash; 32],
        factor_id,
    };
    let cooldown = CodeLimits {
        ttl: HOUR,
        resend_after: HOUR,
        max_sends: 5,
    };
    assert!(matches!(
        s.repo
            .set_challenge_code(challenge.id, code(1), cooldown)
            .await
            .unwrap(),
        SendOutcome::Stored { .. }
    ));
    assert_eq!(
        s.repo
            .set_challenge_code(challenge.id, code(2), cooldown)
            .await
            .unwrap(),
        SendOutcome::TooSoon
    );
    let no_cooldown = CodeLimits {
        resend_after: Duration::ZERO,
        max_sends: 2,
        ..cooldown
    };
    assert!(matches!(
        s.repo
            .set_challenge_code(challenge.id, code(3), no_cooldown)
            .await
            .unwrap(),
        SendOutcome::Stored { .. }
    ));
    assert_eq!(
        s.repo
            .set_challenge_code(challenge.id, code(4), no_cooldown)
            .await
            .unwrap(),
        SendOutcome::LimitReached
    );
    let (stored, _) = s.repo.find_challenge(challenge.id).await.unwrap().unwrap();
    let sent = stored.code.unwrap();
    assert_eq!(
        (sent.factor_id, sent.code.code_hash, sent.code.sends),
        (factor_id, [3; 32], 2)
    );
    assert_eq!(
        s.repo
            .set_challenge_code(Uuid::new_v4(), code(5), no_cooldown)
            .await
            .unwrap(),
        SendOutcome::NotFound
    );

    // Factor codes: attempts are bounded per code and reset by a new one.
    let factor = s
        .repo
        .insert_pending_factor(delivered_factor(user.id), HOUR)
        .await
        .unwrap();
    assert_eq!(
        s.repo.record_factor_attempt(factor.id, 2).await.unwrap(),
        None,
        "no code"
    );
    s.repo
        .set_factor_code(factor.id, [6; 32], no_cooldown)
        .await
        .unwrap();
    assert_eq!(
        s.repo.record_factor_attempt(factor.id, 2).await.unwrap(),
        Some(1)
    );
    assert_eq!(
        s.repo.record_factor_attempt(factor.id, 2).await.unwrap(),
        Some(2)
    );
    assert_eq!(
        s.repo.record_factor_attempt(factor.id, 2).await.unwrap(),
        None
    );
    s.repo
        .set_factor_code(factor.id, [7; 32], no_cooldown)
        .await
        .unwrap();
    assert_eq!(
        s.repo.record_factor_attempt(factor.id, 2).await.unwrap(),
        Some(1)
    );
    s.repo.mark_factor_used(factor.id).await.unwrap();
    let (f, _) = s.repo.find_factor(factor.id).await.unwrap().unwrap();
    assert!(f.code.is_none() && f.last_used_at.is_some());
    cleanup_user_by_id(&s.auth, user.id).await.unwrap();
}

#[tokio::test]
async fn test_failures_lock_and_clear() {
    let s = setup().await;
    let user = user(&s).await;
    let state = s.repo.lock_state(user.id).await.unwrap();
    assert_eq!((state.failures, state.locked_until), (0, None));

    for expected in [1, 2] {
        let state = s.repo.record_failure(user.id, HOUR, 3, HOUR).await.unwrap();
        assert_eq!(state.failures, expected);
        assert!(!state.is_locked());
    }
    let state = s.repo.record_failure(user.id, HOUR, 3, HOUR).await.unwrap();
    assert!(state.is_locked(), "third failure locks");
    assert_eq!(state.failures, 0, "and restarts the count");
    assert!(s.repo.lock_state(user.id).await.unwrap().is_locked());

    // An old window restarts the count.
    s.repo.clear_failures(user.id).await.unwrap();
    s.repo.record_failure(user.id, HOUR, 3, HOUR).await.unwrap();
    let state = s
        .repo
        .record_failure(user.id, Duration::ZERO, 3, HOUR)
        .await
        .unwrap();
    assert_eq!(state.failures, 1);
    s.repo.clear_failures(user.id).await.unwrap();
    assert!(!s.repo.lock_state(user.id).await.unwrap().is_locked());
    cleanup_user_by_id(&s.auth, user.id).await.unwrap();
}

#[tokio::test]
async fn test_delete_all_and_purge() {
    let s = setup().await;
    let user = user(&s).await;
    let active = s
        .repo
        .insert_pending_factor(delivered_factor(user.id), HOUR)
        .await
        .unwrap();
    s.repo
        .activate_factor(active.id, user.id, None)
        .await
        .unwrap();
    s.repo
        .insert_pending_factor(
            NewFactor {
                method: MfaMethod::Sms,
                ..delivered_factor(user.id)
            },
            Duration::ZERO,
        )
        .await
        .unwrap();
    let expired = s
        .repo
        .create_challenge(new_challenge(user.id), Duration::ZERO)
        .await
        .unwrap();
    let open = s
        .repo
        .create_challenge(new_challenge(user.id), HOUR)
        .await
        .unwrap();

    // Other tests' rows may be purged too; ours must be.
    assert!(s.repo.purge(Duration::ZERO).await.unwrap() >= 2);
    assert!(s.repo.find_challenge(expired.id).await.unwrap().is_none());
    assert!(s.repo.find_challenge(open.id).await.unwrap().is_some());
    let left = s.repo.list_factors(user.id).await.unwrap();
    assert_eq!(left.len(), 1, "the expired enrollment went");

    s.repo
        .replace_recovery_codes(user.id, &[[3; 32]])
        .await
        .unwrap();
    s.repo.record_failure(user.id, HOUR, 5, HOUR).await.unwrap();
    assert_eq!(s.repo.delete_all(user.id).await.unwrap(), 1);
    assert!(s.repo.list_factors(user.id).await.unwrap().is_empty());
    assert!(s.repo.find_challenge(open.id).await.unwrap().is_none());
    assert_eq!(s.repo.count_recovery_codes(user.id).await.unwrap(), 0);
    assert_eq!(s.repo.lock_state(user.id).await.unwrap().failures, 0);
    cleanup_user_by_id(&s.auth, user.id).await.unwrap();
}
