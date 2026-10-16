//! Enrolling, removing and resetting factors; step-up proofs; secrets at
//! rest.

mod support;

use std::time::Duration;

use z_auth::prelude::*;
use z_auth_mfa::model::{FactorStatus, MfaMethod, ProofMethod, StepUpProof};

use crate::support::*;

#[tokio::test]
async fn totp_enrollment_gives_an_otpauth_uri_and_needs_a_first_code() {
    let s = mfa_server(mfa_raw_config().totp_issuer("Acme Inc."));
    let user = register(s.auth(), "jane+mfa@example.com").await;
    let e = s
        .service()
        .begin_totp_enrollment(user.id, Some("  Work phone  ".into()))
        .await
        .unwrap();
    assert_eq!(e.secret.len(), 32, "20 bytes in base32");
    assert_eq!(
        e.otpauth_uri,
        format!(
            "otpauth://totp/Acme%20Inc.:jane%2Bmfa%40example.com?secret={}&issuer=Acme%20Inc.\
             &algorithm=SHA1&digits=6&period=30",
            e.secret
        )
    );
    assert!(!format!("{e:?}").contains(&e.secret), "secret redacted");

    // Not active until confirmed.
    assert!(s.service().factors(user.id).await.unwrap().is_empty());
    let err = s
        .service()
        .confirm_enrollment(user.id, e.factor_id, "000000")
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidSecondFactor));

    let code = totp_code(&e.secret, &s.server.clock, &default_totp(), 0);
    let confirmed = s
        .service()
        .confirm_enrollment(user.id, e.factor_id, &code)
        .await
        .unwrap();
    assert_eq!(confirmed.factor.label.as_deref(), Some("Work phone"));
    assert_eq!(confirmed.factor.method, MfaMethod::Totp);
    assert!(confirmed.factor.confirmed_at.is_some());
    let codes = confirmed.recovery_codes.unwrap();
    assert_eq!(codes.len(), 10);
    assert!(codes.iter().all(|c| c.len() == 11 && &c[5..6] == "-"));

    // Twice is not possible.
    assert!(matches!(
        s.service().begin_totp_enrollment(user.id, None).await,
        Err(AuthError::SecondFactorAlreadyEnrolled)
    ));
    assert!(matches!(
        s.service()
            .confirm_enrollment(user.id, e.factor_id, &code)
            .await,
        Err(AuthError::SecondFactorAlreadyEnrolled)
    ));
}

#[tokio::test]
async fn totp_secrets_are_sealed_at_rest() {
    let s = mfa_server(mfa_raw_config());
    let (_, e, _) = with_totp(&s, "sealed@example.com").await;
    let stored = s.server.db.mfa_factors().pop().unwrap();
    let sealed = stored.secret_sealed.clone().unwrap();
    let raw = z_auth_mfa::crypto::base32::decode(&e.secret).unwrap();
    assert!(
        !sealed.windows(raw.len()).any(|w| w == raw.as_slice()),
        "no plaintext secret in storage"
    );
    assert!(format!("{stored:?}").contains(r#"secret_sealed: Some("<redacted>")"#));
}

#[tokio::test]
async fn enrollments_expire_and_belong_to_their_user() {
    let s = mfa_server(mfa_raw_config().enrollment_ttl_secs(120));
    let user = register(s.auth(), "slow@example.com").await;
    let other = register(s.auth(), "other@example.com").await;
    let e = s
        .service()
        .begin_totp_enrollment(user.id, None)
        .await
        .unwrap();
    let code = totp_code(&e.secret, &s.server.clock, &default_totp(), 0);
    assert!(matches!(
        s.service()
            .confirm_enrollment(other.id, e.factor_id, &code)
            .await,
        Err(AuthError::SecondFactorNotFound)
    ));
    s.server.clock.advance(Duration::from_secs(121));
    let code = totp_code(&e.secret, &s.server.clock, &default_totp(), 0);
    assert!(matches!(
        s.service()
            .confirm_enrollment(user.id, e.factor_id, &code)
            .await,
        Err(AuthError::ChallengeExpired)
    ));
    // Starting over replaces the stale enrollment.
    s.service()
        .begin_totp_enrollment(user.id, None)
        .await
        .unwrap();
    let pending: Vec<_> = s
        .server
        .db
        .mfa_factors()
        .into_iter()
        .filter(|f| f.status == FactorStatus::Pending)
        .collect();
    assert_eq!(pending.len(), 1);
}

#[tokio::test]
async fn disabled_methods_cannot_be_enrolled() {
    let s = mfa_server(mfa_raw_config().methods(["email"]));
    let user = register(s.auth(), "nototp@example.com").await;
    assert!(matches!(
        s.service().begin_totp_enrollment(user.id, None).await,
        Err(AuthError::UnsupportedSecondFactor(m)) if m == "totp"
    ));
    assert!(matches!(
        s.service()
            .begin_delivered_enrollment(user.id, MfaMethod::Sms, Some("+15551234567".into()), None)
            .await,
        Err(AuthError::UnsupportedSecondFactor(m)) if m == "sms"
    ));
}

#[tokio::test]
async fn removing_a_factor_needs_a_fresh_code_and_ends_sessions() {
    let s = mfa_server(mfa_raw_config());
    let (user, e, recovery) = with_totp(&s, "remove@example.com").await;
    next_step(&s);
    let c = challenge(&s, "remove@example.com", IP_A).await;
    let code = totp_code(&e.secret, &s.server.clock, &default_totp(), 0);
    let pair = complete(&s, &c, None, &code).await.unwrap();

    // The code that logged in cannot be replayed as a proof.
    let replay = StepUpProof {
        method: ProofMethod::Factor(MfaMethod::Totp),
        code: code.clone(),
    };
    assert!(matches!(
        s.service()
            .remove_factor(user.id, e.factor_id, replay)
            .await,
        Err(AuthError::InvalidSecondFactor)
    ));
    // Unknown factors are reported before any proof is checked.
    assert!(matches!(
        s.service()
            .remove_factor(
                user.id,
                uuid::Uuid::new_v4(),
                StepUpProof {
                    method: ProofMethod::RecoveryCode,
                    code: recovery[0].clone(),
                }
            )
            .await,
        Err(AuthError::SecondFactorNotFound)
    ));

    s.service()
        .remove_factor(
            user.id,
            e.factor_id,
            StepUpProof {
                method: ProofMethod::RecoveryCode,
                code: recovery[0].clone(),
            },
        )
        .await
        .unwrap();
    let status = s.service().status(user.id).await.unwrap();
    assert!(status.factors.is_empty());
    assert_eq!(
        status.recovery_codes_left, 0,
        "they go with the last factor"
    );
    // AUTH_MFA_END_SESSIONS_ON_REMOVAL (default on).
    assert!(matches!(
        s.auth().verifier().verify(&pair.access_token),
        Err(AuthError::TokenRevoked)
    ));
    // And the next login is password-only again.
    let outcome = s
        .auth()
        .authentication()
        .login(credentials("remove@example.com"), ctx(IP_A))
        .await
        .unwrap();
    assert!(matches!(outcome, LoginOutcome::Tokens(_)));
}

#[tokio::test]
async fn regenerating_recovery_codes_replaces_the_old_set() {
    let s = mfa_server(
        mfa_raw_config()
            .recovery_code_count(4)
            .recovery_code_length(12),
    );
    let (user, e, old) = with_totp(&s, "regen@example.com").await;
    assert_eq!(old.len(), 4);
    assert_eq!(old[0].len(), 14, "12 characters in groups of five");
    next_step(&s);
    let fresh = s
        .service()
        .regenerate_recovery_codes(
            user.id,
            StepUpProof {
                method: ProofMethod::Factor(MfaMethod::Totp),
                code: totp_code(&e.secret, &s.server.clock, &default_totp(), 0),
            },
        )
        .await
        .unwrap();
    assert_eq!(fresh.len(), 4);
    assert!(fresh.iter().all(|c| !old.contains(c)));

    let c = challenge(&s, "regen@example.com", IP_A).await;
    assert!(matches!(
        complete(&s, &c, Some("recovery_code"), &old[0]).await,
        Err(AuthError::InvalidSecondFactor)
    ));
    complete(&s, &c, Some("recovery_code"), &fresh[0])
        .await
        .unwrap();
}

#[tokio::test]
async fn reset_deletes_everything_and_ends_sessions() {
    let s = mfa_server(mfa_raw_config());
    let (user, e, _) = with_totp(&s, "reset@example.com").await;
    next_step(&s);
    let c = challenge(&s, "reset@example.com", IP_A).await;
    let code = totp_code(&e.secret, &s.server.clock, &default_totp(), 0);
    let pair = complete(&s, &c, None, &code).await.unwrap();

    assert_eq!(s.service().reset(user.id).await.unwrap(), 1);
    assert!(s.server.db.mfa_factors().is_empty());
    assert!(s.auth().verifier().verify(&pair.access_token).is_err());
    assert_eq!(s.service().reset(user.id).await.unwrap(), 0);
}

#[tokio::test]
async fn sessions_survive_removal_when_configured() {
    let s = mfa_server(mfa_raw_config().end_sessions_on_removal(false));
    let (user, e, recovery) = with_totp(&s, "keep@example.com").await;
    next_step(&s);
    let c = challenge(&s, "keep@example.com", IP_A).await;
    let code = totp_code(&e.secret, &s.server.clock, &default_totp(), 0);
    let pair = complete(&s, &c, None, &code).await.unwrap();
    s.service()
        .remove_factor(
            user.id,
            e.factor_id,
            StepUpProof {
                method: ProofMethod::RecoveryCode,
                code: recovery[1].clone(),
            },
        )
        .await
        .unwrap();
    assert!(s.auth().verifier().verify(&pair.access_token).is_ok());
}
