//! Email and SMS factors: enrollment, codes sent at login, resend limits,
//! step-up codes and delivery failures.

mod support;

use std::sync::Arc;
use std::time::Duration;

use z_auth::prelude::*;
use z_auth_mfa::model::{MfaMethod, ProofMethod, StepUpProof};
use z_auth_mfa::{CodePurpose, Mfa};

use crate::support::*;

const PHONE: &str = "+15551234567";

fn both() -> z_auth_mfa::config::RawMfaConfig {
    mfa_raw_config()
        .methods(["totp", "email", "sms"])
        .code_resend_secs(30)
        .code_max_sends(3)
}

/// Register and enroll email (the account's address).
async fn with_email(s: &MfaServer, email: &str) -> User {
    let user = register(s.auth(), email).await;
    let pending = s
        .service()
        .begin_delivered_enrollment(user.id, MfaMethod::Email, None, None)
        .await
        .unwrap();
    assert_eq!(pending.method, MfaMethod::Email);
    let code = s.sender.last_code(email).expect("enrollment code sent");
    s.service()
        .confirm_enrollment(user.id, pending.factor_id, &code)
        .await
        .unwrap();
    user
}

#[tokio::test]
async fn email_enrollment_defaults_to_the_account_address() {
    let s = mfa_server(both());
    let user = register(s.auth(), "jane.doe@example.com").await;
    let pending = s
        .service()
        .begin_delivered_enrollment(user.id, MfaMethod::Email, None, Some("mail".into()))
        .await
        .unwrap();
    assert_eq!(pending.destination_hint, "j*******@example.com");
    let sent = s.sender.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].purpose, CodePurpose::Enrollment);
    assert_eq!(sent[0].destination, "jane.doe@example.com");
    assert_eq!(sent[0].code.len(), 6);
    assert!(!format!("{:?}", sent[0]).contains(&sent[0].code));

    // A wrong code, then the right one.
    assert!(matches!(
        s.service()
            .confirm_enrollment(user.id, pending.factor_id, "000000")
            .await,
        Err(AuthError::InvalidSecondFactor)
    ));
    let confirmed = s
        .service()
        .confirm_enrollment(user.id, pending.factor_id, &sent[0].code)
        .await
        .unwrap();
    assert_eq!(
        confirmed.factor.destination_hint.as_deref(),
        Some("j*******@example.com")
    );
    assert!(confirmed.recovery_codes.is_some());
}

#[tokio::test]
async fn logins_send_the_code_right_away_without_totp() {
    let s = mfa_server(both());
    with_email(&s, "mail@example.com").await;
    let c = challenge(&s, "mail@example.com", IP_A).await;
    assert_eq!(c.methods, ["email", "recovery_code"]);
    let delivery = c.delivery.clone().expect("auto-sent");
    assert_eq!(delivery.method, "email");
    let sent = s.sender.sent();
    assert_eq!(sent.last().unwrap().purpose, CodePurpose::Login);
    let code = s.sender.last_code("mail@example.com").unwrap();

    let pair = complete(&s, &c, Some("email"), &code).await.unwrap();
    assert_eq!(claims(&s, &pair).amr, ["mfa", "otp", "pwd"]);
}

#[tokio::test]
async fn sms_sessions_carry_the_sms_method() {
    let s = mfa_server(both());
    let user = register(s.auth(), "sms@example.com").await;
    let pending = s
        .service()
        .begin_delivered_enrollment(
            user.id,
            MfaMethod::Sms,
            Some("+1 (555) 123-4567".into()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(pending.destination_hint, "*******4567");
    let code = s.sender.last_code(PHONE).unwrap();
    s.service()
        .confirm_enrollment(user.id, pending.factor_id, &code)
        .await
        .unwrap();

    let c = challenge(&s, "sms@example.com", IP_A).await;
    let code = s.sender.last_code(PHONE).unwrap();
    // The code proves SMS only.
    assert!(matches!(
        complete(&s, &c, Some("email"), &code).await,
        Err(AuthError::InvalidSecondFactor)
    ));
    let pair = complete(&s, &c, None, &code).await.unwrap();
    assert_eq!(claims(&s, &pair).amr, ["mfa", "pwd", "sms"]);
}

#[tokio::test]
async fn phone_numbers_must_be_international() {
    let s = mfa_server(both());
    let user = register(s.auth(), "badphone@example.com").await;
    for bad in [None, Some("5551234567"), Some("+12")] {
        assert!(matches!(
            s.service()
                .begin_delivered_enrollment(user.id, MfaMethod::Sms, bad.map(Into::into), None)
                .await,
            Err(AuthError::InvalidDestination(_))
        ));
    }
    assert!(matches!(
        s.service()
            .begin_delivered_enrollment(user.id, MfaMethod::Email, Some("nope".into()), None)
            .await,
        Err(AuthError::InvalidEmail(_))
    ));
}

#[tokio::test]
async fn resends_are_rate_limited_and_replace_the_code() {
    let s = mfa_server(both());
    with_email(&s, "resend@example.com").await;
    let c = challenge(&s, "resend@example.com", IP_A).await;
    let first = s.sender.last_code("resend@example.com").unwrap();

    assert!(matches!(
        s.service()
            .send_login_code(&c.challenge_token, Some(MfaMethod::Email))
            .await,
        Err(AuthError::CodeResendTooSoon)
    ));
    s.server.clock.advance(Duration::from_secs(31));
    s.service()
        .send_login_code(&c.challenge_token, None)
        .await
        .unwrap();
    let second = s.sender.last_code("resend@example.com").unwrap();

    if first != second {
        assert!(matches!(
            complete(&s, &c, None, &first).await,
            Err(AuthError::InvalidSecondFactor)
        ));
    }
    // Three sends per challenge (code_max_sends).
    s.server.clock.advance(Duration::from_secs(31));
    s.service()
        .send_login_code(&c.challenge_token, None)
        .await
        .unwrap();
    s.server.clock.advance(Duration::from_secs(31));
    assert!(matches!(
        s.service().send_login_code(&c.challenge_token, None).await,
        Err(AuthError::CodeResendTooSoon)
    ));
    let latest = s.sender.last_code("resend@example.com").unwrap();
    complete(&s, &c, None, &latest).await.unwrap();
}

#[tokio::test]
async fn codes_expire() {
    let s = mfa_server(both().code_ttl_secs(60).challenge_ttl_secs(600));
    with_email(&s, "late@example.com").await;
    let c = challenge(&s, "late@example.com", IP_A).await;
    let code = s.sender.last_code("late@example.com").unwrap();
    s.server.clock.advance(Duration::from_secs(61));
    assert!(matches!(
        complete(&s, &c, None, &code).await,
        Err(AuthError::InvalidSecondFactor)
    ));
}

#[tokio::test]
async fn with_totp_enrolled_codes_are_sent_on_request_only() {
    let s = mfa_server(both());
    let (user, _, _) = with_totp(&s, "both@example.com").await;
    let pending = s
        .service()
        .begin_delivered_enrollment(user.id, MfaMethod::Email, None, None)
        .await
        .unwrap();
    let code = s.sender.last_code("both@example.com").unwrap();
    s.service()
        .confirm_enrollment(user.id, pending.factor_id, &code)
        .await
        .unwrap();
    let before = s.sender.sent().len();

    let c = challenge(&s, "both@example.com", IP_A).await;
    assert_eq!(c.methods, ["totp", "email", "recovery_code"]);
    assert!(c.delivery.is_none());
    assert_eq!(s.sender.sent().len(), before);

    let delivery = s
        .service()
        .send_login_code(&c.challenge_token, None)
        .await
        .unwrap();
    assert_eq!(delivery.method, "email");
    let code = s.sender.last_code("both@example.com").unwrap();
    complete(&s, &c, Some("email"), &code).await.unwrap();
}

#[tokio::test]
async fn step_up_codes_prove_a_delivered_factor() {
    let s = mfa_server(both());
    let user = with_email(&s, "stepup@example.com").await;
    let factor = s.service().factors(user.id).await.unwrap().remove(0);

    s.service()
        .send_step_up_code(user.id, Some(MfaMethod::Email))
        .await
        .unwrap();
    let sent = s.sender.sent();
    assert_eq!(sent.last().unwrap().purpose, CodePurpose::StepUp);
    let code = sent.last().unwrap().code.clone();
    let proof = |code: &str| StepUpProof {
        method: ProofMethod::Factor(MfaMethod::Email),
        code: code.into(),
    };
    let codes = s
        .service()
        .regenerate_recovery_codes(user.id, proof(&code))
        .await
        .unwrap();
    assert_eq!(codes.len(), 10);
    // Used up.
    assert!(matches!(
        s.service()
            .remove_factor(user.id, factor.id, proof(&code))
            .await,
        Err(AuthError::InvalidSecondFactor)
    ));
    assert!(matches!(
        s.service()
            .send_step_up_code(user.id, Some(MfaMethod::Sms))
            .await,
        Err(AuthError::SecondFactorNotEnrolled)
    ));
}

#[tokio::test]
async fn delivery_failures_surface_as_retryable_errors() {
    let s = mfa_server(both());
    with_email(&s, "down@example.com").await;
    s.sender.fail(true);
    let err = s
        .auth()
        .authentication()
        .login(credentials("down@example.com"), ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::CodeDeliveryFailed(_)));
    let api = z_auth::controller::api::ApiError::from(err);
    assert_eq!(api.status, 503);
}

#[tokio::test]
async fn email_or_sms_without_a_sender_is_a_configuration_error() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let mfa = Arc::new(Mfa::new(both().build().unwrap(), db.clone()));
    let result = ZAuth::builder(test_config(), repositories(&db))
        .clock(clock)
        .extension(mfa)
        .build();
    assert!(matches!(result, Err(AuthError::Config(m)) if m.contains("CodeSender")));
}
