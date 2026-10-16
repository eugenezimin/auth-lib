//! Shared helpers for z-auth-mfa's tests: see `z-auth-testkit` (feature
//! `mfa`), plus the steps most tests repeat.
#![allow(dead_code, unused_imports)]

pub use z_auth_testkit::mfa::*;
pub use z_auth_testkit::*;

use z_auth::prelude::*;
use z_auth_mfa::model::TotpEnrollment;

/// Register `email` and enroll TOTP; returns the user, the enrollment and
/// the recovery codes issued with it.
pub async fn with_totp(s: &MfaServer, email: &str) -> (User, TotpEnrollment, Vec<String>) {
    let user = register(s.auth(), email).await;
    let enrollment = s
        .service()
        .begin_totp_enrollment(user.id, Some("phone".into()))
        .await
        .unwrap();
    let code = totp_code(&enrollment.secret, &s.server.clock, &default_totp(), 0);
    let confirmed = s
        .service()
        .confirm_enrollment(user.id, enrollment.factor_id, &code)
        .await
        .unwrap();
    (
        user,
        enrollment,
        confirmed.recovery_codes.unwrap_or_default(),
    )
}

/// Log in with the password; panics unless a challenge comes back.
pub async fn challenge(s: &MfaServer, email: &str, ip: std::net::IpAddr) -> LoginChallenge {
    match s
        .auth()
        .authentication()
        .login(credentials(email), ctx(ip))
        .await
        .unwrap()
    {
        LoginOutcome::SecondFactor(c) => c,
        LoginOutcome::Tokens(_) => panic!("expected a second-factor challenge"),
    }
}

pub fn proof(c: &LoginChallenge, method: Option<&str>, code: &str) -> SecondFactorProof {
    SecondFactorProof {
        challenge_token: c.challenge_token.clone(),
        method: method.map(Into::into),
        code: code.into(),
    }
}

pub async fn complete(
    s: &MfaServer,
    c: &LoginChallenge,
    method: Option<&str>,
    code: &str,
) -> Result<TokenPair, AuthError> {
    s.auth()
        .authentication()
        .complete_login(proof(c, method, code), ctx(IP_A))
        .await
}

pub fn claims(s: &MfaServer, pair: &TokenPair) -> Claims {
    s.auth().verifier().verify(&pair.access_token).unwrap()
}

/// Move the mock clock to the next TOTP step (so a fresh code is due).
pub fn next_step(s: &MfaServer) {
    s.server.clock.advance(std::time::Duration::from_secs(30));
}
