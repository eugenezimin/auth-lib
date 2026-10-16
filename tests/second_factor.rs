//! Two-step login through a `SecondFactorGate` installed by an extension,
//! against in-memory adapters.  The gate here is a stub; the real one
//! lives in z-auth-mfa.
//!
//! Invariants checked here:
//! - a challenged login opens (and evicts) no session;
//! - only `complete_login` opens it, with `amr` = pwd + the gate's + mfa;
//! - the account is re-checked at completion.

// The facade's defaults need the `argon2` and `crypto` features.
#![cfg(all(feature = "argon2", feature = "crypto"))]

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;
use z_auth::controller::api::dto::{CompleteLoginRequest, LoginRequest, LoginResponse};
use z_auth::controller::api::handlers;
use z_auth::controller::extension::AssembleContext;
use z_auth::prelude::*;

use crate::support::{
    IP_A, InMemoryDb, MockClock, VALID_PASSWORD, credentials, ctx, raw_config, register,
    repositories,
};

const CODE: &str = "123456";

/// Challenges every user in `challenged`; accepts `CODE` once per
/// challenge token.
#[derive(Default)]
struct StubGate {
    challenged: Mutex<Vec<Uuid>>,
    /// challenge token → user.
    pending: Mutex<Vec<(String, Uuid)>>,
}

#[async_trait]
impl SecondFactorGate for StubGate {
    async fn on_password_verified(
        &self,
        account: &z_auth::identity::user::UserWithRoles,
        _: &ClientContext,
    ) -> Result<SecondFactorDecision, AuthError> {
        if !self.challenged.lock().unwrap().contains(&account.user.id) {
            return Ok(SecondFactorDecision::Proceed);
        }
        let token = format!("ch-{}", Uuid::new_v4());
        self.pending
            .lock()
            .unwrap()
            .push((token.clone(), account.user.id));
        Ok(SecondFactorDecision::Challenge(LoginChallenge {
            challenge_token: token,
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            methods: vec!["totp".into()],
            delivery: None,
        }))
    }

    async fn verify(
        &self,
        proof: &SecondFactorProof,
        _: &ClientContext,
    ) -> Result<VerifiedSecondFactor, AuthError> {
        let mut pending = self.pending.lock().unwrap();
        let at = pending
            .iter()
            .position(|(t, _)| *t == proof.challenge_token)
            .ok_or(AuthError::ChallengeExpired)?;
        if proof.code != CODE {
            return Err(AuthError::InvalidSecondFactor);
        }
        let (_, user_id) = pending.remove(at);
        Ok(VerifiedSecondFactor {
            user_id,
            amr: vec!["otp".into()],
        })
    }
}

struct GateExtension(Arc<StubGate>);

impl Extension for GateExtension {
    fn name(&self) -> &'static str {
        "stub-2fa"
    }
    fn assemble(&self, ctx: &mut AssembleContext<'_>) -> Result<(), AuthError> {
        ctx.set_second_factor_gate(self.0.clone())
    }
}

struct Setup {
    auth: ZAuth,
    db: Arc<InMemoryDb>,
    clock: Arc<MockClock>,
    gate: Arc<StubGate>,
}

fn setup(config: AuthConfig) -> Setup {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let gate = Arc::new(StubGate::default());
    let auth = ZAuth::builder(config, repositories(&db))
        .clock(clock.clone())
        .extension(Arc::new(GateExtension(gate.clone())))
        .build()
        .unwrap();
    Setup {
        auth,
        db,
        clock,
        gate,
    }
}

async fn active_sessions(s: &Setup, user: Uuid) -> usize {
    SessionRepository::list_active_for_user(&*s.db, user)
        .await
        .unwrap()
        .len()
}

async fn challenged_user(s: &Setup, email: &str) -> (User, LoginChallenge) {
    let user = register(&s.auth, email).await;
    s.gate.challenged.lock().unwrap().push(user.id);
    match s
        .auth
        .authentication()
        .login(credentials(email), ctx(IP_A))
        .await
        .unwrap()
    {
        LoginOutcome::SecondFactor(challenge) => (user, challenge),
        LoginOutcome::Tokens(_) => panic!("expected a challenge"),
    }
}

fn proof(challenge: &LoginChallenge, code: &str) -> SecondFactorProof {
    SecondFactorProof {
        challenge_token: challenge.challenge_token.clone(),
        method: None,
        code: code.into(),
    }
}

#[tokio::test]
async fn users_the_gate_lets_through_get_password_tokens() {
    let s = setup(raw_config().build().unwrap());
    register(&s.auth, "plain@example.com").await;
    let outcome = s
        .auth
        .authentication()
        .login(credentials("plain@example.com"), ctx(IP_A))
        .await
        .unwrap();
    let pair = outcome.into_tokens().unwrap();
    let claims = s.auth.verifier().verify(&pair.access_token).unwrap();
    assert_eq!(claims.amr, ["pwd"]);
}

#[tokio::test]
async fn a_challenged_login_opens_a_session_only_once_completed() {
    let s = setup(raw_config().build().unwrap());
    let (user, challenge) = challenged_user(&s, "mfa@example.com").await;
    assert_eq!(active_sessions(&s, user.id).await, 0);

    let err = s
        .auth
        .authentication()
        .complete_login(proof(&challenge, "000000"), ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidSecondFactor));
    assert_eq!(active_sessions(&s, user.id).await, 0);

    let pair = s
        .auth
        .authentication()
        .complete_login(proof(&challenge, CODE), ctx(IP_A))
        .await
        .unwrap();
    assert_eq!(active_sessions(&s, user.id).await, 1);
    let claims = s.auth.verifier().verify(&pair.access_token).unwrap();
    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.amr, ["mfa", "otp", "pwd"]);
    assert!(s.auth.authorizer().require_mfa(&claims).is_ok());

    // The session keeps its methods across refreshes.
    s.clock.advance(Duration::from_secs(301));
    let next = s
        .auth
        .authentication()
        .refresh(&pair.access_token, &pair.refresh_token, ctx(IP_A))
        .await
        .unwrap();
    let claims = s.auth.verifier().verify(&next.access_token).unwrap();
    assert_eq!(claims.amr, ["mfa", "otp", "pwd"]);

    // The challenge was single-use.
    let err = s
        .auth
        .authentication()
        .complete_login(proof(&challenge, CODE), ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::ChallengeExpired));
}

#[tokio::test]
async fn a_password_alone_evicts_no_session() {
    let s = setup(raw_config().max_sessions_per_user(1).build().unwrap());
    let (user, first) = challenged_user(&s, "evict@example.com").await;
    let pair = s
        .auth
        .authentication()
        .complete_login(proof(&first, CODE), ctx(IP_A))
        .await
        .unwrap();

    // Someone with only the password: the existing session survives.
    let LoginOutcome::SecondFactor(second) = s
        .auth
        .authentication()
        .login(credentials("evict@example.com"), ctx(IP_A))
        .await
        .unwrap()
    else {
        panic!("expected a challenge");
    };
    assert!(s.auth.verifier().verify(&pair.access_token).is_ok());
    assert_eq!(active_sessions(&s, user.id).await, 1);

    // Completing the second login evicts the oldest as usual.
    s.auth
        .authentication()
        .complete_login(proof(&second, CODE), ctx(IP_A))
        .await
        .unwrap();
    assert_eq!(active_sessions(&s, user.id).await, 1);
    let ended = SessionRepository::find(&*s.db, pair.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended.end_reason, Some(RevocationReason::Evicted));
}

#[tokio::test]
async fn the_account_is_rechecked_at_completion() {
    let s = setup(raw_config().build().unwrap());
    let (user, challenge) = challenged_user(&s, "gone@example.com").await;
    s.auth.users().deactivate(user.id).await.unwrap();
    let err = s
        .auth
        .authentication()
        .complete_login(proof(&challenge, CODE), ctx(IP_A))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::AccountDisabled));
    assert_eq!(active_sessions(&s, user.id).await, 0);
}

#[tokio::test]
async fn without_a_gate_complete_login_is_refused() {
    let auth = support::make_auth();
    let err = auth
        .authentication()
        .complete_login(
            SecondFactorProof {
                challenge_token: "x".into(),
                method: None,
                code: CODE.into(),
            },
            ctx(IP_A),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidToken(_)));
}

#[tokio::test]
async fn only_one_second_factor_gate_may_be_installed() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let gate = Arc::new(StubGate::default());
    let result = ZAuth::builder(raw_config().build().unwrap(), repositories(&db))
        .extension(Arc::new(GateExtension(gate.clone())))
        .extension(Arc::new(GateExtension(gate)))
        .build();
    assert!(matches!(result, Err(AuthError::Config(_))));
}

#[tokio::test]
async fn handlers_report_the_challenge_and_complete_the_login() {
    let s = setup(raw_config().build().unwrap());
    let user = register(&s.auth, "api-mfa@example.com").await;
    s.gate.challenged.lock().unwrap().push(user.id);

    let response = handlers::login(
        s.auth.authentication(),
        LoginRequest {
            email: "api-mfa@example.com".into(),
            password: VALID_PASSWORD.into(),
        },
        ctx(IP_A),
    )
    .await
    .unwrap();
    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["status"], "second_factor_required");
    assert_eq!(json["methods"], serde_json::json!(["totp"]));
    assert!(!format!("{response:?}").contains("ch-"), "token redacted");
    let LoginResponse::SecondFactorRequired(challenge) = response else {
        panic!("expected a challenge");
    };

    let err = handlers::complete_login(
        s.auth.authentication(),
        CompleteLoginRequest {
            challenge_token: challenge.challenge_token.clone(),
            method: Some("totp".into()),
            code: "999999".into(),
        },
        ctx(IP_A),
    )
    .await
    .unwrap_err();
    assert_eq!((err.status, err.code), (401, "invalid_second_factor"));

    let request: CompleteLoginRequest = serde_json::from_value(serde_json::json!({
        "challenge_token": challenge.challenge_token,
        "code": CODE,
    }))
    .unwrap();
    let pair = handlers::complete_login(s.auth.authentication(), request, ctx(IP_A))
        .await
        .unwrap();
    let claims = s.auth.verifier().verify(&pair.access_token).unwrap();
    assert!(claims.has_amr("mfa"));

    // Without a challenge, login answers `authenticated`.
    s.gate.challenged.lock().unwrap().clear();
    let response = handlers::login(
        s.auth.authentication(),
        LoginRequest {
            email: "api-mfa@example.com".into(),
            password: VALID_PASSWORD.into(),
        },
        ctx(IP_A),
    )
    .await
    .unwrap();
    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["status"], "authenticated");
    assert!(json["access_token"].is_string());
}

#[test]
fn second_factor_errors_map_to_stable_codes() {
    use z_auth::controller::api::ApiError;
    let cases = [
        (
            AuthError::SecondFactorRequired,
            403,
            "second_factor_required",
        ),
        (AuthError::InvalidSecondFactor, 401, "invalid_second_factor"),
        (AuthError::SecondFactorLocked, 429, "second_factor_locked"),
        (AuthError::ChallengeExpired, 401, "challenge_expired"),
        (
            AuthError::SecondFactorNotEnrolled,
            403,
            "second_factor_not_enrolled",
        ),
        (
            AuthError::SecondFactorAlreadyEnrolled,
            409,
            "second_factor_already_enrolled",
        ),
        (
            AuthError::SecondFactorNotFound,
            404,
            "second_factor_not_found",
        ),
        (
            AuthError::UnsupportedSecondFactor("webauthn".into()),
            422,
            "unsupported_second_factor",
        ),
        (
            AuthError::InvalidDestination("not a phone number".into()),
            422,
            "invalid_destination",
        ),
        (AuthError::CodeResendTooSoon, 429, "code_resend_too_soon"),
    ];
    for (err, status, code) in cases {
        let api = ApiError::from(err);
        assert_eq!((api.status, api.code), (status, code));
    }
    let api = ApiError::from(AuthError::CodeDeliveryFailed(
        "smtp: 550 secret@host".into(),
    ));
    assert_eq!((api.status, api.code), (503, "code_delivery_failed"));
    assert!(!api.message.contains("secret"), "details stay internal");
}
