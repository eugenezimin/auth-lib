//! Sign-in through external identity providers and account linking,
//! against in-memory adapters.  The principals here stand for what a
//! protocol adapter (z-auth-sso) verified.
//!
//! Invariants checked here:
//! - an identity is matched by `(issuer, subject)` only, never by email;
//! - a first sign-in links to an existing account only through its
//!   password, or silently when both sides' emails are verified and the
//!   provider is trusted with emails;
//! - explicit linking needs a recent, active session;
//! - the last way to log in cannot be unlinked;
//! - the second factor still applies, and `amr` records how the login
//!   started.

// The facade's defaults need the `argon2` and `crypto` features.
#![cfg(all(feature = "argon2", feature = "crypto"))]

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;
use z_auth::controller::api::handlers;
use z_auth::controller::extension::AssembleContext;
use z_auth::prelude::*;

use crate::support::{
    IP_A, InMemoryDb, MockClock, Server, VALID_PASSWORD, credentials, ctx, external_server,
    register, repositories, test_config,
};

const GOOGLE: &str = "https://accounts.google.com";

fn google(subject: &str, email: Option<(&str, bool)>) -> ExternalPrincipal {
    let principal = ExternalPrincipal::new("google", GOOGLE, subject);
    match email {
        Some((email, verified)) => principal.with_email(email, verified),
        None => principal,
    }
}

fn policy(link: LinkPolicy, provisioning: Provisioning, trust_email: bool) -> ProviderPolicy {
    ProviderPolicy {
        link,
        provisioning,
        trust_email,
        max_links: 1,
    }
}

async fn external(
    s: &Server,
    principal: ExternalPrincipal,
    policy: ProviderPolicy,
) -> Result<ExternalLoginOutcome, AuthError> {
    s.auth
        .authentication()
        .login_external(principal, policy, ctx(IP_A))
        .await
}

fn tokens(outcome: ExternalLoginOutcome) -> TokenPair {
    match outcome {
        ExternalLoginOutcome::Tokens(pair) => pair,
        other => panic!("expected tokens, got {other:?}"),
    }
}

fn link_challenge(outcome: ExternalLoginOutcome) -> LinkChallenge {
    match outcome {
        ExternalLoginOutcome::LinkConfirmation(challenge) => challenge,
        other => panic!("expected a link confirmation, got {other:?}"),
    }
}

async fn claims(s: &Server, pair: &TokenPair) -> Claims {
    s.auth
        .authentication()
        .verify_access_token(&pair.access_token)
        .await
        .unwrap()
}

async fn password_login(s: &Server, email: &str) -> TokenPair {
    s.auth
        .authentication()
        .login(credentials(email), ctx(IP_A))
        .await
        .and_then(LoginOutcome::into_tokens)
        .unwrap()
}

// ── Linked identities ─────────────────────────────────────────────────────────

#[tokio::test]
async fn explicit_link_then_both_methods_sign_in_the_same_user() {
    let s = external_server(test_config());
    let user = register(&s.auth, "ann@example.com").await;
    let pair = password_login(&s, "ann@example.com").await;
    let sid = claims(&s, &pair).await.sid;

    let identity = s
        .auth
        .account_links()
        .link(sid, &google("g-ann", None), &ProviderPolicy::default())
        .await
        .unwrap();
    assert_eq!(identity.user_id, user.id);
    assert_eq!(identity.provider, "google");

    let pair = tokens(
        external(&s, google("g-ann", None), ProviderPolicy::default())
            .await
            .unwrap(),
    );
    let c = claims(&s, &pair).await;
    assert_eq!(c.sub, user.id);
    assert_eq!(c.amr, ["fed"]);
    let listed = s.auth.account_links().list(user.id).await.unwrap();
    assert!(listed[0].last_login_at.is_some());
    // The password still works and names the same user.
    let c = claims(&s, &password_login(&s, "ann@example.com").await).await;
    assert_eq!(c.sub, user.id);
    assert_eq!(c.amr, ["pwd"]);
}

#[tokio::test]
async fn identities_are_matched_by_issuer_and_subject_not_email() {
    let s = external_server(test_config());
    register(&s.auth, "ann@example.com").await;
    let sid = claims(&s, &password_login(&s, "ann@example.com").await)
        .await
        .sid;
    s.auth
        .account_links()
        .link(sid, &google("g-ann", None), &ProviderPolicy::default())
        .await
        .unwrap();

    // Same subject, another issuer: a different identity.
    let other = ExternalPrincipal::new("evil", "https://evil.example", "g-ann");
    let err = external(&s, other, ProviderPolicy::default()).await;
    assert!(matches!(err, Err(AuthError::ExternalIdentityNotLinked)));
}

#[tokio::test]
async fn disabled_users_cannot_sign_in_through_a_linked_identity() {
    let s = external_server(test_config());
    let user = register(&s.auth, "ann@example.com").await;
    let sid = claims(&s, &password_login(&s, "ann@example.com").await)
        .await
        .sid;
    s.auth
        .account_links()
        .link(sid, &google("g-ann", None), &ProviderPolicy::default())
        .await
        .unwrap();
    s.auth.users().deactivate(user.id).await.unwrap();

    let err = external(&s, google("g-ann", None), ProviderPolicy::default()).await;
    assert!(matches!(err, Err(AuthError::AccountDisabled)));
}

// ── First sign-in: an account with the provider's email exists ────────────────

#[tokio::test]
async fn never_policy_refuses_to_link_by_email() {
    let s = external_server(test_config());
    register(&s.auth, "ann@example.com").await;
    let err = external(
        &s,
        google("g-ann", Some(("ann@example.com", true))),
        policy(LinkPolicy::Never, Provisioning::Create, true),
    )
    .await;
    assert!(matches!(err, Err(AuthError::ExternalIdentityNotLinked)));
}

#[tokio::test]
async fn confirming_with_the_password_links_and_signs_in() {
    let s = external_server(test_config());
    let user = register(&s.auth, "ann@example.com").await;
    let principal = google("g-ann", Some(("Ann@Example.com", false)));
    let challenge = link_challenge(
        external(&s, principal.clone(), ProviderPolicy::default())
            .await
            .unwrap(),
    );
    assert_eq!(challenge.email, "ann@example.com");
    assert!(
        s.auth
            .account_links()
            .list(user.id)
            .await
            .unwrap()
            .is_empty()
    );

    let pair = s
        .auth
        .authentication()
        .confirm_link(
            LinkConfirmation {
                challenge_token: challenge.challenge_token,
                password: VALID_PASSWORD.into(),
            },
            ctx(IP_A),
        )
        .await
        .and_then(LoginOutcome::into_tokens)
        .unwrap();
    let c = claims(&s, &pair).await;
    assert_eq!(c.sub, user.id);
    assert_eq!(c.amr, ["fed", "pwd"]);

    // Linked now: the next sign-in goes straight through.
    let pair = tokens(
        external(&s, principal, ProviderPolicy::default())
            .await
            .unwrap(),
    );
    assert_eq!(claims(&s, &pair).await.sub, user.id);
}

#[tokio::test]
async fn a_wrong_password_ends_the_link_challenge() {
    let s = external_server(test_config());
    let user = register(&s.auth, "ann@example.com").await;
    let challenge = link_challenge(
        external(
            &s,
            google("g-ann", Some(("ann@example.com", true))),
            ProviderPolicy::default(),
        )
        .await
        .unwrap(),
    );
    let confirm = |password: &str| LinkConfirmation {
        challenge_token: challenge.challenge_token.clone(),
        password: password.into(),
    };

    let err = s
        .auth
        .authentication()
        .confirm_link(confirm("wrong-password"), ctx(IP_A))
        .await;
    assert!(matches!(err, Err(AuthError::InvalidCredentials)));
    let err = s
        .auth
        .authentication()
        .confirm_link(confirm(VALID_PASSWORD), ctx(IP_A))
        .await;
    assert!(matches!(err, Err(AuthError::ChallengeExpired)));
    assert!(
        s.auth
            .account_links()
            .list(user.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn link_challenges_expire() {
    let s = external_server(test_config());
    register(&s.auth, "ann@example.com").await;
    let challenge = link_challenge(
        external(
            &s,
            google("g-ann", Some(("ann@example.com", true))),
            ProviderPolicy::default(),
        )
        .await
        .unwrap(),
    );
    s.clock.advance(Duration::from_secs(301));
    let err = s
        .auth
        .authentication()
        .confirm_link(
            LinkConfirmation {
                challenge_token: challenge.challenge_token,
                password: VALID_PASSWORD.into(),
            },
            ctx(IP_A),
        )
        .await;
    assert!(matches!(err, Err(AuthError::ChallengeExpired)));
}

#[tokio::test]
async fn verified_emails_on_both_sides_link_silently() {
    let s = external_server(test_config());
    let user = register(&s.auth, "ann@example.com").await;
    s.db.set_verified(user.id, true);

    let pair = tokens(
        external(
            &s,
            google("g-ann", Some(("ann@example.com", true))),
            policy(LinkPolicy::VerifiedEmail, Provisioning::Deny, true),
        )
        .await
        .unwrap(),
    );
    assert_eq!(claims(&s, &pair).await.sub, user.id);
    assert_eq!(s.auth.account_links().list(user.id).await.unwrap().len(), 1);
}

/// Account pre-hijacking: someone registered the victim's email (never
/// verified) before the victim first signs in with the provider.  The
/// identity must not join that account without its password.
#[tokio::test]
async fn an_unverified_local_account_is_never_linked_silently() {
    let s = external_server(test_config());
    let squatter = register(&s.auth, "victim@example.com").await;
    let outcome = external(
        &s,
        google("g-victim", Some(("victim@example.com", true))),
        policy(LinkPolicy::VerifiedEmail, Provisioning::Create, true),
    )
    .await
    .unwrap();
    link_challenge(outcome);
    assert!(
        s.auth
            .account_links()
            .list(squatter.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn unverified_or_untrusted_provider_emails_are_never_linked_silently() {
    let s = external_server(test_config());
    let user = register(&s.auth, "ann@example.com").await;
    s.db.set_verified(user.id, true);

    // The provider does not vouch for the email.
    let outcome = external(
        &s,
        google("g-1", Some(("ann@example.com", false))),
        policy(LinkPolicy::VerifiedEmail, Provisioning::Deny, true),
    )
    .await
    .unwrap();
    link_challenge(outcome);
    // The provider vouches, but is not trusted to (nOAuth-style).
    let outcome = external(
        &s,
        google("g-2", Some(("ann@example.com", true))),
        policy(LinkPolicy::VerifiedEmail, Provisioning::Deny, false),
    )
    .await
    .unwrap();
    link_challenge(outcome);
    assert!(
        s.auth
            .account_links()
            .list(user.id)
            .await
            .unwrap()
            .is_empty()
    );
}

// ── First sign-in: no account with the provider's email ───────────────────────

#[tokio::test]
async fn provisioning_deny_refuses_unknown_users() {
    let s = external_server(test_config());
    let err = external(
        &s,
        google("g-new", Some(("new@example.com", true))),
        policy(LinkPolicy::ConfirmWithPassword, Provisioning::Deny, true),
    )
    .await;
    assert!(matches!(err, Err(AuthError::ExternalIdentityNotLinked)));
}

#[tokio::test]
async fn provisioning_create_makes_a_user_without_a_password() {
    let s = external_server(test_config());
    register(&s.auth, "taken@example.com").await;
    s.auth
        .users()
        .update(
            s.auth
                .users()
                .find_by_email("taken@example.com")
                .await
                .unwrap()
                .unwrap()
                .id,
            UpdateUser {
                username: Some("ann".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut principal = google("g-new", Some(("New@Example.com", true)));
    principal.username = Some("ann".into()); // taken: dropped
    principal.first_name = Some("Ann".into());
    let pair = tokens(
        external(
            &s,
            principal,
            policy(LinkPolicy::ConfirmWithPassword, Provisioning::Create, true),
        )
        .await
        .unwrap(),
    );
    let user = s
        .auth
        .users()
        .find_by_id(claims(&s, &pair).await.sub)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.email, "new@example.com");
    assert!(user.password_hash.is_none());
    assert!(user.is_verified);
    assert_eq!(user.username, None);
    assert_eq!(user.first_name.as_deref(), Some("Ann"));

    // An untrusted provider's email is not taken as verified.
    let pair = tokens(
        external(
            &s,
            google("g-other", Some(("other@example.com", true))),
            policy(LinkPolicy::ConfirmWithPassword, Provisioning::Create, false),
        )
        .await
        .unwrap(),
    );
    let other = s
        .auth
        .users()
        .find_by_id(claims(&s, &pair).await.sub)
        .await
        .unwrap()
        .unwrap();
    assert!(!other.is_verified);
}

#[tokio::test]
async fn provisioning_needs_an_email() {
    let s = external_server(test_config());
    let err = external(
        &s,
        google("g-new", None),
        policy(LinkPolicy::ConfirmWithPassword, Provisioning::Create, true),
    )
    .await;
    assert!(matches!(err, Err(AuthError::InvalidEmail(_))));
}

// ── Explicit linking ──────────────────────────────────────────────────────────

#[tokio::test]
async fn linking_needs_a_recent_session() {
    let s = external_server(test_config());
    register(&s.auth, "ann@example.com").await;
    let pair = password_login(&s, "ann@example.com").await;
    let sid = claims(&s, &pair).await.sid;

    // Refreshing keeps the session alive but does not make it recent.
    s.clock.advance(Duration::from_secs(400));
    s.auth
        .authentication()
        .refresh(&pair.access_token, &pair.refresh_token, ctx(IP_A))
        .await
        .unwrap();
    s.clock.advance(Duration::from_secs(400));
    let err = s
        .auth
        .account_links()
        .link(sid, &google("g-ann", None), &ProviderPolicy::default())
        .await;
    assert!(matches!(err, Err(AuthError::ReauthenticationRequired)));

    // A fresh login may.
    let sid = claims(&s, &password_login(&s, "ann@example.com").await)
        .await
        .sid;
    s.auth
        .account_links()
        .link(sid, &google("g-ann", None), &ProviderPolicy::default())
        .await
        .unwrap();
}

#[tokio::test]
async fn an_ended_session_cannot_link() {
    let s = external_server(test_config());
    register(&s.auth, "ann@example.com").await;
    let pair = password_login(&s, "ann@example.com").await;
    let sid = claims(&s, &pair).await.sid;
    // E.g. the user logged out between leaving for the provider and the
    // callback.
    s.auth
        .authentication()
        .logout(&pair.access_token)
        .await
        .unwrap();
    let err = s
        .auth
        .account_links()
        .link(sid, &google("g-ann", None), &ProviderPolicy::default())
        .await;
    assert!(matches!(err, Err(AuthError::TokenRevoked)));
}

#[tokio::test]
async fn an_identity_belongs_to_one_user() {
    let s = external_server(test_config());
    register(&s.auth, "ann@example.com").await;
    register(&s.auth, "bob@example.com").await;
    let ann = claims(&s, &password_login(&s, "ann@example.com").await)
        .await
        .sid;
    let bob = claims(&s, &password_login(&s, "bob@example.com").await)
        .await
        .sid;
    let links = s.auth.account_links();
    let first = links
        .link(ann, &google("g-1", None), &ProviderPolicy::default())
        .await
        .unwrap();

    // Again for the same user: unchanged.
    let again = links
        .link(ann, &google("g-1", None), &ProviderPolicy::default())
        .await
        .unwrap();
    assert_eq!(again.id, first.id);
    // For another user: refused, never moved.
    let err = links
        .link(bob, &google("g-1", None), &ProviderPolicy::default())
        .await;
    assert!(matches!(
        err,
        Err(AuthError::ExternalIdentityLinkedElsewhere)
    ));
    // A second account of the same provider: over the policy's limit.
    let err = links
        .link(ann, &google("g-2", None), &ProviderPolicy::default())
        .await;
    assert!(matches!(err, Err(AuthError::ProviderAlreadyLinked)));
    let unlimited = ProviderPolicy {
        max_links: 0,
        ..Default::default()
    };
    links
        .link(ann, &google("g-2", None), &unlimited)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_last_way_to_log_in_cannot_be_unlinked() {
    let s = external_server(test_config());
    // A provisioned user: no password, one identity.
    let pair = tokens(
        external(
            &s,
            google("g-new", Some(("new@example.com", true))),
            policy(LinkPolicy::Never, Provisioning::Create, true),
        )
        .await
        .unwrap(),
    );
    let c = claims(&s, &pair).await;
    let links = s.auth.account_links();
    let only = links.list(c.sub).await.unwrap().remove(0);
    let err = links.unlink(c.sid, only.id).await;
    assert!(matches!(err, Err(AuthError::LastLoginMethod)));

    // With a second identity, one may go.
    links
        .link(
            c.sid,
            &google("g-new-2", None),
            &ProviderPolicy {
                max_links: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    links.unlink(c.sid, only.id).await.unwrap();
    assert_eq!(links.list(c.sub).await.unwrap().len(), 1);
}

#[tokio::test]
async fn users_with_a_password_may_unlink_every_identity() {
    let s = external_server(test_config());
    register(&s.auth, "ann@example.com").await;
    register(&s.auth, "bob@example.com").await;
    let ann = claims(&s, &password_login(&s, "ann@example.com").await).await;
    let bob = claims(&s, &password_login(&s, "bob@example.com").await).await;
    let links = s.auth.account_links();
    let identity = links
        .link(ann.sid, &google("g-ann", None), &ProviderPolicy::default())
        .await
        .unwrap();

    // Not Bob's to remove.
    let err = links.unlink(bob.sid, identity.id).await;
    assert!(matches!(err, Err(AuthError::ExternalIdentityNotFound)));
    links.unlink(ann.sid, identity.id).await.unwrap();
    assert!(links.list(ann.sub).await.unwrap().is_empty());
    let err = external(&s, google("g-ann", None), ProviderPolicy::default()).await;
    assert!(matches!(err, Err(AuthError::ExternalIdentityNotLinked)));
}

#[tokio::test]
async fn link_and_unlink_are_announced() {
    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);
    #[async_trait]
    impl ExternalIdentityEvents for Recorder {
        async fn linked(&self, identity: &ExternalIdentity) {
            self.0
                .lock()
                .unwrap()
                .push(format!("+{}", identity.subject));
        }
        async fn unlinked(&self, identity: &ExternalIdentity) {
            self.0
                .lock()
                .unwrap()
                .push(format!("-{}", identity.subject));
        }
    }

    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let events = Arc::new(Recorder::default());
    let auth = ZAuth::builder(test_config(), repositories(&db))
        .external_identities(db.clone(), db.clone())
        .external_identity_events(events.clone())
        .clock(clock.clone())
        .build()
        .unwrap();
    let s = Server { auth, db, clock };
    register(&s.auth, "ann@example.com").await;
    let sid = claims(&s, &password_login(&s, "ann@example.com").await)
        .await
        .sid;
    let identity = s
        .auth
        .account_links()
        .link(sid, &google("g-ann", None), &ProviderPolicy::default())
        .await
        .unwrap();
    s.auth
        .account_links()
        .unlink(sid, identity.id)
        .await
        .unwrap();
    assert_eq!(*events.0.lock().unwrap(), ["+g-ann", "-g-ann"]);
}

// ── Second factor ─────────────────────────────────────────────────────────────

const CODE: &str = "123456";

/// Challenges every login; accepts `CODE`.
#[derive(Default)]
struct StubGate {
    pending: Mutex<Vec<(String, Uuid)>>,
}

#[async_trait]
impl SecondFactorGate for StubGate {
    async fn on_password_verified(
        &self,
        account: &UserWithRoles,
        _: &ClientContext,
    ) -> Result<SecondFactorDecision, AuthError> {
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

fn gated_server() -> Server {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let auth = ZAuth::builder(test_config(), repositories(&db))
        .external_identities(db.clone(), db.clone())
        .extension(Arc::new(GateExtension(Arc::default())))
        .clock(clock.clone())
        .build()
        .unwrap();
    Server { auth, db, clock }
}

async fn complete(s: &Server, challenge: LoginChallenge) -> Claims {
    let pair = s
        .auth
        .authentication()
        .complete_login(
            SecondFactorProof {
                challenge_token: challenge.challenge_token,
                method: None,
                code: CODE.into(),
            },
            ctx(IP_A),
        )
        .await
        .unwrap();
    claims(s, &pair).await
}

fn create_users() -> ProviderPolicy {
    policy(LinkPolicy::Never, Provisioning::Create, true)
}

#[tokio::test]
async fn the_second_factor_applies_after_an_external_sign_in() {
    let s = gated_server();
    let outcome = external(
        &s,
        google("g-new", Some(("new@example.com", true))),
        create_users(),
    )
    .await
    .unwrap();
    let ExternalLoginOutcome::SecondFactor(challenge) = outcome else {
        panic!("expected a second-factor challenge, got {outcome:?}");
    };
    // The session records the provider, not a password.
    assert_eq!(complete(&s, challenge).await.amr, ["fed", "mfa", "otp"]);
}

#[tokio::test]
async fn a_password_confirmed_link_records_both_methods() {
    let s = gated_server();
    register(&s.auth, "ann@example.com").await;
    let challenge = link_challenge(
        external(
            &s,
            google("g-ann", Some(("ann@example.com", true))),
            ProviderPolicy::default(),
        )
        .await
        .unwrap(),
    );
    let outcome = s
        .auth
        .authentication()
        .confirm_link(
            LinkConfirmation {
                challenge_token: challenge.challenge_token,
                password: VALID_PASSWORD.into(),
            },
            ctx(IP_A),
        )
        .await
        .unwrap();
    let LoginOutcome::SecondFactor(challenge) = outcome else {
        panic!("expected a second-factor challenge");
    };
    assert_eq!(
        complete(&s, challenge).await.amr,
        ["fed", "mfa", "otp", "pwd"]
    );
}

#[tokio::test]
async fn password_logins_still_record_pwd() {
    let s = gated_server();
    register(&s.auth, "ann@example.com").await;
    let outcome = s
        .auth
        .authentication()
        .login(credentials("ann@example.com"), ctx(IP_A))
        .await
        .unwrap();
    let LoginOutcome::SecondFactor(challenge) = outcome else {
        panic!("expected a second-factor challenge");
    };
    assert_eq!(complete(&s, challenge).await.amr, ["mfa", "otp", "pwd"]);
}

#[tokio::test]
async fn a_provider_that_did_mfa_skips_the_local_second_factor() {
    let s = gated_server();
    let mut principal = google("g-new", Some(("new@example.com", true)));
    principal.amr = vec!["pwd".into(), "mfa".into(), "bad,value".into()];
    let pair = tokens(external(&s, principal, create_users()).await.unwrap());
    assert_eq!(claims(&s, &pair).await.amr, ["fed", "mfa", "pwd"]);
}

// ── Wiring ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn without_the_stores_external_sign_in_is_a_configuration_error() {
    let s = support::server(test_config());
    let err = external(&s, google("g", None), ProviderPolicy::default()).await;
    assert!(matches!(err, Err(AuthError::Config(_))));
    let err = s.auth.account_links().list(Uuid::new_v4()).await;
    assert!(matches!(err, Err(AuthError::Config(_))));
}

#[tokio::test]
async fn tick_purges_expired_flow_states() {
    let s = external_server(test_config());
    register(&s.auth, "ann@example.com").await;
    link_challenge(
        external(
            &s,
            google("g-ann", Some(("ann@example.com", true))),
            ProviderPolicy::default(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(s.db.flow_count(), 1);
    assert_eq!(s.auth.tick().await.unwrap().flows_purged, 0);
    s.clock.advance(Duration::from_secs(301));
    assert_eq!(s.auth.tick().await.unwrap().flows_purged, 1);
    assert_eq!(s.db.flow_count(), 0);
}

#[tokio::test]
async fn handlers_list_and_unlink_identities() {
    let s = external_server(test_config());
    register(&s.auth, "ann@example.com").await;
    let pair = password_login(&s, "ann@example.com").await;
    let sid = claims(&s, &pair).await.sid;
    s.auth
        .account_links()
        .link(sid, &google("g-ann", None), &ProviderPolicy::default())
        .await
        .unwrap();

    let listed = handlers::external_identities(
        s.auth.authentication(),
        s.auth.account_links(),
        &pair.access_token,
    )
    .await
    .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].provider, "google");
    // The wire form names the provider, never the subject or a token.
    let json = serde_json::to_string(&listed).unwrap();
    assert!(!json.contains("g-ann"));

    let removed = handlers::unlink_external_identity(
        s.auth.authentication(),
        s.auth.account_links(),
        &pair.access_token,
        listed[0].id,
    )
    .await
    .unwrap();
    assert_eq!(removed.id, listed[0].id);
    let err = handlers::unlink_external_identity(
        s.auth.authentication(),
        s.auth.account_links(),
        &pair.access_token,
        listed[0].id,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "external_identity_not_found");
    assert_eq!(err.status, 404);
}
