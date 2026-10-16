//! Integration tests — linked external identities and flow states against
//! Postgres (feature `external-identity`).
//!
//! Run with:
//!   cargo test -p z-auth-postgres --features external-identity --test external_identity

mod helpers;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;
use z_auth::AuthError;
use z_auth::ZAuth;
use z_auth::conf::config::RawConfig;
use z_auth::identity::external::{
    ExternalIdentityRepository, ExternalPrincipal, LinkPolicy, NewExternalIdentity, ProviderPolicy,
    Provisioning,
};
use z_auth::identity::user::RegisterUser;
use z_auth::security::authentication::{
    ClientContext, ExternalLoginOutcome, FlowStateRepository, LinkConfirmation, LoginOutcome,
};
use z_auth::security::token::keys::{generate_refresh_secret, generate_signing_key};
use z_auth_postgres::{
    PgExternalIdentityRepository, PgFlowStateRepository, repositories, run_external_migrations,
};

use crate::helpers::{cleanup_user_by_id, create_test_user, pool, unique_email};

const PASSWORD: &str = "S3cur3P@ssw0rd!";

struct Setup {
    auth: ZAuth,
    identities: Arc<PgExternalIdentityRepository>,
    flows: Arc<PgFlowStateRepository>,
}

async fn setup() -> Setup {
    let pool = pool().await;
    run_external_migrations(&pool)
        .await
        .expect("external-identity migrations");
    let identities = Arc::new(PgExternalIdentityRepository::new(pool.clone()));
    let flows = Arc::new(PgFlowStateRepository::new(pool.clone()));
    let keys = generate_signing_key().unwrap();
    let config = RawConfig::default()
        .jwt_signing_key(keys.signing_key)
        .jwt_issuer("z-auth-test")
        .refresh_secret(generate_refresh_secret().unwrap())
        .build()
        .unwrap();
    let auth = ZAuth::builder(config, repositories(&pool))
        .external_identities(identities.clone(), flows.clone())
        .build()
        .unwrap();
    Setup {
        auth,
        identities,
        flows,
    }
}

fn ctx() -> ClientContext {
    ClientContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

async fn user(s: &Setup) -> z_auth::identity::user::User {
    create_test_user(
        &s.auth,
        RegisterUser {
            email: unique_email("ext"),
            password: PASSWORD.into(),
            username: None,
            first_name: None,
            last_name: None,
        },
    )
    .await
}

fn new_identity(user_id: Uuid, subject: &str) -> NewExternalIdentity {
    NewExternalIdentity {
        user_id,
        provider: "google".into(),
        issuer: "https://accounts.google.com".into(),
        subject: subject.into(),
        email: Some("someone@example.com".into()),
    }
}

#[tokio::test]
async fn identities_round_trip_and_follow_their_user() {
    let s = setup().await;
    let u = user(&s).await;
    let subject = Uuid::new_v4().to_string();
    let created = s
        .identities
        .create(new_identity(u.id, &subject))
        .await
        .unwrap();
    assert_eq!(created.user_id, u.id);
    assert!(created.last_login_at.is_none());

    let found = s
        .identities
        .find_by_subject("https://accounts.google.com", &subject)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found, created);
    s.identities.record_login(created.id).await.unwrap();
    let listed = s.identities.list_for_user(u.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].last_login_at.is_some());

    // One owner per (issuer, subject).
    let other = user(&s).await;
    let err = s.identities.create(new_identity(other.id, &subject)).await;
    assert!(matches!(
        err,
        Err(AuthError::ExternalIdentityLinkedElsewhere)
    ));

    // Deleting the user deletes their identities.
    cleanup_user_by_id(&s.auth, u.id).await.unwrap();
    assert!(s.identities.find(created.id).await.unwrap().is_none());
    cleanup_user_by_id(&s.auth, other.id).await.unwrap();
}

#[tokio::test]
async fn flow_states_are_single_use_and_expire() {
    let s = setup().await;
    let key = format!("test:{}", Uuid::new_v4());
    s.flows
        .put(&key, "value", Duration::from_secs(60))
        .await
        .unwrap();
    // Replaced by a second put.
    s.flows
        .put(&key, "newer", Duration::from_secs(60))
        .await
        .unwrap();

    // Raced: exactly one taker gets it.
    let takes = (0..8).map(|_| {
        let flows = s.flows.clone();
        let key = key.clone();
        tokio::spawn(async move { flows.take(&key).await.unwrap() })
    });
    let mut won = Vec::new();
    for take in takes {
        won.extend(take.await.unwrap());
    }
    assert_eq!(won, ["newer"]);

    let expired = format!("test:{}", Uuid::new_v4());
    s.flows.put(&expired, "old", Duration::ZERO).await.unwrap();
    assert_eq!(s.flows.take(&expired).await.unwrap(), None);
    s.flows.put(&expired, "old", Duration::ZERO).await.unwrap();
    assert!(s.flows.purge_expired().await.unwrap() >= 1);
}

#[tokio::test]
async fn external_sign_in_links_through_the_password() {
    let s = setup().await;
    let u = user(&s).await;
    let principal = ExternalPrincipal::new("google", "https://accounts.google.com", Uuid::new_v4())
        .with_email(u.email.clone(), true);
    let policy = ProviderPolicy {
        link: LinkPolicy::ConfirmWithPassword,
        provisioning: Provisioning::Deny,
        trust_email: true,
        max_links: 1,
    };

    let outcome = s
        .auth
        .authentication()
        .login_external(principal.clone(), policy, ctx())
        .await
        .unwrap();
    let ExternalLoginOutcome::LinkConfirmation(challenge) = outcome else {
        panic!("expected a link confirmation, got {outcome:?}");
    };
    let pair = s
        .auth
        .authentication()
        .confirm_link(
            LinkConfirmation {
                challenge_token: challenge.challenge_token,
                password: PASSWORD.into(),
            },
            ctx(),
        )
        .await
        .and_then(LoginOutcome::into_tokens)
        .unwrap();
    let claims = s
        .auth
        .authentication()
        .verify_access_token(&pair.access_token)
        .await
        .unwrap();
    assert_eq!(claims.sub, u.id);
    assert_eq!(claims.amr, ["fed", "pwd"]);

    let outcome = s
        .auth
        .authentication()
        .login_external(principal, policy, ctx())
        .await
        .unwrap();
    assert!(matches!(outcome, ExternalLoginOutcome::Tokens(_)));
    assert_eq!(s.auth.account_links().list(u.id).await.unwrap().len(), 1);
    cleanup_user_by_id(&s.auth, u.id).await.unwrap();
}
