//! Integration tests — the store side of revocation enforcement and key
//! distribution against Postgres: the enforcement compare-and-swap and
//! published verifying keys.
//!
//! Run with:
//!   cargo test -p z-auth-postgres --test keys

mod helpers;

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;
use z_auth::security::session::RevocationReason;
use z_auth::security::token::{
    KeyRepository, KeyStatus, NewRevocation, NewVerifyingKey, RevocationRepository,
    RevocationScope, RevocationStatus,
};
use z_auth_postgres::{PgKeyRepository, PgRevocationRepository};

use crate::helpers::pool;

#[tokio::test]
async fn test_exactly_one_instance_enforces_a_revocation() {
    let repo = Arc::new(PgRevocationRepository::new(pool().await));
    let stored = repo
        .insert(&NewRevocation {
            scope: RevocationScope::Session(Uuid::new_v4()),
            reason: RevocationReason::Administrative,
            ttl: Duration::from_secs(60),
            origin_node: Uuid::new_v4(),
        })
        .await
        .unwrap();
    assert_eq!(stored.status, RevocationStatus::Pending);
    assert!(stored.enforced_at.is_none());

    let (n1, n2) = (Uuid::new_v4(), Uuid::new_v4());
    let (a, b) = tokio::join!(
        repo.mark_enforced(stored.id, n1),
        repo.mark_enforced(stored.id, n2)
    );
    let winners: Vec<_> = [a.unwrap(), b.unwrap()].into_iter().flatten().collect();
    assert_eq!(winners.len(), 1, "compare-and-swap: one winner");
    let won = &winners[0];
    assert_eq!(won.status, RevocationStatus::Enforced);
    assert!(won.enforced_at.is_some());
    assert!(won.enforced_by == Some(n1) || won.enforced_by == Some(n2));
    assert!(repo.mark_enforced(stored.id, n1).await.unwrap().is_none());
}

#[tokio::test]
async fn test_verifying_keys_publish_idempotently_and_revoke_for_good() {
    let repo = PgKeyRepository::new(pool().await);
    let kid = Uuid::new_v4().simple().to_string()[..16].to_string();
    let key = NewVerifyingKey {
        kid: kid.clone(),
        public_key: [9; 32],
        published_by: Uuid::new_v4(),
    };

    let first = repo.publish(&key).await.unwrap();
    assert_eq!(first.status, KeyStatus::Active);
    assert_eq!(first.public_key, [9; 32]);
    let again = repo.publish(&key).await.unwrap();
    assert_eq!(again, first, "idempotent per kid");

    let revoked = repo.revoke(&kid).await.unwrap().unwrap();
    assert_eq!(revoked.status, KeyStatus::Revoked);
    assert!(revoked.revoked_at.is_some());
    assert_eq!(
        repo.publish(&key).await.unwrap().status,
        KeyStatus::Revoked,
        "a revoked key stays revoked"
    );
    assert!(repo.list().await.unwrap().iter().any(|k| k.kid == kid));
    assert!(repo.revoke("unknown-kid").await.unwrap().is_none());
}
