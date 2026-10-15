//! Integration tests — versioned migrations and connection settings.
//!
//! Run with:
//!   cargo test -p z-auth-postgres --test migrations

mod helpers;

use z_auth_postgres::{MIGRATOR, run_migrations};

use crate::helpers::pool;

#[tokio::test]
async fn test_migrations_are_recorded_and_idempotent() {
    let pool = pool().await; // already migrated once
    run_migrations(&pool).await.expect("re-running is a no-op");

    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    let embedded: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    let core: Vec<i64> = versions.iter().copied().filter(|v| *v < 1000).collect();
    assert_eq!(core, embedded);
}

/// The cluster set lives beside the core one in `_sqlx_migrations`
/// (versions from 1001); each migrator leaves the other's versions alone.
#[cfg(feature = "shared")]
#[tokio::test]
async fn test_cluster_migrations_apply_on_top_of_the_core_set() {
    use z_auth_postgres::{CLUSTER_MIGRATOR, run_cluster_migrations};

    let pool = pool().await;
    run_cluster_migrations(&pool)
        .await
        .expect("cluster set applies");
    run_migrations(&pool)
        .await
        .expect("the core migrator ignores cluster versions");

    let versions: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success AND version >= 1000 ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let embedded: Vec<i64> = CLUSTER_MIGRATOR.iter().map(|m| m.version).collect();
    assert_eq!(versions, embedded);
    assert!(embedded.iter().all(|v| *v >= 1000));
}

#[tokio::test]
async fn test_enum_types_exist() {
    let pool = pool().await;
    let mut types: Vec<String> = sqlx::query_scalar(
        // Only this schema: session-store schemas left behind by an
        // interrupted sync or federation test carry the same types.
        "SELECT typname::text FROM pg_type
         WHERE typtype = 'e'
           AND typnamespace = current_schema()::regnamespace
           AND typname IN ('session_status', 'revocation_scope', 'revocation_reason')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    types.sort();
    assert_eq!(
        types,
        ["revocation_reason", "revocation_scope", "session_status"]
    );
}

#[tokio::test]
async fn test_pooled_connections_use_utc() {
    let pool = pool().await;
    let tz: String = sqlx::query_scalar("SHOW timezone")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tz, "UTC");
}
