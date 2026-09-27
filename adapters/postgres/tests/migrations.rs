//! Integration tests — versioned migrations and connection settings.
//!
//! Run with:
//!   cargo test -p auth-lib-postgres --test migrations

mod helpers;

use auth_lib_postgres::{MIGRATOR, run_migrations};

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
    assert_eq!(versions, embedded);
}

#[tokio::test]
async fn test_enum_types_exist() {
    let pool = pool().await;
    let mut types: Vec<String> = sqlx::query_scalar(
        "SELECT typname::text FROM pg_type
         WHERE typtype = 'e'
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
