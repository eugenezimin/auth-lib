//! PostgreSQL implementation of [`RevocationRepository`] — the persisted
//! denylist.  All SQL lives in [`crate::queries::revocation_queries`];
//! `revoked_at` / `expires_at` are stamped by the database.

use async_trait::async_trait;
use auth_lib::AuthError;
use auth_lib::token::{NewRevocation, Revocation, RevocationRepository, RevocationScope};
use sqlx::PgPool;

use crate::enums::{PgRevocationReason, PgRevocationScope};
use crate::errors::map_sqlx_error;
use crate::queries::revocation_queries;
use crate::rows::RevocationRow;

/// PostgreSQL-backed revocation repository.
pub struct PgRevocationRepository {
    pool: PgPool,
}

impl PgRevocationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RevocationRepository for PgRevocationRepository {
    async fn insert(&self, revocation: &NewRevocation) -> Result<Revocation, AuthError> {
        let (scope, subject) = match revocation.scope {
            RevocationScope::Session(id) => (PgRevocationScope::Session, id),
            RevocationScope::User(id) => (PgRevocationScope::User, id),
        };
        let row: RevocationRow = sqlx::query_as(revocation_queries::INSERT_REVOCATION)
            .bind(scope)
            .bind(subject)
            .bind(PgRevocationReason::from(revocation.reason))
            .bind(revocation.ttl)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.into())
    }

    async fn list_active(&self) -> Result<Vec<Revocation>, AuthError> {
        let rows: Vec<RevocationRow> = sqlx::query_as(revocation_queries::LIST_ACTIVE)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn purge_expired(&self) -> Result<u64, AuthError> {
        let result = sqlx::query(revocation_queries::PURGE_EXPIRED)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }
}
