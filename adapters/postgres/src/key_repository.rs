//! PostgreSQL implementation of [`KeyRepository`]: published verifying
//! keys.  All SQL lives in [`crate::queries::key_queries`].

use async_trait::async_trait;
use z_auth::AuthError;
use z_auth::security::token::{KeyRepository, NewVerifyingKey, VerifyingKeyRecord};
use sqlx::PgPool;

use crate::errors::map_sqlx_error;
use crate::queries::key_queries as q;
use crate::rows::KeyRow;

/// PostgreSQL-backed store of published verifying keys.
pub struct PgKeyRepository {
    pool: PgPool,
}

impl PgKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KeyRepository for PgKeyRepository {
    async fn publish(&self, key: &NewVerifyingKey) -> Result<VerifyingKeyRecord, AuthError> {
        let row: KeyRow = sqlx::query_as(q::PUBLISH_KEY)
            .bind(&key.kid)
            .bind(key.public_key.as_slice())
            .bind(key.published_by)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.try_into()
    }

    async fn revoke(&self, kid: &str) -> Result<Option<VerifyingKeyRecord>, AuthError> {
        let row: Option<KeyRow> = sqlx::query_as(q::REVOKE_KEY)
            .bind(kid)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list(&self) -> Result<Vec<VerifyingKeyRecord>, AuthError> {
        let rows: Vec<KeyRow> = sqlx::query_as(q::LIST_KEYS)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}
