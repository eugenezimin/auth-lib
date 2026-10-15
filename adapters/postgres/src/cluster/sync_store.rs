//! PostgreSQL implementation of the federation-mode [`SyncStore`]: the
//! change feed (`cluster_change_feed`, filled by triggers in both the
//! authority's and the session-store schema), session aggregates with a revision
//! compare-and-swap, revocations and keys merged under a row lock, the
//! authority's snapshots, and per-cluster cursors.  Works on both the
//! authority's schema and the session-store schema.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;
use z_auth::AuthError;
use z_auth::security::session::{Session, SessionGeneration};
use z_auth::security::token::{Revocation, RevocationScope, VerifyingKeyRecord};
use z_auth_cluster::federation::{
    AccountSnapshot, ApplyOutcome, CatalogSnapshot, ChangePage, FeedCursor, GenerationVariant,
    SessionAggregate, SiteId, SyncRecord, SyncStore, merge_key, merge_revocation,
};

use crate::codes::to_db_generation;
use crate::enums::{
    PgKeyStatus, PgRevocationReason, PgRevocationScope, PgRevocationStatus, PgSessionStatus,
};
use crate::errors::map_sqlx_error;

/// SQLSTATE: foreign-key violation.
const PG_FOREIGN_KEY_VIOLATION: &str = "23503";
use super::sync_queries as q;
use crate::rows::{GenerationRow, KeyRow, RevocationRow, SessionRow, fingerprint_from_db};

/// PostgreSQL-backed sync store.
pub struct PgSyncStore {
    pool: PgPool,
}

impl PgSyncStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The next account-snapshot version (authority only).
    pub async fn next_account_version(&self) -> Result<u64, AuthError> {
        let v: i64 = sqlx::query_scalar(q::NEXT_ACCOUNT_VERSION)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(v as u64)
    }
}

#[derive(sqlx::FromRow)]
struct SessionRevRow {
    #[sqlx(flatten)]
    session: SessionRow,
    merge_rev: i64,
}

#[derive(sqlx::FromRow)]
struct AliasRow {
    jti: Uuid,
    generation: i32,
    parent_jti: Option<Uuid>,
    issued_ip: IpAddr,
    issued_user_agent: Option<String>,
    fingerprint_hash: Option<Vec<u8>>,
    issued_at: DateTime<Utc>,
    access_expires_at: DateTime<Utc>,
    superseded_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct FeedRow {
    kind: String,
    key: String,
    seq: i64,
    txid: String,
}

#[derive(sqlx::FromRow)]
struct AccountRow {
    user_id: Uuid,
    version: i64,
    is_active: bool,
    deleted: bool,
    authz: Option<Json<z_auth::security::token::AuthzClaims>>,
}

fn cursor_of(txid: &str, seq: i64) -> Result<FeedCursor, AuthError> {
    Ok(FeedCursor {
        txid: txid
            .parse()
            .map_err(|_| AuthError::Storage(format!("bad feed txid {txid}")))?,
        seq: seq as u64,
    })
}

fn scope_parts(scope: RevocationScope) -> (PgRevocationScope, Uuid) {
    match scope {
        RevocationScope::Session(id) => (PgRevocationScope::Session, id),
        RevocationScope::User(id) => (PgRevocationScope::User, id),
        RevocationScope::Token(jti) => (PgRevocationScope::Token, jti),
    }
}

fn is_fk_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some(PG_FOREIGN_KEY_VIOLATION))
}

async fn load_aggregate(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<(SessionAggregate, u64)>, AuthError> {
    let Some(row): Option<SessionRevRow> = sqlx::query_as(q::LOAD_SESSION)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx_error)?
    else {
        return Ok(None);
    };
    let rev = row.merge_rev as u64;
    let session: Session = row.session.try_into()?;
    let gens: Vec<GenerationRow> = sqlx::query_as(q::LOAD_GENERATIONS)
        .bind(id)
        .fetch_all(&mut **tx)
        .await
        .map_err(map_sqlx_error)?;
    let aliases: Vec<AliasRow> = sqlx::query_as(q::LOAD_ALIASES)
        .bind(id)
        .fetch_all(&mut **tx)
        .await
        .map_err(map_sqlx_error)?;
    let mut parts: Vec<(SessionGeneration, Vec<GenerationVariant>)> = Vec::new();
    for g in gens {
        let g: SessionGeneration = g.try_into()?;
        let variants = aliases
            .iter()
            .filter(|a| a.generation as u32 == g.generation)
            .map(|a| {
                Ok(GenerationVariant {
                    access_jti: a.jti,
                    parent_jti: a.parent_jti,
                    issued_ip: a.issued_ip,
                    issued_user_agent: a.issued_user_agent.clone(),
                    fingerprint_hash: fingerprint_from_db(a.fingerprint_hash.clone())?,
                    issued_at: a.issued_at,
                    access_expires_at: a.access_expires_at,
                    superseded_at: a.superseded_at,
                })
            })
            .collect::<Result<Vec<_>, AuthError>>()?;
        parts.push((g, variants));
    }
    Ok(Some((SessionAggregate::from_parts(&session, &parts), rev)))
}

impl PgSyncStore {
    async fn record(&self, kind: &str, key: &str) -> Result<Option<SyncRecord>, AuthError> {
        match kind {
            "session" => {
                let Ok(id) = key.parse() else { return Ok(None) };
                Ok(self
                    .load_session(id)
                    .await?
                    .map(|(a, _)| SyncRecord::Session(Box::new(a))))
            }
            "revocation" => {
                let Ok(id) = key.parse::<Uuid>() else {
                    return Ok(None);
                };
                let row: Option<RevocationRow> = sqlx::query_as(q::SELECT_REVOCATION)
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                Ok(row.map(|r| SyncRecord::Revocation(r.into())))
            }
            "verifying_key" => {
                let row: Option<KeyRow> = sqlx::query_as(q::SELECT_KEY)
                    .bind(key)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                row.map(|r| r.try_into().map(SyncRecord::VerifyingKey))
                    .transpose()
            }
            "account" => {
                let Ok(id) = key.parse() else { return Ok(None) };
                Ok(self.load_account(id).await?.map(SyncRecord::Account))
            }
            "catalog" => Ok(self
                .load_catalog()
                .await?
                .map(|c| SyncRecord::Catalog(Box::new(c)))),
            _ => Ok(None),
        }
    }
}

#[async_trait]
impl SyncStore for PgSyncStore {
    async fn site_id(&self) -> Result<SiteId, AuthError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let created: Option<Uuid> = sqlx::query_scalar(q::CREATE_SITE)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let id = match created {
            Some(id) => {
                sqlx::query(q::SEED_FEED)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
                id
            }
            None => sqlx::query_scalar(q::SELECT_SITE)
                .fetch_one(&mut *tx)
                .await
                .map_err(map_sqlx_error)?,
        };
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(SiteId(id))
    }

    async fn head(&self) -> Result<FeedCursor, AuthError> {
        let row: Option<(String, i64)> = sqlx::query_as(q::HEAD)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.map(|(txid, seq)| cursor_of(&txid, seq))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    async fn changes_since(&self, after: FeedCursor, limit: u32) -> Result<ChangePage, AuthError> {
        let site = self.site_id().await?;
        let rows: Vec<FeedRow> = sqlx::query_as(q::CHANGES_SINCE)
            .bind(after.txid.to_string())
            .bind(after.seq as i64)
            .bind(i64::from(limit) + 1)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        let more = rows.len() > limit as usize;
        let mut next = after;
        let mut records = Vec::new();
        for row in rows.into_iter().take(limit as usize) {
            next = cursor_of(&row.txid, row.seq)?;
            if let Some(record) = self.record(&row.kind, &row.key).await? {
                records.push(record);
            }
        }
        Ok(ChangePage {
            site,
            records,
            next,
            more,
        })
    }

    async fn load_session(&self, id: Uuid) -> Result<Option<(SessionAggregate, u64)>, AuthError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        // One consistent snapshot of the session and its generations.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let aggregate = load_aggregate(&mut tx, id).await?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(aggregate)
    }

    async fn store_session(
        &self,
        merged: &SessionAggregate,
        expected: Option<u64>,
    ) -> Result<ApplyOutcome, AuthError> {
        let s = &merged.session;
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let current: Option<i64> = sqlx::query_scalar(q::LOCK_SESSION_REV)
            .bind(s.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        if current.map(|r| r as u64) != expected {
            return Ok(ApplyOutcome::Conflict);
        }
        let status = PgSessionStatus::from(s.status);
        let end_reason = s.end_reason.map(PgRevocationReason::from);
        let current_generation = to_db_generation(s.current_generation)?;
        if current.is_none() {
            let inserted = sqlx::query(q::INSERT_SESSION_WITH_ID)
                .bind(s.id)
                .bind(s.user_id)
                .bind(&s.secret)
                .bind(status)
                .bind(end_reason)
                .bind(s.created_ip)
                .bind(&s.user_agent)
                .bind(current_generation)
                .bind(s.created_at)
                .bind(s.idle_expires_at)
                .bind(s.absolute_expires_at)
                .bind(s.ended_at)
                .execute(&mut *tx)
                .await;
            match inserted {
                Ok(_) => {}
                // The authority deleted the user (sessions cascade): drop.
                Err(e) if is_fk_violation(&e) => return Ok(ApplyOutcome::Dropped),
                Err(e) => return Err(map_sqlx_error(e)),
            }
        } else {
            sqlx::query(q::UPDATE_MERGED_SESSION)
                .bind(s.id)
                .bind(status)
                .bind(end_reason)
                .bind(current_generation)
                .bind(s.idle_expires_at)
                .bind(s.ended_at)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
        }
        for delete in [q::DELETE_ALIASES, q::DELETE_GENERATIONS] {
            sqlx::query(delete)
                .bind(s.id)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
        }
        for (g, aliases) in merged.stored_generations() {
            let generation = to_db_generation(g.generation)?;
            sqlx::query(q::INSERT_GENERATION_WITH_ID)
                .bind(g.access_jti)
                .bind(s.id)
                .bind(generation)
                .bind(g.issued_ip)
                .bind(g.issued_at)
                .bind(g.access_expires_at)
                .bind(g.superseded_at)
                .bind(g.parent_jti)
                .bind(&g.issued_user_agent)
                .bind(g.fingerprint_hash.map(|h| h.to_vec()))
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
            for a in aliases {
                sqlx::query(q::INSERT_ALIAS)
                    .bind(a.access_jti)
                    .bind(s.id)
                    .bind(generation)
                    .bind(a.parent_jti)
                    .bind(a.issued_ip)
                    .bind(&a.issued_user_agent)
                    .bind(a.fingerprint_hash.map(|h| h.to_vec()))
                    .bind(a.issued_at)
                    .bind(a.access_expires_at)
                    .bind(a.superseded_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
            }
        }
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(ApplyOutcome::Applied)
    }

    async fn active_session_ids(&self, user_id: Uuid) -> Result<Vec<Uuid>, AuthError> {
        sqlx::query_scalar(q::ACTIVE_SESSION_IDS)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)
    }

    async fn merge_revocation(&self, incoming: &Revocation) -> Result<ApplyOutcome, AuthError> {
        // Twice at most: a concurrent insert of the same id makes the first
        // attempt merge into it.
        for _ in 0..2 {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let existing: Option<RevocationRow> = sqlx::query_as(q::LOCK_REVOCATION)
                .bind(incoming.id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
            let (target, insert) = match existing {
                Some(row) => {
                    let existing: Revocation = row.into();
                    let merged = merge_revocation(&existing, incoming);
                    if merged == existing {
                        return Ok(ApplyOutcome::Unchanged);
                    }
                    (merged, false)
                }
                None => (incoming.clone(), true),
            };
            if insert {
                let (scope, subject) = scope_parts(target.scope);
                let inserted = sqlx::query(q::INSERT_REVOCATION_WITH_ID)
                    .bind(target.id)
                    .bind(scope)
                    .bind(subject)
                    .bind(PgRevocationReason::from(target.reason))
                    .bind(PgRevocationStatus::from(target.status))
                    .bind(target.origin_node)
                    .bind(target.revoked_at)
                    .bind(target.expires_at)
                    .bind(target.enforced_at)
                    .bind(target.enforced_by)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
                if inserted.rows_affected() == 0 {
                    continue; // inserted concurrently: merge into it
                }
            } else {
                sqlx::query(q::UPDATE_MERGED_REVOCATION)
                    .bind(target.id)
                    .bind(PgRevocationReason::from(target.reason))
                    .bind(PgRevocationStatus::from(target.status))
                    .bind(target.origin_node)
                    .bind(target.revoked_at)
                    .bind(target.expires_at)
                    .bind(target.enforced_at)
                    .bind(target.enforced_by)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
            }
            tx.commit().await.map_err(map_sqlx_error)?;
            return Ok(ApplyOutcome::Applied);
        }
        Ok(ApplyOutcome::Conflict)
    }

    async fn merge_key(&self, incoming: &VerifyingKeyRecord) -> Result<ApplyOutcome, AuthError> {
        for _ in 0..2 {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let existing: Option<KeyRow> = sqlx::query_as(q::LOCK_KEY)
                .bind(&incoming.kid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
            match existing {
                Some(row) => {
                    let existing: VerifyingKeyRecord = row.try_into()?;
                    let merged = merge_key(&existing, incoming);
                    if merged == existing {
                        return Ok(ApplyOutcome::Unchanged);
                    }
                    sqlx::query(q::UPDATE_MERGED_KEY)
                        .bind(&merged.kid)
                        .bind(PgKeyStatus::from(merged.status))
                        .bind(merged.published_by)
                        .bind(merged.created_at)
                        .bind(merged.revoked_at)
                        .execute(&mut *tx)
                        .await
                        .map_err(map_sqlx_error)?;
                }
                None => {
                    let inserted = sqlx::query(q::INSERT_KEY_FULL)
                        .bind(&incoming.kid)
                        .bind(incoming.public_key.as_slice())
                        .bind(PgKeyStatus::from(incoming.status))
                        .bind(incoming.published_by)
                        .bind(incoming.created_at)
                        .bind(incoming.revoked_at)
                        .execute(&mut *tx)
                        .await
                        .map_err(map_sqlx_error)?;
                    if inserted.rows_affected() == 0 {
                        continue;
                    }
                }
            }
            tx.commit().await.map_err(map_sqlx_error)?;
            return Ok(ApplyOutcome::Applied);
        }
        Ok(ApplyOutcome::Conflict)
    }

    async fn apply_account(&self, a: &AccountSnapshot) -> Result<ApplyOutcome, AuthError> {
        let result = sqlx::query(q::APPLY_ACCOUNT)
            .bind(a.user_id)
            .bind(a.version as i64)
            .bind(a.is_active)
            .bind(a.deleted)
            .bind(a.authz.as_ref().map(Json))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(if result.rows_affected() > 0 {
            ApplyOutcome::Applied
        } else {
            ApplyOutcome::Unchanged
        })
    }

    async fn load_account(&self, user_id: Uuid) -> Result<Option<AccountSnapshot>, AuthError> {
        let row: Option<AccountRow> = sqlx::query_as(q::LOAD_ACCOUNT)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(|r| AccountSnapshot {
            user_id: r.user_id,
            version: r.version as u64,
            is_active: r.is_active,
            deleted: r.deleted,
            authz: r.authz.map(|Json(a)| a),
        }))
    }

    async fn apply_catalog(&self, c: &CatalogSnapshot) -> Result<ApplyOutcome, AuthError> {
        let result = sqlx::query(q::APPLY_CATALOG)
            .bind(c.version as i64)
            .bind(Json(&c.catalog))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(if result.rows_affected() > 0 {
            ApplyOutcome::Applied
        } else {
            ApplyOutcome::Unchanged
        })
    }

    async fn load_catalog(&self) -> Result<Option<CatalogSnapshot>, AuthError> {
        let row: Option<(
            i64,
            Json<z_auth::security::authorization::PermissionCatalog>,
        )> = sqlx::query_as(q::LOAD_CATALOG)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(|(version, Json(catalog))| CatalogSnapshot {
            version: version as u64,
            catalog,
        }))
    }

    async fn cursor(&self, site: SiteId) -> Result<FeedCursor, AuthError> {
        let row: Option<(i64, i64)> = sqlx::query_as(q::LOAD_CURSOR)
            .bind(site.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row
            .map(|(txid, seq)| FeedCursor {
                txid: txid as u64,
                seq: seq as u64,
            })
            .unwrap_or_default())
    }

    async fn advance_cursor(&self, site: SiteId, to: FeedCursor) -> Result<(), AuthError> {
        sqlx::query(q::ADVANCE_CURSOR)
            .bind(site.0)
            .bind(to.txid as i64)
            .bind(to.seq as i64)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn reset_cursor(&self, site: SiteId) -> Result<(), AuthError> {
        sqlx::query(q::RESET_CURSOR)
            .bind(site.0)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn next_version(&self) -> Result<u64, AuthError> {
        self.next_account_version().await
    }

    async fn record_caught_up(&self, service: &str, at: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(q::RECORD_CAUGHT_UP)
            .bind(service)
            .bind(at)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn caught_up_at(&self, service: &str) -> Result<Option<DateTime<Utc>>, AuthError> {
        sqlx::query_scalar(q::CAUGHT_UP_AT)
            .bind(service)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)
    }
}
