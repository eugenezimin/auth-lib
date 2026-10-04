//! PostgreSQL implementation of [`SessionRepository`].
//!
//! All SQL lives in [`crate::queries::session_queries`].  Every timestamp
//! is assigned by the database (`now()`); only durations are bound.
//! `create` and `rotate` run in transactions; `rotate` is a compare-and-swap
//! on `current_generation`, so concurrent refreshes of one session are
//! settled by the row lock (the loser gets [`RotateOutcome::Conflict`]).

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use auth_lib::AuthError;
use auth_lib::authentication::{
    NewSession, RefreshSnapshot, RotateOutcome, Session, SessionGeneration, SessionLifetimes,
    SessionRepository, SessionStatus,
};
use auth_lib::token::RevocationReason;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::codes::to_db_generation;
use crate::enums::{PgRevocationReason, PgSessionStatus};
use crate::errors::map_sqlx_error;
use crate::queries::session_queries;
use crate::rows::{GenerationRow, RefreshRow, SessionRow};

/// PostgreSQL-backed session repository.
pub struct PgSessionRepository {
    pool: PgPool,
}

impl PgSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

async fn insert_generation(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
    generation: i32,
    issued_ip: IpAddr,
    access_ttl: Duration,
) -> Result<SessionGeneration, AuthError> {
    let row: GenerationRow = sqlx::query_as(session_queries::INSERT_GENERATION)
        .bind(session_id)
        .bind(generation)
        .bind(issued_ip)
        .bind(access_ttl)
        .fetch_one(&mut **tx)
        .await
        .map_err(map_sqlx_error)?;
    row.try_into()
}

#[async_trait]
impl SessionRepository for PgSessionRepository {
    async fn create(
        &self,
        session: NewSession,
        lifetimes: &SessionLifetimes,
    ) -> Result<(Session, SessionGeneration), AuthError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let row: SessionRow = sqlx::query_as(session_queries::INSERT_SESSION)
            .bind(session.user_id)
            .bind(&session.secret)
            .bind(session.created_ip)
            .bind(&session.user_agent)
            .bind(lifetimes.idle_timeout)
            .bind(lifetimes.absolute_timeout)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let session: Session = row.try_into()?;
        let first = insert_generation(
            &mut tx,
            session.id,
            to_db_generation(session.current_generation)?,
            session.created_ip,
            lifetimes.access_ttl,
        )
        .await?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok((session, first))
    }

    async fn find(&self, session_id: Uuid) -> Result<Option<Session>, AuthError> {
        let row: Option<SessionRow> = sqlx::query_as(session_queries::FIND_SESSION)
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn find_generation(
        &self,
        session_id: Uuid,
        generation: u32,
    ) -> Result<Option<SessionGeneration>, AuthError> {
        let row: Option<GenerationRow> = sqlx::query_as(session_queries::FIND_GENERATION)
            .bind(session_id)
            .bind(to_db_generation(generation)?)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn load_for_refresh(
        &self,
        session_id: Uuid,
        generation: u32,
    ) -> Result<Option<RefreshSnapshot>, AuthError> {
        let row: Option<RefreshRow> = sqlx::query_as(session_queries::LOAD_FOR_REFRESH)
            .bind(session_id)
            .bind(to_db_generation(generation)?)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn rotate(
        &self,
        session_id: Uuid,
        expected_generation: u32,
        issued_ip: IpAddr,
        lifetimes: &SessionLifetimes,
    ) -> Result<RotateOutcome, AuthError> {
        let expected = to_db_generation(expected_generation)?;
        let newest = to_db_generation(expected_generation + 1)?;

        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let advanced: Option<SessionRow> = sqlx::query_as(session_queries::ADVANCE_SESSION)
            .bind(session_id)
            .bind(expected)
            .bind(lifetimes.idle_timeout)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let Some(session) = advanced else {
            tx.rollback().await.map_err(map_sqlx_error)?;
            return Ok(RotateOutcome::Conflict);
        };

        sqlx::query(session_queries::SUPERSEDE_GENERATION)
            .bind(session_id)
            .bind(expected)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let generation =
            insert_generation(&mut tx, session_id, newest, issued_ip, lifetimes.access_ttl).await?;
        sqlx::query(session_queries::TRIM_GENERATIONS)
            .bind(session_id)
            .bind(newest.saturating_sub(lifetimes.history_size as i32))
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(RotateOutcome::Rotated {
            session: session.try_into()?,
            generation,
        })
    }

    async fn end(
        &self,
        session_id: Uuid,
        status: SessionStatus,
        reason: RevocationReason,
    ) -> Result<bool, AuthError> {
        let result = sqlx::query(session_queries::END_SESSION)
            .bind(session_id)
            .bind(PgSessionStatus::from(status))
            .bind(PgRevocationReason::from(reason))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn mark_compromised(
        &self,
        session_id: Uuid,
        reason: RevocationReason,
    ) -> Result<bool, AuthError> {
        let result = sqlx::query(session_queries::MARK_COMPROMISED)
            .bind(session_id)
            .bind(PgRevocationReason::from(reason))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn end_all_for_user(
        &self,
        user_id: Uuid,
        status: SessionStatus,
        reason: RevocationReason,
    ) -> Result<Vec<Uuid>, AuthError> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(session_queries::END_ALL_FOR_USER)
            .bind(user_id)
            .bind(PgSessionStatus::from(status))
            .bind(PgRevocationReason::from(reason))
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn list_active_for_user(&self, user_id: Uuid) -> Result<Vec<Session>, AuthError> {
        let rows: Vec<SessionRow> = sqlx::query_as(session_queries::LIST_ACTIVE_FOR_USER)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn purge(&self, retention: Duration) -> Result<u64, AuthError> {
        let result = sqlx::query(session_queries::PURGE_SESSIONS)
            .bind(retention)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }
}
