//! Token revocation service implementation.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use crate::authentication::model::SessionStatus;
use crate::authentication::repository::SessionRepository;
use crate::clock::Clock;
use crate::error::AuthError;
use crate::events::{DomainEvent, EventPublisher};
use crate::token::codec::{AccessTokenDecoder, RefreshTokenCodec};
use crate::token::denylist::Denylist;
use crate::token::model::{
    ExpiryCheck, NewRevocation, RevocationReason, RevocationScope, RevokeTarget,
};
use crate::token::repository::RevocationRepository;
use crate::token::service::TokenRevocationService;

/// Default implementation of [`TokenRevocationService`].
pub struct TokenRevocationServiceImpl {
    sessions: Arc<dyn SessionRepository>,
    revocations: Arc<dyn RevocationRepository>,
    denylist: Arc<Denylist>,
    decoder: Arc<dyn AccessTokenDecoder>,
    refresh_codec: Arc<dyn RefreshTokenCodec>,
    clock: Arc<dyn Clock>,
    events: Arc<dyn EventPublisher>,
    /// This instance.
    node_id: Uuid,
    /// How long a denylist entry must live: access TTL + leeway.
    entry_ttl: Duration,
}

impl TokenRevocationServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: Arc<dyn SessionRepository>,
        revocations: Arc<dyn RevocationRepository>,
        denylist: Arc<Denylist>,
        decoder: Arc<dyn AccessTokenDecoder>,
        refresh_codec: Arc<dyn RefreshTokenCodec>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn EventPublisher>,
        node_id: Uuid,
        entry_ttl: Duration,
    ) -> Self {
        Self {
            sessions,
            revocations,
            denylist,
            decoder,
            refresh_codec,
            clock,
            events,
            node_id,
            entry_ttl,
        }
    }

    /// Persist a pending revocation, apply it locally, push it to every
    /// other instance.
    async fn publish(
        &self,
        scope: RevocationScope,
        reason: RevocationReason,
    ) -> Result<(), AuthError> {
        let stored = self
            .revocations
            .insert(&NewRevocation {
                scope,
                reason,
                ttl: self.entry_ttl,
                origin_node: self.node_id,
            })
            .await?;
        self.denylist.apply(&stored);
        self.events.publish(DomainEvent::Revoked(stored)).await;
        Ok(())
    }

    /// Resolve a refresh token to its session, verifying the MAC.
    async fn session_of_refresh_token(&self, token: &str) -> Result<Uuid, AuthError> {
        let parsed = self.refresh_codec.parse(token)?;
        let session = self
            .sessions
            .find(parsed.session_id)
            .await?
            .ok_or_else(|| AuthError::InvalidToken("unknown session".into()))?;
        if !self.refresh_codec.verify(&parsed, &session.secret) {
            return Err(AuthError::InvalidToken("bad refresh token".into()));
        }
        Ok(session.id)
    }
}

/// Security incidents mark a session `compromised`; everything else `revoked`.
fn status_for(reason: RevocationReason) -> SessionStatus {
    match reason {
        RevocationReason::TokenReuse
        | RevocationReason::IpMismatch
        | RevocationReason::Compromised
        | RevocationReason::RevokedTokenUsed => SessionStatus::Compromised,
        RevocationReason::Logout
        | RevocationReason::LogoutAll
        | RevocationReason::Evicted
        | RevocationReason::Administrative
        | RevocationReason::PasswordChanged
        | RevocationReason::AccountDisabled
        | RevocationReason::AccountDeleted => SessionStatus::Revoked,
    }
}

#[async_trait]
impl TokenRevocationService for TokenRevocationServiceImpl {
    async fn revoke(
        &self,
        target: RevokeTarget,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let session_id = match target {
            RevokeTarget::User(user_id) => return self.end_all_for_user(user_id, reason).await,
            RevokeTarget::Session(id) => id,
            RevokeTarget::AccessToken(token) => {
                self.decoder
                    .decode(&token, self.clock.now(), ExpiryCheck::Ignore)?
                    .sid
            }
            RevokeTarget::RefreshToken(token) => self.session_of_refresh_token(&token).await?,
        };
        Ok(u64::from(self.end_session(session_id, reason).await?))
    }

    async fn revoke_many(
        &self,
        targets: Vec<RevokeTarget>,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let mut ended = 0;
        for target in targets {
            match self.revoke(target, reason).await {
                Ok(n) => ended += n,
                Err(AuthError::InvalidToken(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(ended)
    }

    async fn end_session(
        &self,
        session_id: Uuid,
        reason: RevocationReason,
    ) -> Result<bool, AuthError> {
        let ended = self
            .sessions
            .end(session_id, status_for(reason), reason)
            .await?;
        if ended {
            self.publish(RevocationScope::Session(session_id), reason)
                .await?;
        }
        Ok(ended)
    }

    async fn end_all_for_user(
        &self,
        user_id: Uuid,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let ended = self
            .sessions
            .end_all_for_user(user_id, status_for(reason), reason)
            .await?;
        self.publish(RevocationScope::User(user_id), reason).await?;
        Ok(ended.len() as u64)
    }

    async fn purge_expired(&self) -> Result<u64, AuthError> {
        self.revocations.purge_expired().await
    }

    async fn load(&self) -> Result<usize, AuthError> {
        let active = self.revocations.list_active().await?;
        Ok(active.iter().filter(|r| self.denylist.apply(r)).count())
    }

    async fn enforce_pending(&self) -> Result<usize, AuthError> {
        let mut enforced = 0;
        for hit in self.denylist.drain_hits() {
            // Exactly one instance wins the compare-and-swap; the others
            // learn the outcome from the pushed event.
            let Some(revocation) = self
                .revocations
                .mark_enforced(hit.revocation_id, self.node_id)
                .await?
            else {
                continue;
            };
            self.sessions
                .mark_compromised(hit.session_id, RevocationReason::RevokedTokenUsed)
                .await?;
            self.denylist.apply(&revocation);
            self.events
                .publish(DomainEvent::RevocationEnforced(revocation))
                .await;
            enforced += 1;
        }
        Ok(enforced)
    }
}
