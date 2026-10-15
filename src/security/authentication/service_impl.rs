//! Authentication service implementation.
//!
//! Orchestrates repositories, codecs and the revocation service around the
//! pure refresh policy in [`crate::security::authentication::policy`].  The only I/O on
//! the hot path ([`verify_access_token`](AuthenticationService::verify_access_token))
//! is none: it is served entirely from memory.
//!
//! Every persisted timestamp comes from the store (see
//! [`SessionRepository`]); the local [`Clock`] only feeds the stateless
//! denylist and token checks.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use crate::conf::config::AuthConfig;
use crate::conf::constants::{REFRESH_ROTATE_ATTEMPTS, SESSION_SECRET_LEN};
use crate::identity::credentials::PasswordHasher;
use crate::identity::user::normalize_email;
use crate::identity::user::repository::UserRepository;
use crate::security::authentication::account::RefreshAccountSource;
use crate::security::authentication::gate::RefreshGate;
use crate::security::authentication::model::{ClientContext, Credentials, TokenPair};
use crate::security::authentication::policy::{RefreshDecision, RefreshInput, evaluate_refresh};
use crate::security::authentication::service::AuthenticationService;
use crate::security::authorization::service::AuthzClaimsProvider;
use crate::security::session::{
    NewSession, RevocationReason, RotateOutcome, Session, SessionGeneration, SessionLifetimes,
    SessionRepository,
};
use crate::security::token::codec::{AccessTokenDecoder, AccessTokenIssuer, RefreshTokenCodec};
use crate::security::token::keyring::KeyRing;
use crate::security::token::model::{AuthzClaims, Claims, ExpiryCheck};
use crate::security::token::service::TokenRevocationService;
use crate::security::token::verifier::TokenVerifier;
use crate::utils::clock::Clock;
use crate::utils::error::AuthError;
use crate::utils::random::random_bytes;

/// Default implementation of [`AuthenticationService`].
pub struct AuthenticationServiceImpl {
    users: Arc<dyn UserRepository>,
    accounts: Arc<dyn RefreshAccountSource>,
    sessions: Arc<dyn SessionRepository>,
    revocation: Arc<dyn TokenRevocationService>,
    authz: Arc<dyn AuthzClaimsProvider>,
    hasher: Arc<dyn PasswordHasher>,
    issuer: Arc<dyn AccessTokenIssuer>,
    decoder: Arc<dyn AccessTokenDecoder>,
    refresh_codec: Arc<dyn RefreshTokenCodec>,
    verifier: Arc<TokenVerifier>,
    keyring: Arc<KeyRing>,
    clock: Arc<dyn Clock>,
    lifetimes: SessionLifetimes,
    config: AuthConfig,
    /// Installed by an extension (e.g. a federated session store).
    gate: Option<Arc<dyn RefreshGate>>,
}

impl AuthenticationServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        accounts: Arc<dyn RefreshAccountSource>,
        sessions: Arc<dyn SessionRepository>,
        revocation: Arc<dyn TokenRevocationService>,
        authz: Arc<dyn AuthzClaimsProvider>,
        hasher: Arc<dyn PasswordHasher>,
        issuer: Arc<dyn AccessTokenIssuer>,
        decoder: Arc<dyn AccessTokenDecoder>,
        refresh_codec: Arc<dyn RefreshTokenCodec>,
        verifier: Arc<TokenVerifier>,
        keyring: Arc<KeyRing>,
        clock: Arc<dyn Clock>,
        config: AuthConfig,
    ) -> Self {
        Self {
            users,
            accounts,
            sessions,
            revocation,
            authz,
            hasher,
            issuer,
            decoder,
            refresh_codec,
            verifier,
            keyring,
            clock,
            lifetimes: SessionLifetimes::from_config(&config),
            config,
            gate: None,
        }
    }

    /// Consult `gate` on every refresh: it may refuse a stale instance and
    /// fetch sessions / accounts that have not reached this one yet.
    pub fn with_gate(mut self, gate: Arc<dyn RefreshGate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Mint the (deterministic) token pair of one generation.
    fn token_pair(
        &self,
        session: &Session,
        generation: &SessionGeneration,
        authz: Option<AuthzClaims>,
    ) -> Result<TokenPair, AuthError> {
        // Never mint with a key the cluster has revoked: every verifier
        // would reject it.
        if let Some(kid) = self.issuer.key_id()
            && self.keyring.is_revoked(kid)
        {
            return Err(AuthError::Config(format!(
                "signing key {kid} has been revoked; rotate AUTH_JWT_SIGNING_KEY"
            )));
        }
        let claims = Claims {
            sub: session.user_id,
            sid: session.id,
            jti: generation.access_jti,
            generation: generation.generation,
            iss: self.config.jwt.issuer.clone(),
            iat: generation.issued_at.timestamp(),
            exp: generation.access_expires_at.timestamp(),
            authz,
        };
        Ok(TokenPair {
            session_id: session.id,
            access_token: self.issuer.mint(&claims)?,
            access_expires_at: generation.access_expires_at,
            refresh_token: self.refresh_codec.issue(
                session.id,
                generation.generation,
                &session.secret,
            )?,
            refresh_expires_at: session.idle_expires_at.min(session.absolute_expires_at),
        })
    }

    /// Evict the oldest active sessions so a new one fits the limit.
    /// A limit of 0 means unlimited.
    async fn enforce_session_limit(&self, user_id: Uuid) -> Result<(), AuthError> {
        let max = self.config.session.max_sessions_per_user as usize;
        if max == 0 {
            return Ok(());
        }
        let active = self.sessions.list_active_for_user(user_id).await?;
        let excess = (active.len() + 1).saturating_sub(max);
        for session in active.iter().take(excess) {
            self.revocation
                .end_session(session.id, RevocationReason::Evicted)
                .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl AuthenticationService for AuthenticationServiceImpl {
    async fn login(
        &self,
        credentials: Credentials,
        ctx: ClientContext,
    ) -> Result<TokenPair, AuthError> {
        // One read: the account plus its active roles (for the token).
        let account = self
            .users
            .find_with_roles_by_email(&normalize_email(&credentials.email))
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        let user = &account.user;
        let hash = user
            .password_hash
            .as_deref()
            .ok_or(AuthError::InvalidCredentials)?;
        if !self.hasher.verify(&credentials.password, hash)? {
            return Err(AuthError::InvalidCredentials);
        }
        if !user.is_active {
            return Err(AuthError::AccountDisabled);
        }

        let authz = self.authz.claims_for(&account).await?;
        self.enforce_session_limit(user.id).await?;

        let issued = ctx.issue_context(None);
        let (session, first) = self
            .sessions
            .create(
                NewSession {
                    user_id: user.id,
                    secret: random_bytes(SESSION_SECRET_LEN)?,
                    created_ip: issued.ip,
                    user_agent: issued.user_agent,
                    fingerprint_hash: issued.fingerprint_hash,
                },
                &self.lifetimes,
            )
            .await?;

        self.token_pair(&session, &first, authz)
    }

    async fn refresh(
        &self,
        access_token: &str,
        refresh_token: &str,
        ctx: ClientContext,
    ) -> Result<TokenPair, AuthError> {
        let now = self.clock.now();
        let claims = self
            .decoder
            .decode(access_token, now, ExpiryCheck::Ignore)?;
        let parsed = self.refresh_codec.parse(refresh_token)?;
        if parsed.session_id != claims.sid {
            return Err(AuthError::InvalidToken("token pair mismatch".into()));
        }
        self.verifier.denylist().check_for_refresh(&claims, now)?;
        if let Some(gate) = &self.gate {
            gate.check_fresh().await?;
        }
        // Re-read the account: deactivation (also directly in storage) stops
        // refreshes, and role / permission changes enter the new token.
        let mut caught_up = false;
        let account = match (self.accounts.load(claims.sub).await, &self.gate) {
            (Err(AuthError::ReplicaBehind), Some(gate)) => {
                caught_up = true;
                gate.catch_up(claims.sid, claims.sub).await?;
                self.accounts.load(claims.sub).await?
            }
            (other, _) => other?,
        }
        .ok_or(AuthError::TokenRevoked)?;
        if !account.is_active {
            return Err(AuthError::AccountDisabled);
        }
        let authz = account.authz;
        let issued = ctx.issue_context(Some(claims.jti));

        // Retries when a concurrent refresh wins the rotation race, and
        // once after fetching a session not synced here yet.
        for _ in 0..=REFRESH_ROTATE_ATTEMPTS {
            let snapshot = match self
                .sessions
                .load_for_refresh(claims.sid, parsed.generation)
                .await?
            {
                Some(snapshot) => snapshot,
                None => match &self.gate {
                    Some(gate) if !caught_up => {
                        caught_up = true;
                        gate.catch_up(claims.sid, claims.sub).await?;
                        continue;
                    }
                    Some(_) => return Err(AuthError::ReplicaBehind),
                    None => return Err(AuthError::TokenRevoked),
                },
            };
            let session = snapshot.session;
            // Nothing about the generation is trusted until the MAC verifies.
            let mac_valid = self.refresh_codec.verify(&parsed, &session.secret);
            // A newer generation than this cluster has: it was rotated at
            // another service and has not arrived yet — fetch it, never
            // treat it as theft.
            if mac_valid
                && snapshot.presented.is_none()
                && parsed.generation > session.current_generation
                && let Some(gate) = &self.gate
            {
                if caught_up {
                    return Err(AuthError::ReplicaBehind);
                }
                caught_up = true;
                gate.catch_up(claims.sid, claims.sub).await?;
                continue;
            }
            let (presented, current) = if mac_valid {
                (snapshot.presented, snapshot.current)
            } else {
                (None, None)
            };

            let decision = evaluate_refresh(&RefreshInput {
                claims: &claims,
                session: &session,
                mac_valid,
                presented: presented.as_ref(),
                current: current.as_ref(),
                ctx: &ctx,
                request: issued.traits(),
                now: snapshot.now,
                config: &self.config.session,
            });

            match decision {
                RefreshDecision::Rotate => {
                    let outcome = self
                        .sessions
                        .rotate(
                            session.id,
                            session.current_generation,
                            &issued,
                            &self.lifetimes,
                        )
                        .await?;
                    match outcome {
                        RotateOutcome::Rotated {
                            session,
                            generation,
                        } => return self.token_pair(&session, &generation, authz.clone()),
                        RotateOutcome::Conflict => continue,
                    }
                }
                RefreshDecision::ReturnCurrent => {
                    let current = current.ok_or_else(|| {
                        AuthError::Internal("grace decision without current generation".into())
                    })?;
                    return self.token_pair(&session, &current, authz.clone());
                }
                RefreshDecision::Compromise(reason) => {
                    self.revocation.end_session(session.id, reason).await?;
                    return Err(AuthError::SessionCompromised);
                }
                RefreshDecision::Reject(err) => return Err(err),
            }
        }

        Err(AuthError::InvalidToken(
            "concurrent refresh conflict; retry".into(),
        ))
    }

    async fn logout(&self, access_token: &str) -> Result<bool, AuthError> {
        let claims = self
            .decoder
            .decode(access_token, self.clock.now(), ExpiryCheck::Ignore)?;
        self.revocation
            .end_session(claims.sid, RevocationReason::Logout)
            .await
    }

    async fn logout_all(&self, user_id: Uuid) -> Result<u64, AuthError> {
        self.revocation
            .end_all_for_user(user_id, RevocationReason::LogoutAll)
            .await
    }

    async fn verify_access_token(&self, access_token: &str) -> Result<Claims, AuthError> {
        self.verifier.verify(access_token)
    }

    async fn purge_sessions(&self, retention: Duration) -> Result<u64, AuthError> {
        self.sessions.purge(retention).await
    }
}
