//! Authentication service implementation.
//!
//! Orchestrates repositories, codecs and the revocation service around the
//! pure refresh policy in [`crate::authentication::policy`].  The only I/O on
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

use crate::{
    authentication::{
        model::{
            ClientContext, Credentials, NewSession, RotateOutcome, Session, SessionGeneration,
            SessionLifetimes, TokenPair,
        },
        policy::{RefreshDecision, RefreshInput, evaluate_refresh},
        repository::SessionRepository,
        service::AuthenticationService,
    },
    authorization::service::AuthzClaimsProvider,
    clock::Clock,
    config::AuthConfig,
    constants::{MAX_USER_AGENT_LEN, REFRESH_ROTATE_ATTEMPTS, SESSION_SECRET_LEN},
    credentials::PasswordHasher,
    error::AuthError,
    random::random_bytes,
    token::keyring::KeyRing,
    token::{
        codec::{AccessTokenDecoder, AccessTokenIssuer, RefreshTokenCodec},
        model::{AuthzClaims, Claims, ExpiryCheck, RevocationReason},
        service::TokenRevocationService,
        verifier::TokenVerifier,
    },
    user::{normalize_email, repository::UserRepository},
};

/// Default implementation of [`AuthenticationService`].
pub struct AuthenticationServiceImpl {
    users: Arc<dyn UserRepository>,
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
}

impl AuthenticationServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
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
        }
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

/// Cap a client-supplied user agent at [`MAX_USER_AGENT_LEN`] bytes,
/// cutting on a character boundary.
fn truncate_user_agent(user_agent: Option<String>) -> Option<String> {
    user_agent.map(|mut ua| {
        if ua.len() > MAX_USER_AGENT_LEN {
            let mut end = MAX_USER_AGENT_LEN;
            while !ua.is_char_boundary(end) {
                end -= 1;
            }
            ua.truncate(end);
        }
        ua
    })
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

        let (session, first) = self
            .sessions
            .create(
                NewSession {
                    user_id: user.id,
                    secret: random_bytes(SESSION_SECRET_LEN)?,
                    created_ip: ctx.ip,
                    user_agent: truncate_user_agent(ctx.user_agent),
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
        self.verifier.denylist().check(&claims, now)?;
        // Re-read the account: deactivation (also directly in storage) stops
        // refreshes, and role / permission changes enter the new token.
        let account = self
            .users
            .find_with_roles_by_id(claims.sub)
            .await?
            .ok_or(AuthError::TokenRevoked)?;
        if !account.user.is_active {
            return Err(AuthError::AccountDisabled);
        }
        let authz = self.authz.claims_for(&account).await?;

        // Retries only when a concurrent refresh wins the rotation race.
        for _ in 0..REFRESH_ROTATE_ATTEMPTS {
            let snapshot = self
                .sessions
                .load_for_refresh(claims.sid, parsed.generation)
                .await?
                .ok_or(AuthError::TokenRevoked)?;
            let session = snapshot.session;
            // Nothing about the generation is trusted until the MAC verifies.
            let mac_valid = self.refresh_codec.verify(&parsed, &session.secret);
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
                            ctx.ip,
                            &self.lifetimes,
                        )
                        .await?;
                    match outcome {
                        RotateOutcome::Rotated {
                            session,
                            generation,
                        } => return self.token_pair(&session, &generation, authz),
                        RotateOutcome::Conflict => continue,
                    }
                }
                RefreshDecision::ReturnCurrent => {
                    let current = current.ok_or_else(|| {
                        AuthError::Internal("grace decision without current generation".into())
                    })?;
                    return self.token_pair(&session, &current, authz);
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
