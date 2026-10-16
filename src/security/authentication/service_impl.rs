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
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;

use crate::conf::config::AuthConfig;
use crate::conf::constants::{
    AMR_FED, AMR_MFA, AMR_PWD, LINK_CHALLENGE_SECRET_LEN, REFRESH_ROTATE_ATTEMPTS,
    SESSION_SECRET_LEN,
};
use crate::identity::credentials::PasswordHasher;
use crate::identity::external::{ExternalPrincipal, LinkPolicy, ProviderPolicy, Provisioning};
use crate::identity::user::model::{NewUser, UserWithRoles};
use crate::identity::user::repository::UserRepository;
use crate::identity::user::{normalize_email, validate_email};
use crate::security::authentication::account::RefreshAccountSource;
use crate::security::authentication::flow::flow_key;
use crate::security::authentication::gate::RefreshGate;
use crate::security::authentication::linking::{
    ExternalStores, Linker, PendingLink, clean_amr, missing_stores,
};
use crate::security::authentication::model::{
    ClientContext, Credentials, ExternalLoginOutcome, LinkChallenge, LinkConfirmation,
    LoginOutcome, SecondFactorProof, TokenPair,
};
use crate::security::authentication::policy::{RefreshDecision, RefreshInput, evaluate_refresh};
use crate::security::authentication::second_factor::{SecondFactorDecision, SecondFactorGate};
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
    /// Installed by an extension (e.g. z-auth-mfa).
    second_factor: Option<Arc<dyn SecondFactorGate>>,
    /// External sign-in and linking, when the host supplied the stores.
    external: Option<(ExternalStores, Linker)>,
}

/// Flow-state kinds (see [`flow_key`]).
const FLOW_LINK: &str = "link";
const FLOW_MFA: &str = "mfa";

/// How a first sign-in through an unlinked identity resolves.
enum Unlinked {
    Account(UserWithRoles),
    Confirm(LinkChallenge),
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
            second_factor: None,
            external: None,
        }
    }

    /// Enable external sign-in ([`AuthenticationService::login_external`])
    /// and remember how logins waiting for a second factor started.
    pub fn with_external(mut self, stores: ExternalStores) -> Self {
        let linker = Linker::new(&stores);
        self.external = Some((stores, linker));
        self
    }

    fn external(&self) -> Result<&(ExternalStores, Linker), AuthError> {
        self.external.as_ref().ok_or_else(missing_stores)
    }

    /// After the first factor (`amr`) of an external sign-in: ask the
    /// second-factor gate, unless the provider reported `mfa`.  A challenge
    /// remembers `amr` for [`complete_login`](AuthenticationService::complete_login).
    async fn finish_first_factor(
        &self,
        account: &UserWithRoles,
        amr: Vec<String>,
        ctx: &ClientContext,
    ) -> Result<LoginOutcome, AuthError> {
        if !amr.iter().any(|m| m == AMR_MFA)
            && let Some(gate) = &self.second_factor
            && let SecondFactorDecision::Challenge(challenge) =
                gate.on_password_verified(account, ctx).await?
        {
            let (stores, _) = self.external()?;
            // Outlives the challenge a little; the key is unguessable.
            let ttl = (challenge.expires_at - self.clock.now())
                .to_std()
                .unwrap_or_default()
                + Duration::from_secs(60);
            stores
                .flows
                .put(
                    &flow_key(FLOW_MFA, &challenge.challenge_token),
                    &amr.join(","),
                    ttl,
                )
                .await?;
            return Ok(LoginOutcome::SecondFactor(challenge));
        }
        let pair = self.open_session(account, amr, ctx).await?;
        Ok(LoginOutcome::Tokens(pair))
    }

    /// A first sign-in through an identity no user has: link it to the user
    /// with the provider's email, or create one, as `policy` allows.
    async fn resolve_unlinked(
        &self,
        principal: &ExternalPrincipal,
        policy: &ProviderPolicy,
    ) -> Result<Unlinked, AuthError> {
        let (stores, linker) = self.external()?;
        let email = principal
            .email
            .as_deref()
            .map(normalize_email)
            .filter(|e| !e.is_empty());
        let existing = match &email {
            Some(email) => self.users.find_with_roles_by_email(email).await?,
            None => None,
        };

        let Some(account) = existing else {
            if policy.provisioning == Provisioning::Deny {
                return Err(AuthError::ExternalIdentityNotLinked);
            }
            let email = email.ok_or_else(|| {
                AuthError::InvalidEmail("the identity provider shared no email address".into())
            })?;
            validate_email(&email)?;
            let username = match &principal.username {
                Some(u) if !self.users.exists_by_username(u).await? => Some(u.clone()),
                _ => None,
            };
            let user = self
                .users
                .create(NewUser {
                    email,
                    password_hash: None,
                    username,
                    first_name: principal.first_name.clone(),
                    last_name: principal.last_name.clone(),
                    is_verified: policy.trust_email && principal.email_verified,
                })
                .await?;
            linker.link(user.id, principal, policy.max_links).await?;
            return Ok(Unlinked::Account(UserWithRoles {
                user,
                roles: Vec::new(),
            }));
        };

        if policy.link == LinkPolicy::Never {
            return Err(AuthError::ExternalIdentityNotLinked);
        }
        if !account.user.is_active {
            return Err(AuthError::AccountDisabled);
        }
        let vouched = policy.link == LinkPolicy::VerifiedEmail
            && policy.trust_email
            && principal.email_verified
            && account.user.is_verified;
        if vouched {
            linker
                .link(account.user.id, principal, policy.max_links)
                .await?;
            return Ok(Unlinked::Account(account));
        }
        // Only the account's password can confirm the link.
        if account.user.password_hash.is_none() {
            return Err(AuthError::ExternalIdentityNotLinked);
        }
        let token = URL_SAFE_NO_PAD.encode(random_bytes(LINK_CHALLENGE_SECRET_LEN)?);
        let ttl = self.config.external.link_challenge_ttl;
        let pending = PendingLink {
            user_id: account.user.id,
            max_links: policy.max_links,
            principal: principal.clone(),
        };
        stores
            .flows
            .put(&flow_key(FLOW_LINK, &token), &pending.encode(), ttl)
            .await?;
        Ok(Unlinked::Confirm(LinkChallenge {
            challenge_token: token,
            expires_at: self.clock.now() + ttl,
            email: account.user.email,
        }))
    }

    /// Consult `gate` on every refresh: it may refuse a stale instance and
    /// fetch sessions / accounts that have not reached this one yet.
    pub fn with_gate(mut self, gate: Arc<dyn RefreshGate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Consult `gate` on every login once the password matched: it may ask
    /// for a second factor, verified by
    /// [`complete_login`](AuthenticationService::complete_login).
    pub fn with_second_factor(mut self, gate: Arc<dyn SecondFactorGate>) -> Self {
        self.second_factor = Some(gate);
        self
    }

    /// Open a session for an authenticated account and issue its first
    /// pair.  `amr` is stored sorted.
    async fn open_session(
        &self,
        account: &UserWithRoles,
        mut amr: Vec<String>,
        ctx: &ClientContext,
    ) -> Result<TokenPair, AuthError> {
        amr.sort();
        amr.dedup();
        let user_id = account.user.id;
        let authz = self.authz.claims_for(account).await?;
        self.enforce_session_limit(user_id).await?;

        let issued = ctx.issue_context(None);
        let (session, first) = self
            .sessions
            .create(
                NewSession {
                    user_id,
                    secret: random_bytes(SESSION_SECRET_LEN)?,
                    created_ip: issued.ip,
                    user_agent: issued.user_agent,
                    fingerprint_hash: issued.fingerprint_hash,
                    amr,
                },
                &self.lifetimes,
            )
            .await?;

        self.token_pair(&session, &first, authz)
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
            amr: session.amr.clone(),
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
    ) -> Result<LoginOutcome, AuthError> {
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
        // Before any session exists, so a password alone evicts nothing.
        if let Some(gate) = &self.second_factor
            && let SecondFactorDecision::Challenge(challenge) =
                gate.on_password_verified(&account, &ctx).await?
        {
            return Ok(LoginOutcome::SecondFactor(challenge));
        }

        let pair = self
            .open_session(&account, vec![AMR_PWD.to_string()], &ctx)
            .await?;
        Ok(LoginOutcome::Tokens(pair))
    }

    async fn login_external(
        &self,
        mut principal: ExternalPrincipal,
        policy: ProviderPolicy,
        ctx: ClientContext,
    ) -> Result<ExternalLoginOutcome, AuthError> {
        principal.validate()?;
        principal.amr = clean_amr(&principal.amr).collect();
        let (stores, _) = self.external()?;
        let account = match stores
            .identities
            .find_by_subject(&principal.issuer, &principal.subject)
            .await?
        {
            Some(identity) => {
                let account = self
                    .users
                    .find_with_roles_by_id(identity.user_id)
                    .await?
                    .ok_or(AuthError::ExternalIdentityNotLinked)?;
                if !account.user.is_active {
                    return Err(AuthError::AccountDisabled);
                }
                stores.identities.record_login(identity.id).await?;
                account
            }
            None => match self.resolve_unlinked(&principal, &policy).await? {
                Unlinked::Account(account) => account,
                Unlinked::Confirm(challenge) => {
                    return Ok(ExternalLoginOutcome::LinkConfirmation(challenge));
                }
            },
        };
        let mut amr = vec![AMR_FED.to_string()];
        amr.extend(principal.amr);
        Ok(self.finish_first_factor(&account, amr, &ctx).await?.into())
    }

    async fn confirm_link(
        &self,
        confirmation: LinkConfirmation,
        ctx: ClientContext,
    ) -> Result<LoginOutcome, AuthError> {
        let (stores, linker) = self.external()?;
        let pending = stores
            .flows
            .take(&flow_key(FLOW_LINK, &confirmation.challenge_token))
            .await?
            .ok_or(AuthError::ChallengeExpired)?;
        let pending = PendingLink::decode(&pending)?;
        let account = self
            .users
            .find_with_roles_by_id(pending.user_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        let hash = account
            .user
            .password_hash
            .as_deref()
            .ok_or(AuthError::InvalidCredentials)?;
        if !self.hasher.verify(&confirmation.password, hash)? {
            return Err(AuthError::InvalidCredentials);
        }
        if !account.user.is_active {
            return Err(AuthError::AccountDisabled);
        }
        linker
            .link(account.user.id, &pending.principal, pending.max_links)
            .await?;
        let mut amr = vec![AMR_FED.to_string(), AMR_PWD.to_string()];
        amr.extend(pending.principal.amr);
        self.finish_first_factor(&account, amr, &ctx).await
    }

    async fn complete_login(
        &self,
        proof: SecondFactorProof,
        ctx: ClientContext,
    ) -> Result<TokenPair, AuthError> {
        let gate = self
            .second_factor
            .as_ref()
            .ok_or_else(|| AuthError::InvalidToken("no second factor is expected".into()))?;
        let verified = gate.verify(&proof, &ctx).await?;
        // Re-read the account: it may have changed since the password step.
        let account = self
            .users
            .find_with_roles_by_id(verified.user_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        if !account.user.is_active {
            return Err(AuthError::AccountDisabled);
        }
        // How the login started: a password, unless an external sign-in
        // left its methods behind.
        let first = match &self.external {
            Some((stores, _)) => {
                stores
                    .flows
                    .take(&flow_key(FLOW_MFA, &proof.challenge_token))
                    .await?
            }
            None => None,
        };
        let mut amr = verified.amr;
        match first {
            Some(first) => amr.extend(first.split(',').map(String::from)),
            None => amr.push(AMR_PWD.to_string()),
        }
        amr.push(AMR_MFA.to_string());
        self.open_session(&account, amr, &ctx).await
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
