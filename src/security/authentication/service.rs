//! Authentication service interface — login, refresh, logout.

use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use crate::identity::external::{ExternalPrincipal, ProviderPolicy};
use crate::security::authentication::model::{
    ClientContext, Credentials, ExternalLoginOutcome, LinkConfirmation, LoginOutcome,
    SecondFactorProof, TokenPair,
};
use crate::security::token::model::Claims;
use crate::utils::error::AuthError;

#[async_trait]
pub trait AuthenticationService: Send + Sync {
    /// Verify credentials, open a new session and issue its first pair.
    /// Evicts the user's oldest sessions beyond `max_sessions_per_user`.
    ///
    /// With a [`SecondFactorGate`] installed (e.g. by z-auth-mfa) the
    /// password may only earn a [`LoginOutcome::SecondFactor`] challenge:
    /// no session is opened (and none evicted) until
    /// [`complete_login`](Self::complete_login) succeeds.
    ///
    /// [`SecondFactorGate`]: crate::security::authentication::SecondFactorGate
    async fn login(
        &self,
        credentials: Credentials,
        ctx: ClientContext,
    ) -> Result<LoginOutcome, AuthError>;

    /// Sign in with an identity an external provider asserted, verified by
    /// a protocol adapter (e.g. z-auth-sso).  Needs
    /// [`ZAuthBuilder::external_identities`](crate::ZAuthBuilder::external_identities).
    ///
    /// The identity's linked user signs in.  An identity not linked yet is
    /// linked to the user with the provider's email, or a user is created,
    /// as `policy` allows — linking may first need that user's password
    /// ([`ExternalLoginOutcome::LinkConfirmation`]).  The second-factor
    /// gate applies as after a password, unless the provider reported
    /// `mfa`.  Tokens carry `amr` with `fed`.
    ///
    /// # Errors
    /// [`AuthError::ExternalIdentityNotLinked`] when `policy` neither links
    /// nor creates a user; [`AuthError::AccountDisabled`].
    async fn login_external(
        &self,
        principal: ExternalPrincipal,
        policy: ProviderPolicy,
        ctx: ClientContext,
    ) -> Result<ExternalLoginOutcome, AuthError>;

    /// Answer a [`ExternalLoginOutcome::LinkConfirmation`] with the
    /// existing account's password: link the identity, then continue the
    /// login (tokens carry `amr` with `fed` and `pwd`).  The challenge is
    /// single use — a wrong password ends it.
    async fn confirm_link(
        &self,
        confirmation: LinkConfirmation,
        ctx: ClientContext,
    ) -> Result<LoginOutcome, AuthError>;

    /// Second step of a login that returned [`LoginOutcome::SecondFactor`]:
    /// verify the proof, then open the session as [`login`](Self::login)
    /// would.  Its tokens carry `amr` with `mfa`.
    async fn complete_login(
        &self,
        proof: SecondFactorProof,
        ctx: ClientContext,
    ) -> Result<TokenPair, AuthError>;

    /// Exchange an (expired) access token plus its refresh token for the
    /// session's next pair.  See [`crate::security::authentication::policy`].
    async fn refresh(
        &self,
        access_token: &str,
        refresh_token: &str,
        ctx: ClientContext,
    ) -> Result<TokenPair, AuthError>;

    /// End the session the access token belongs to (expired tokens are
    /// accepted).  Returns `true` if the session was active.
    async fn logout(&self, access_token: &str) -> Result<bool, AuthError>;

    /// End every session of a user.  Returns the number ended.
    async fn logout_all(&self, user_id: Uuid) -> Result<u64, AuthError>;

    /// Verify an access token — signature, expiry and denylist.  **No I/O.**
    async fn verify_access_token(&self, access_token: &str) -> Result<Claims, AuthError>;

    /// Delete sessions that ended or expired more than `retention` ago.
    async fn purge_sessions(&self, retention: Duration) -> Result<u64, AuthError>;
}
