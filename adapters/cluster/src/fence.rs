//! Federation mode: once an instance is fenced it refuses every session
//! operation (its view of the cluster can no longer be trusted).  The flag
//! is set by the cluster; these wrappers check it before delegating.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use z_auth::security::authentication::{
    AuthenticationService, ClientContext, Credentials, LoginOutcome, SecondFactorProof, TokenPair,
};
use z_auth::security::session::RevocationReason;
use z_auth::security::token::TokenRevocationService;
use z_auth::security::token::model::{Claims, RevokeTarget};
use z_auth::utils::error::AuthError;
use z_auth::utils::fence::ServingFence;

fn check(fenced: &ServingFence) -> Result<(), AuthError> {
    fenced.check()
}

pub(crate) struct FencedAuthentication {
    pub inner: Arc<dyn AuthenticationService>,
    pub fenced: ServingFence,
}

#[async_trait]
impl AuthenticationService for FencedAuthentication {
    async fn login(
        &self,
        credentials: Credentials,
        ctx: ClientContext,
    ) -> Result<LoginOutcome, AuthError> {
        check(&self.fenced)?;
        self.inner.login(credentials, ctx).await
    }

    async fn complete_login(
        &self,
        proof: SecondFactorProof,
        ctx: ClientContext,
    ) -> Result<TokenPair, AuthError> {
        check(&self.fenced)?;
        self.inner.complete_login(proof, ctx).await
    }

    async fn refresh(
        &self,
        access_token: &str,
        refresh_token: &str,
        ctx: ClientContext,
    ) -> Result<TokenPair, AuthError> {
        check(&self.fenced)?;
        self.inner.refresh(access_token, refresh_token, ctx).await
    }

    async fn logout(&self, access_token: &str) -> Result<bool, AuthError> {
        check(&self.fenced)?;
        self.inner.logout(access_token).await
    }

    async fn logout_all(&self, user_id: Uuid) -> Result<u64, AuthError> {
        check(&self.fenced)?;
        self.inner.logout_all(user_id).await
    }

    async fn verify_access_token(&self, access_token: &str) -> Result<Claims, AuthError> {
        check(&self.fenced)?;
        self.inner.verify_access_token(access_token).await
    }

    async fn purge_sessions(&self, retention: Duration) -> Result<u64, AuthError> {
        self.inner.purge_sessions(retention).await
    }
}

pub(crate) struct FencedRevocation {
    pub inner: Arc<dyn TokenRevocationService>,
    pub fenced: ServingFence,
}

#[async_trait]
impl TokenRevocationService for FencedRevocation {
    async fn revoke(
        &self,
        target: RevokeTarget,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        check(&self.fenced)?;
        self.inner.revoke(target, reason).await
    }

    async fn revoke_many(
        &self,
        targets: Vec<RevokeTarget>,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        check(&self.fenced)?;
        self.inner.revoke_many(targets, reason).await
    }

    async fn end_session(
        &self,
        session_id: Uuid,
        reason: RevocationReason,
    ) -> Result<bool, AuthError> {
        check(&self.fenced)?;
        self.inner.end_session(session_id, reason).await
    }

    async fn end_all_for_user(
        &self,
        user_id: Uuid,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        check(&self.fenced)?;
        self.inner.end_all_for_user(user_id, reason).await
    }

    async fn purge_expired(&self) -> Result<u64, AuthError> {
        self.inner.purge_expired().await
    }

    async fn load(&self) -> Result<usize, AuthError> {
        self.inner.load().await
    }

    async fn enforce_pending(&self) -> Result<usize, AuthError> {
        check(&self.fenced)?;
        self.inner.enforce_pending().await
    }
}
