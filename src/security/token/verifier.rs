//! Access-token verification — the hot path.  **No I/O.**
//!
//! Signature + issuer + expiry via an [`AccessTokenDecoder`], then the
//! in-memory [`Denylist`].  Extensions (e.g. a cluster) keep that denylist
//! current across instances.

use std::sync::Arc;

use crate::security::token::codec::AccessTokenDecoder;
use crate::security::token::denylist::Denylist;
use crate::security::token::model::{Claims, ExpiryCheck};
use crate::utils::clock::Clock;
use crate::utils::error::AuthError;
use crate::utils::fence::ServingFence;

pub struct TokenVerifier {
    decoder: Arc<dyn AccessTokenDecoder>,
    denylist: Arc<Denylist>,
    clock: Arc<dyn Clock>,
    /// Raised when this instance is fenced — its denylist may be stale, so
    /// it verifies nothing.
    fence: Option<ServingFence>,
}

impl TokenVerifier {
    pub fn new(
        decoder: Arc<dyn AccessTokenDecoder>,
        denylist: Arc<Denylist>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            decoder,
            denylist,
            clock,
            fence: None,
        }
    }

    /// Refuse every token with [`AuthError::NodeFenced`] once `fence` is up.
    pub fn with_fence(mut self, fence: ServingFence) -> Self {
        self.fence = Some(fence);
        self
    }

    /// Verifier for a downstream service using the built-in Ed25519 decoder.
    #[cfg(feature = "crypto")]
    pub fn from_config(
        config: &crate::conf::config::JwtConfig,
        denylist: Arc<Denylist>,
    ) -> Result<Self, AuthError> {
        Ok(Self::new(
            Arc::new(crate::security::token::jwt::Ed25519Decoder::from_config(
                config,
            )?),
            denylist,
            Arc::new(crate::utils::clock::SystemClock),
        ))
    }

    /// Verify an access token.  Returns [`AuthError::InvalidToken`] for bad
    /// or expired tokens and [`AuthError::TokenRevoked`] for denylisted ones.
    pub fn verify(&self, token: &str) -> Result<Claims, AuthError> {
        if let Some(fence) = &self.fence {
            fence.check()?;
        }
        let now = self.clock.now();
        let claims = self.decoder.decode(token, now, ExpiryCheck::Enforce)?;
        self.denylist.check(&claims, now)?;
        Ok(claims)
    }

    pub fn denylist(&self) -> &Arc<Denylist> {
        &self.denylist
    }
}
