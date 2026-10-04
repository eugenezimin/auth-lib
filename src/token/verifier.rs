//! Access-token verification — the hot path.  **No I/O.**
//!
//! Signature + issuer + expiry via an [`AccessTokenDecoder`], then the
//! in-memory [`Denylist`].  Every auth-lib instance keeps that denylist
//! current through cluster pushes (see [`crate::cluster`]).

use std::sync::Arc;

use crate::clock::Clock;
use crate::error::AuthError;
use crate::token::codec::AccessTokenDecoder;
use crate::token::denylist::Denylist;
use crate::token::model::{Claims, ExpiryCheck};

pub struct TokenVerifier {
    decoder: Arc<dyn AccessTokenDecoder>,
    denylist: Arc<Denylist>,
    clock: Arc<dyn Clock>,
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
        }
    }

    /// Verifier for a downstream service using the built-in Ed25519 decoder.
    #[cfg(feature = "crypto")]
    pub fn from_config(
        config: &crate::config::JwtConfig,
        denylist: Arc<Denylist>,
    ) -> Result<Self, AuthError> {
        Ok(Self::new(
            Arc::new(crate::token::jwt::Ed25519Decoder::from_config(config)?),
            denylist,
            Arc::new(crate::clock::SystemClock),
        ))
    }

    /// Verify an access token.  Returns [`AuthError::InvalidToken`] for bad
    /// or expired tokens and [`AuthError::TokenRevoked`] for denylisted ones.
    pub fn verify(&self, token: &str) -> Result<Claims, AuthError> {
        let now = self.clock.now();
        let claims = self.decoder.decode(token, now, ExpiryCheck::Enforce)?;
        self.denylist.check(&claims, now)?;
        Ok(claims)
    }

    pub fn denylist(&self) -> &Arc<Denylist> {
        &self.denylist
    }
}
