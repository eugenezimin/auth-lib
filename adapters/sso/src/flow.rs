//! A redirect waiting for its callback, as kept in z-auth's flow-state
//! store under the hash of its `state`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;
use z_auth::AuthError;

/// What the redirect is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Intent {
    /// Sign in (or up).
    Login,
    /// Link the identity to the user of this session.
    Link { session_id: Uuid },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingRedirect {
    pub intent: Intent,
    pub provider: String,
    pub nonce: String,
    pub pkce_verifier: String,
    /// SHA-256 of the secret the browser that started the redirect holds.
    pub binding_hash: String,
}

impl PendingRedirect {
    /// Each field base64url-encoded, joined with `.`.
    pub fn encode(&self) -> String {
        let (intent, session) = match self.intent {
            Intent::Login => ("login", String::new()),
            Intent::Link { session_id } => ("link", session_id.to_string()),
        };
        [
            intent,
            &session,
            &self.provider,
            &self.nonce,
            &self.pkce_verifier,
            &self.binding_hash,
        ]
        .iter()
        .map(|f| URL_SAFE_NO_PAD.encode(f))
        .collect::<Vec<_>>()
        .join(".")
    }

    pub fn decode(value: &str) -> Result<Self, AuthError> {
        let bad = || AuthError::Internal("malformed pending redirect".into());
        let fields = value
            .split('.')
            .map(|f| {
                URL_SAFE_NO_PAD
                    .decode(f)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or_else(bad)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let [
            intent,
            session,
            provider,
            nonce,
            pkce_verifier,
            binding_hash,
        ] = <[String; 6]>::try_from(fields).map_err(|_| bad())?;
        let intent = match intent.as_str() {
            "login" => Intent::Login,
            "link" => Intent::Link {
                session_id: session.parse().map_err(|_| bad())?,
            },
            _ => return Err(bad()),
        };
        Ok(Self {
            intent,
            provider,
            nonce,
            pkce_verifier,
            binding_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_round_trip() {
        for intent in [
            Intent::Login,
            Intent::Link {
                session_id: Uuid::new_v4(),
            },
        ] {
            let pending = PendingRedirect {
                intent,
                provider: "google".into(),
                nonce: "n.1".into(),
                pkce_verifier: "v".into(),
                binding_hash: "h".into(),
            };
            assert_eq!(PendingRedirect::decode(&pending.encode()).unwrap(), pending);
        }
        assert!(PendingRedirect::decode("x").is_err());
    }
}
