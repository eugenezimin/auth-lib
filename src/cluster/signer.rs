//! Envelope authentication: HMAC-SHA256 with the shared cluster secret over
//! the JSON of `{message_id, from, sent_at, payload}`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::cluster::model::{ClusterEnvelope, ClusterMessage};
use crate::error::AuthError;

type HmacSha256 = Hmac<Sha256>;

#[derive(serde::Serialize)]
struct Unsigned<'a> {
    message_id: &'a Uuid,
    from: &'a Uuid,
    sent_at: &'a DateTime<Utc>,
    payload: &'a ClusterMessage,
}

pub(crate) struct EnvelopeSigner {
    secret: Vec<u8>,
}

impl EnvelopeSigner {
    pub(crate) fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    fn mac(
        &self,
        message_id: &Uuid,
        from: &Uuid,
        sent_at: &DateTime<Utc>,
        payload: &ClusterMessage,
    ) -> Result<HmacSha256, AuthError> {
        let bytes = serde_json::to_vec(&Unsigned {
            message_id,
            from,
            sent_at,
            payload,
        })
        .map_err(|e| AuthError::Internal(format!("cluster message encoding: {e}")))?;
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(&bytes);
        Ok(mac)
    }

    pub(crate) fn seal(
        &self,
        message_id: Uuid,
        from: Uuid,
        sent_at: DateTime<Utc>,
        payload: ClusterMessage,
    ) -> Result<ClusterEnvelope, AuthError> {
        let mac = self.mac(&message_id, &from, &sent_at, &payload)?;
        Ok(ClusterEnvelope {
            message_id,
            from,
            sent_at,
            payload,
            mac: B64URL.encode(mac.finalize().into_bytes()),
        })
    }

    /// Constant-time check of `envelope.mac`.
    pub(crate) fn verify(&self, envelope: &ClusterEnvelope) -> bool {
        let Ok(tag) = B64URL.decode(&envelope.mac) else {
            return false;
        };
        self.mac(
            &envelope.message_id,
            &envelope.from,
            &envelope.sent_at,
            &envelope.payload,
        )
        .is_ok_and(|mac| mac.verify_slice(&tag).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tampering_breaks_the_mac() {
        let signer = EnvelopeSigner::new(vec![1; 32]);
        let mut env = signer
            .seal(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Utc::now(),
                ClusterMessage::SnapshotRequest,
            )
            .unwrap();
        assert!(signer.verify(&env));
        assert!(
            !EnvelopeSigner::new(vec![2; 32]).verify(&env),
            "wrong secret"
        );
        env.from = Uuid::new_v4();
        assert!(!signer.verify(&env), "forged sender");
    }
}
