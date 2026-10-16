//! z-auth-mfa helpers: fixed keys, a code sender that records instead of
//! sending, a server with the extension wired in, and TOTP codes for a
//! secret at the mock clock's time.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use z_auth::prelude::*;
use z_auth_mfa::config::RawMfaConfig;
use z_auth_mfa::crypto::{base32, totp};
use z_auth_mfa::model::{TotpAlgorithm, TotpParams};
use z_auth_mfa::{CodeDelivery, CodeSender, Mfa, MfaService};

use crate::{InMemoryDb, MockClock, Server, repositories, test_config};

/// Base64 of 32 bytes of 0x01.
pub const ENCRYPTION_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
/// Base64 of 32 bytes of 0x02.
pub const HASH_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

/// Valid keys, everything else at its default (TOTP only, `optional`).
pub fn mfa_raw_config() -> RawMfaConfig {
    RawMfaConfig::default()
        .encryption_key(ENCRYPTION_KEY)
        .hash_key(HASH_KEY)
}

/// Records every code instead of sending it; can be told to fail.
#[derive(Default)]
pub struct RecordingCodeSender {
    sent: Mutex<Vec<CodeDelivery>>,
    failing: Mutex<bool>,
}

impl RecordingCodeSender {
    pub fn sent(&self) -> Vec<CodeDelivery> {
        self.sent.lock().unwrap().clone()
    }
    /// The last code sent to `destination`.
    pub fn last_code(&self, destination: &str) -> Option<String> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|d| d.destination == destination)
            .map(|d| d.code.clone())
    }
    pub fn fail(&self, failing: bool) {
        *self.failing.lock().unwrap() = failing;
    }
}

#[async_trait]
impl CodeSender for RecordingCodeSender {
    async fn send(&self, delivery: CodeDelivery) -> Result<(), AuthError> {
        if *self.failing.lock().unwrap() {
            return Err(AuthError::CodeDeliveryFailed("provider down".into()));
        }
        self.sent.lock().unwrap().push(delivery);
        Ok(())
    }
}

/// A [`Server`] with z-auth-mfa wired in.
pub struct MfaServer {
    pub server: Server,
    pub mfa: Arc<Mfa>,
    pub sender: Arc<RecordingCodeSender>,
}

impl MfaServer {
    pub fn auth(&self) -> &ZAuth {
        &self.server.auth
    }
    pub fn service(&self) -> Arc<dyn MfaService> {
        self.mfa.service().expect("built")
    }
}

/// A server over a fresh in-memory store with z-auth-mfa configured by
/// `raw` (and z-auth by `config`).
pub fn mfa_server_with(raw: RawMfaConfig, config: AuthConfig) -> MfaServer {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let sender = Arc::new(RecordingCodeSender::default());
    let mfa = Arc::new(
        Mfa::new(raw.build().expect("valid mfa config"), db.clone())
            .with_code_sender(sender.clone()),
    );
    let auth = ZAuth::builder(config, repositories(&db))
        .permissions(db.clone())
        .clock(clock.clone())
        .extension(mfa.clone())
        .build()
        .expect("ZAuth with z-auth-mfa must build");
    MfaServer {
        server: Server { auth, db, clock },
        mfa,
        sender,
    }
}

pub fn mfa_server(raw: RawMfaConfig) -> MfaServer {
    mfa_server_with(raw, test_config())
}

/// The default TOTP parameters (SHA-1, 6 digits, 30 s).
pub fn default_totp() -> TotpParams {
    TotpParams {
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period_secs: 30,
    }
}

/// The code for base32 `secret` at `clock`'s time, `offset_steps` away.
pub fn totp_code(
    secret: &str,
    clock: &MockClock,
    params: &TotpParams,
    offset_steps: i64,
) -> String {
    let key = base32::decode(secret).expect("base32 secret");
    let at = clock.now().timestamp() + offset_steps * params.period_secs as i64;
    totp::totp(&key, at, params)
}
