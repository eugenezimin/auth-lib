//! Shared helpers for the core (database-free) test suite.
//!
//! Import with:
//!   mod support;
//!   use support::*;
#![allow(dead_code)] // each test binary uses a different subset

#[cfg(feature = "cluster")]
pub mod cluster;
pub mod in_memory;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use auth_lib::prelude::*;
use auth_lib::token::keys::{generate_refresh_secret, generate_signing_key};
use chrono::{DateTime, Utc};

pub use in_memory::InMemoryDb;

pub const VALID_PASSWORD: &str = "S3cur3P@ssw0rd!";
pub const ISSUER: &str = "auth-lib-test";
pub const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
pub const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

// ── Clock ─────────────────────────────────────────────────────────────────────

/// A controllable clock shared by every component of a test.
pub struct MockClock(Mutex<DateTime<Utc>>);

impl MockClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Utc::now())))
    }
    pub fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Freshly generated keys + defaults (5 min access, 30 min idle, 8 h absolute,
/// history 10, grace 30 s, IP binding off).
pub fn raw_config() -> RawConfig {
    let keys = generate_signing_key().expect("key generation");
    RawConfig::default()
        .jwt_signing_key(keys.signing_key)
        .jwt_verifying_keys([keys.verifying_key])
        .jwt_issuer(ISSUER)
        .refresh_secret(generate_refresh_secret().expect("secret generation"))
}

pub fn test_config() -> AuthConfig {
    raw_config().build().expect("test config must be valid")
}

// ── Harness ───────────────────────────────────────────────────────────────────

/// One "server": an [`AuthLib`] over a (possibly shared) store and clock.
pub struct Server {
    pub auth: AuthLib,
    pub db: Arc<InMemoryDb>,
    pub clock: Arc<MockClock>,
}

/// Every required repository, backed by one in-memory store.
pub fn repositories(db: &Arc<InMemoryDb>) -> Repositories {
    Repositories {
        users: db.clone(),
        roles: db.clone(),
        user_roles: db.clone(),
        sessions: db.clone(),
        revocations: db.clone(),
        keys: db.clone(),
    }
}

pub fn server_with(db: Arc<InMemoryDb>, clock: Arc<MockClock>, config: AuthConfig) -> Server {
    let auth = AuthLib::builder(config, repositories(&db))
        .permissions(db.clone())
        .clock(clock.clone())
        .build()
        .expect("AuthLib must build with all adapters supplied");
    Server { auth, db, clock }
}

pub fn server(config: AuthConfig) -> Server {
    let clock = MockClock::new();
    server_with(Arc::new(InMemoryDb::new(clock.clone())), clock, config)
}

/// A fully wired [`AuthLib`] backed by a fresh in-memory store.
pub fn make_auth() -> AuthLib {
    server(test_config()).auth
}

pub fn ctx(ip: IpAddr) -> ClientContext {
    ClientContext {
        ip,
        user_agent: Some("test-agent".into()),
    }
}

pub fn register_request(email: &str, username: Option<&str>) -> RegisterUser {
    RegisterUser {
        email: email.into(),
        password: VALID_PASSWORD.into(),
        username: username.map(Into::into),
        first_name: None,
        last_name: None,
    }
}

pub fn credentials(email: &str) -> Credentials {
    Credentials {
        email: email.into(),
        password: VALID_PASSWORD.into(),
    }
}

/// Register `email` and log in from `ip`.
pub async fn register_and_login(auth: &AuthLib, email: &str, ip: IpAddr) -> (User, TokenPair) {
    let user = auth
        .users()
        .register(register_request(email, None))
        .await
        .expect("register");
    let pair = auth
        .authentication()
        .login(credentials(email), ctx(ip))
        .await
        .expect("login");
    (user, pair)
}

pub fn new_role(name: &str) -> NewRole {
    NewRole {
        code: name
            .to_lowercase()
            .replace(|c: char| !c.is_ascii_alphanumeric(), "_"),
        name: name.into(),
        description: Some(format!("Description for {name}")),
    }
}
