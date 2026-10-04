//! Config loading — `DirectLoader`, defaults and validation.

use std::time::Duration;

use auth_lib::config::{ConfigError, ConfigLoader, DirectLoader, RawConfig};
use auth_lib::constants::*;

// 32 bytes of 0x07 / 0x09, base64.
const KEY_A: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
const KEY_B: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";

#[test]
fn config_direct_load_with_overrides() {
    let cfg = DirectLoader::new(
        RawConfig::default()
            .jwt_signing_key(KEY_A)
            .jwt_verifying_keys([KEY_A, KEY_B])
            .jwt_access_ttl_secs(60)
            .jwt_leeway_secs(5)
            .jwt_issuer("auth-lib-test")
            .refresh_secret(KEY_B)
            .session_idle_timeout_secs(600)
            .session_absolute_timeout_secs(3_600)
            .session_history_size(4)
            .refresh_grace_secs(10)
            .ip_binding(true)
            .max_sessions_per_user(3)
            .password_min_length(12),
    )
    .load_config()
    .expect("config should load");

    assert_eq!(cfg.jwt.signing_key, Some([7u8; 32]));
    assert_eq!(cfg.jwt.verifying_keys, vec![[7u8; 32], [9u8; 32]]);
    assert_eq!(cfg.jwt.access_token_ttl, Duration::from_secs(60));
    assert_eq!(cfg.jwt.leeway, Duration::from_secs(5));
    assert_eq!(cfg.session.refresh_secret.as_deref(), Some(&[9u8; 32][..]));
    assert_eq!(cfg.session.idle_timeout, Duration::from_secs(600));
    assert_eq!(cfg.session.absolute_timeout, Duration::from_secs(3_600));
    assert_eq!(cfg.session.history_size, 4);
    assert_eq!(cfg.session.refresh_grace, Duration::from_secs(10));
    assert!(cfg.session.ip_binding);
    assert_eq!(cfg.session.max_sessions_per_user, 3);
    assert_eq!(cfg.password.min_length, 12);
}

#[test]
fn config_defaults_come_from_constants() {
    let cfg = RawConfig::default()
        .build()
        .expect("every field is optional");

    assert_eq!(
        cfg.jwt.access_token_ttl.as_secs(),
        DEFAULT_ACCESS_TOKEN_TTL_SECS
    );
    assert_eq!(cfg.jwt.leeway.as_secs(), DEFAULT_JWT_LEEWAY_SECS);
    assert_eq!(cfg.jwt.issuer, DEFAULT_JWT_ISSUER);
    assert!(cfg.jwt.signing_key.is_none());
    assert_eq!(
        cfg.session.idle_timeout.as_secs(),
        DEFAULT_SESSION_IDLE_TIMEOUT_SECS
    );
    assert_eq!(
        cfg.session.absolute_timeout.as_secs(),
        DEFAULT_SESSION_ABSOLUTE_TIMEOUT_SECS
    );
    assert_eq!(cfg.session.history_size, DEFAULT_SESSION_HISTORY_SIZE);
    assert_eq!(
        cfg.session.refresh_grace.as_secs(),
        DEFAULT_REFRESH_GRACE_SECS
    );
    assert_eq!(cfg.session.ip_binding, DEFAULT_IP_BINDING);
    assert_eq!(cfg.password.min_length, DEFAULT_PASSWORD_MIN_LENGTH);
}

#[test]
fn config_rejects_malformed_keys_and_short_secrets() {
    let bad_key = RawConfig::default().jwt_signing_key("not base64!").build();
    assert!(
        matches!(bad_key, Err(ConfigError::Parse { ref key, .. }) if key == FIELD_JWT_SIGNING_KEY)
    );

    let short_key = RawConfig::default().jwt_verifying_keys(["AAAA"]).build();
    assert!(
        matches!(short_key, Err(ConfigError::Parse { ref key, .. }) if key == FIELD_JWT_VERIFYING_KEYS)
    );

    let short_secret = RawConfig::default().refresh_secret("AAAA").build();
    assert!(
        matches!(short_secret, Err(ConfigError::Parse { ref key, .. }) if key == FIELD_REFRESH_SECRET)
    );

    let tiny_history = RawConfig::default().session_history_size(1).build();
    assert!(tiny_history.is_err());
}

#[test]
fn config_debug_redacts_secrets() {
    let raw = RawConfig::default()
        .jwt_signing_key(KEY_A)
        .refresh_secret(KEY_B);
    assert!(!format!("{raw:?}").contains(KEY_A));
    assert!(!format!("{raw:?}").contains(KEY_B));

    let cfg = raw.build().unwrap();
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("[7, 7"), "signing key leaked: {dbg}");
    assert!(!dbg.contains("[9, 9"), "refresh secret leaked: {dbg}");
}
