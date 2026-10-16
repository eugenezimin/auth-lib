//! z-auth-mfa config loading — `RawMfaConfig`, `MfaEnvLoader`, defaults and
//! validation — and the wire shapes of its API.

mod support;

use std::time::Duration;

use z_auth::conf::config::{ConfigError, RetryMatch};
use z_auth_mfa::api::dto::{
    BeginDeliveredRequest, EnrollmentConfirmedResponse, StepUpRequest, TotpEnrollmentResponse,
};
use z_auth_mfa::api::handlers;
use z_auth_mfa::config::{
    Enforcement, MfaConfigLoader, MfaDirectLoader, MfaEnvLoader, RawMfaConfig, Unenrolled,
};
use z_auth_mfa::constants::*;
use z_auth_mfa::model::{MfaMethod, TotpAlgorithm};

use crate::support::*;

fn parse_error(raw: RawMfaConfig) -> (String, String) {
    match raw.build() {
        Err(ConfigError::Parse { key, reason }) => (key, reason),
        Err(ConfigError::Missing(key)) => (key, "missing".into()),
        Ok(_) => panic!("expected a configuration error"),
    }
}

#[test]
fn defaults() {
    let cfg = MfaDirectLoader::new(mfa_raw_config())
        .load_settings()
        .unwrap();
    assert_eq!(cfg.enforcement, Enforcement::Optional);
    assert_eq!(cfg.unenrolled, Unenrolled::Allow);
    assert_eq!(cfg.methods, [MfaMethod::Totp]);
    assert!(cfg.keys.encryption_key.is_some());
    assert!(cfg.keys.previous_encryption_keys.is_empty());
    assert_eq!(cfg.totp.issuer, None);
    assert_eq!(cfg.totp.algorithm, TotpAlgorithm::Sha1);
    assert_eq!(cfg.totp.digits, 6);
    assert_eq!(cfg.totp.period, Duration::from_secs(30));
    assert_eq!(cfg.totp.skew_steps, 1);
    assert_eq!(cfg.totp.secret_bytes, 20);
    assert_eq!(cfg.enrollment_ttl, Duration::from_secs(600));
    assert_eq!((cfg.recovery.count, cfg.recovery.length), (10, 10));
    assert_eq!(cfg.challenge.ttl, Duration::from_secs(300));
    assert_eq!(cfg.challenge.max_attempts, 5);
    assert_eq!(cfg.challenge.client_match, None);
    assert_eq!(cfg.lockout.threshold, 10);
    assert_eq!(cfg.lockout.window, Duration::from_secs(900));
    assert_eq!(cfg.lockout.duration, Duration::from_secs(900));
    assert_eq!(cfg.codes.digits, 6);
    assert_eq!(cfg.codes.ttl, Duration::from_secs(300));
    assert_eq!(cfg.codes.resend_after, Duration::from_secs(30));
    assert_eq!(cfg.codes.max_sends, 5);
    assert!(cfg.codes.auto_send);
    assert!(cfg.end_sessions_on_removal);
    assert_eq!(cfg.purge_interval, Duration::from_secs(300));
    assert_eq!(cfg.purge_retention, Duration::from_secs(86_400));
    assert!(!format!("{:?}", cfg.keys).contains(HASH_KEY));
}

/// The only test touching `AUTH_MFA_*`: the environment is process-wide.
#[test]
fn the_environment_loader_reads_every_variable() {
    let vars = [
        (ENV_MFA_ENFORCEMENT, "roles"),
        (ENV_MFA_REQUIRED_ROLES, "admin, ops"),
        (ENV_MFA_UNENROLLED, "deny"),
        (ENV_MFA_METHODS, "sms,totp"),
        (ENV_MFA_ENCRYPTION_KEY, ENCRYPTION_KEY),
        (ENV_MFA_PREVIOUS_ENCRYPTION_KEYS, HASH_KEY),
        (ENV_MFA_HASH_KEY, HASH_KEY),
        (ENV_MFA_TOTP_ISSUER, "Acme"),
        (ENV_MFA_TOTP_ALGORITHM, "SHA256"),
        (ENV_MFA_TOTP_DIGITS, "8"),
        (ENV_MFA_TOTP_PERIOD_SECS, "60"),
        (ENV_MFA_TOTP_SKEW_STEPS, "2"),
        (ENV_MFA_TOTP_SECRET_BYTES, "32"),
        (ENV_MFA_ENROLLMENT_TTL_SECS, "120"),
        (ENV_MFA_RECOVERY_CODE_COUNT, "0"),
        (ENV_MFA_RECOVERY_CODE_LENGTH, "16"),
        (ENV_MFA_CHALLENGE_TTL_SECS, "90"),
        (ENV_MFA_CHALLENGE_MAX_ATTEMPTS, "3"),
        (ENV_MFA_CHALLENGE_MATCH, "ip,fingerprint"),
        (ENV_MFA_LOCKOUT_THRESHOLD, "0"),
        (ENV_MFA_LOCKOUT_WINDOW_SECS, "60"),
        (ENV_MFA_LOCKOUT_SECS, "120"),
        (ENV_MFA_CODE_DIGITS, "8"),
        (ENV_MFA_CODE_TTL_SECS, "100"),
        (ENV_MFA_CODE_RESEND_SECS, "10"),
        (ENV_MFA_CODE_MAX_SENDS, "2"),
        (ENV_MFA_AUTO_SEND, "false"),
        (ENV_MFA_END_SESSIONS_ON_REMOVAL, "false"),
        (ENV_MFA_PURGE_INTERVAL_SECS, "30"),
        (ENV_MFA_PURGE_RETENTION_SECS, "3600"),
    ];
    for (k, v) in vars {
        // SAFETY: no other test in this binary reads or writes AUTH_MFA_*.
        unsafe { std::env::set_var(k, v) };
    }
    let loaded = MfaEnvLoader.load_settings();
    for (k, _) in vars {
        unsafe { std::env::remove_var(k) };
    }
    let cfg = loaded.unwrap();

    assert_eq!(
        cfg.enforcement,
        Enforcement::Roles(vec!["admin".into(), "ops".into()])
    );
    assert_eq!(cfg.unenrolled, Unenrolled::Deny);
    assert_eq!(cfg.methods, [MfaMethod::Sms, MfaMethod::Totp]);
    assert_eq!(cfg.keys.previous_encryption_keys, [[2u8; 32]]);
    assert_eq!(cfg.totp.issuer.as_deref(), Some("Acme"));
    assert_eq!(cfg.totp.algorithm, TotpAlgorithm::Sha256);
    assert_eq!(cfg.totp.digits, 8);
    assert_eq!(cfg.totp.period, Duration::from_secs(60));
    assert_eq!(cfg.totp.skew_steps, 2);
    assert_eq!(cfg.totp.secret_bytes, 32);
    assert_eq!(cfg.enrollment_ttl, Duration::from_secs(120));
    assert_eq!((cfg.recovery.count, cfg.recovery.length), (0, 16));
    assert_eq!(cfg.challenge.ttl, Duration::from_secs(90));
    assert_eq!(cfg.challenge.max_attempts, 3);
    assert_eq!(
        cfg.challenge.client_match,
        Some(RetryMatch {
            ip: true,
            user_agent: false,
            fingerprint: true
        })
    );
    assert_eq!(cfg.lockout.threshold, 0);
    assert_eq!(cfg.lockout.window, Duration::from_secs(60));
    assert_eq!(cfg.lockout.duration, Duration::from_secs(120));
    assert_eq!(cfg.codes.digits, 8);
    assert_eq!(cfg.codes.ttl, Duration::from_secs(100));
    assert_eq!(cfg.codes.resend_after, Duration::from_secs(10));
    assert_eq!(cfg.codes.max_sends, 2);
    assert!(!cfg.codes.auto_send);
    assert!(!cfg.end_sessions_on_removal);
    assert_eq!(cfg.purge_interval, Duration::from_secs(30));
    assert_eq!(cfg.purge_retention, Duration::from_secs(3600));
}

const MFA_YAML: &str = r#"
mfa:
  enforcement: roles
  required_roles: [admin, ops]
  unenrolled: deny
  methods: [sms, totp]
  encryption_key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
  previous_encryption_keys: [AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=]
  hash_key: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
  enrollment_ttl_secs: 120
  end_sessions_on_removal: false
  totp:
    issuer: Acme
    algorithm: SHA256
    digits: 8
    period_secs: 60
    skew_steps: 2
    secret_bytes: 32
  recovery:
    code_count: 0
    code_length: 16
  challenge:
    ttl_secs: 90
    max_attempts: 3
    match: [ip, fingerprint]
  lockout:
    threshold: 0
    window_secs: 60
    duration_secs: 120
  code:
    digits: 8
    ttl_secs: 100
    resend_secs: 10
    max_sends: 2
    auto_send: false
  purge:
    interval_secs: 30
    retention_secs: 3600
  delivery:
    email:
      provider: log
"#;

#[test]
fn the_source_loader_reads_the_mfa_section() {
    use z_auth::conf::config::ConfigSource;
    use z_auth_mfa::config::MfaSourceLoader;

    let source = ConfigSource::yaml_str(MFA_YAML).unwrap();
    let cfg = MfaSourceLoader::new(source).load_settings().unwrap();

    assert_eq!(
        cfg.enforcement,
        Enforcement::Roles(vec!["admin".into(), "ops".into()])
    );
    assert_eq!(cfg.unenrolled, Unenrolled::Deny);
    assert_eq!(cfg.methods, [MfaMethod::Sms, MfaMethod::Totp]);
    assert_eq!(cfg.keys.previous_encryption_keys, [[2u8; 32]]);
    assert_eq!(cfg.totp.issuer.as_deref(), Some("Acme"));
    assert_eq!(cfg.totp.algorithm, TotpAlgorithm::Sha256);
    assert_eq!(cfg.totp.digits, 8);
    assert_eq!(cfg.totp.period, Duration::from_secs(60));
    assert_eq!(cfg.totp.skew_steps, 2);
    assert_eq!(cfg.totp.secret_bytes, 32);
    assert_eq!(cfg.enrollment_ttl, Duration::from_secs(120));
    assert_eq!((cfg.recovery.count, cfg.recovery.length), (0, 16));
    assert_eq!(cfg.challenge.ttl, Duration::from_secs(90));
    assert_eq!(cfg.challenge.max_attempts, 3);
    assert_eq!(
        cfg.challenge.client_match,
        Some(RetryMatch {
            ip: true,
            user_agent: false,
            fingerprint: true
        })
    );
    assert_eq!(cfg.lockout.threshold, 0);
    assert_eq!(cfg.lockout.window, Duration::from_secs(60));
    assert_eq!(cfg.lockout.duration, Duration::from_secs(120));
    assert_eq!(cfg.codes.digits, 8);
    assert_eq!(cfg.codes.ttl, Duration::from_secs(100));
    assert_eq!(cfg.codes.resend_after, Duration::from_secs(10));
    assert_eq!(cfg.codes.max_sends, 2);
    assert!(!cfg.codes.auto_send);
    assert!(!cfg.end_sessions_on_removal);
    assert_eq!(cfg.purge_interval, Duration::from_secs(30));
    assert_eq!(cfg.purge_retention, Duration::from_secs(3600));
}

#[test]
fn the_environment_overrides_the_mfa_section() {
    use z_auth::conf::config::ConfigSource;
    use z_auth_mfa::config::MfaSourceLoader;

    let source = ConfigSource::yaml_str(MFA_YAML)
        .unwrap()
        .with_lookup(|key| match key {
            ENV_MFA_TOTP_DIGITS => Some("6".into()),
            // Blank counts as unset, as for the environment loader.
            ENV_MFA_TOTP_ISSUER => Some("  ".into()),
            _ => None,
        });
    let cfg = MfaSourceLoader::new(source).load_settings().unwrap();
    assert_eq!(cfg.totp.digits, 6);
    assert_eq!(cfg.totp.issuer.as_deref(), Some("Acme"));
    assert_eq!(cfg.totp.period, Duration::from_secs(60));
}

#[test]
fn the_mfa_section_rejects_unknown_keys_but_not_delivery() {
    use z_auth::conf::config::ConfigSource;
    use z_auth_mfa::config::MfaSourceLoader;

    let typo = format!("{MFA_YAML}  lockout_secs: 5\n");
    let source = ConfigSource::yaml_str(&typo).unwrap();
    match MfaSourceLoader::new(source).load_settings() {
        Err(ConfigError::Parse { key, .. }) => assert_eq!(key, "mfa.lockout_secs in YAML"),
        other => panic!("expected an unknown-key error, got {other:?}"),
    }

    let bad = MFA_YAML.replace("digits: 8\n    period", "digits: eight\n    period");
    let source = ConfigSource::yaml_str(&bad).unwrap();
    match MfaSourceLoader::new(source).load_settings() {
        Err(ConfigError::Parse { key, .. }) => assert_eq!(key, "mfa.totp.digits in YAML"),
        other => panic!("expected a parse error, got {other:?}"),
    }
}

#[test]
fn keys_are_validated() {
    assert_eq!(
        parse_error(RawMfaConfig::default()),
        (ENV_MFA_HASH_KEY.into(), "missing".into())
    );
    let (key, reason) = parse_error(RawMfaConfig::default().hash_key("c2hvcnQ="));
    assert_eq!(key, ENV_MFA_HASH_KEY);
    assert!(reason.contains("at least 32 bytes"));
    let (key, reason) = parse_error(mfa_raw_config().encryption_key("c2hvcnQ="));
    assert_eq!(key, ENV_MFA_ENCRYPTION_KEY);
    assert!(reason.contains("must be 32 bytes"), "{reason}");
    let (key, _) = parse_error(mfa_raw_config().previous_encryption_keys(["!!"]));
    assert_eq!(key, ENV_MFA_PREVIOUS_ENCRYPTION_KEYS);
    // The encryption key is optional here (a custom sealer may stand in);
    // the extension checks it.
    assert!(RawMfaConfig::default().hash_key(HASH_KEY).build().is_ok());
}

#[test]
fn values_are_range_checked() {
    for (raw, key) in [
        (mfa_raw_config().totp_digits(5), ENV_MFA_TOTP_DIGITS),
        (mfa_raw_config().totp_digits(9), ENV_MFA_TOTP_DIGITS),
        (mfa_raw_config().totp_skew_steps(6), ENV_MFA_TOTP_SKEW_STEPS),
        (
            mfa_raw_config().totp_secret_bytes(10),
            ENV_MFA_TOTP_SECRET_BYTES,
        ),
        (
            mfa_raw_config().totp_period_secs(0),
            ENV_MFA_TOTP_PERIOD_SECS,
        ),
        (
            mfa_raw_config().totp_algorithm("md5"),
            ENV_MFA_TOTP_ALGORITHM,
        ),
        (
            mfa_raw_config().recovery_code_length(6),
            ENV_MFA_RECOVERY_CODE_LENGTH,
        ),
        (
            mfa_raw_config().recovery_code_count(100),
            ENV_MFA_RECOVERY_CODE_COUNT,
        ),
        (
            mfa_raw_config().challenge_max_attempts(0),
            ENV_MFA_CHALLENGE_MAX_ATTEMPTS,
        ),
        (
            mfa_raw_config().challenge_ttl_secs(0),
            ENV_MFA_CHALLENGE_TTL_SECS,
        ),
        (
            mfa_raw_config().challenge_match("ip,mac"),
            ENV_MFA_CHALLENGE_MATCH,
        ),
        (mfa_raw_config().code_digits(4), ENV_MFA_CODE_DIGITS),
        (mfa_raw_config().code_max_sends(0), ENV_MFA_CODE_MAX_SENDS),
        (mfa_raw_config().enforcement("always"), ENV_MFA_ENFORCEMENT),
        (mfa_raw_config().unenrolled("maybe"), ENV_MFA_UNENROLLED),
        (
            mfa_raw_config().methods(["totp", "webauthn"]),
            ENV_MFA_METHODS,
        ),
        (mfa_raw_config().methods(["totp", "totp"]), ENV_MFA_METHODS),
        (
            mfa_raw_config().methods(Vec::<String>::new()),
            ENV_MFA_METHODS,
        ),
        (
            mfa_raw_config()
                .enforcement("roles")
                .required_roles(["Not A Code"]),
            ENV_MFA_REQUIRED_ROLES,
        ),
    ] {
        assert_eq!(parse_error(raw).0, key);
    }
    let (key, _) = parse_error(mfa_raw_config().enforcement("roles"));
    assert!(key.starts_with(ENV_MFA_REQUIRED_ROLES), "{key}");
}

#[test]
fn a_missing_encryption_key_fails_the_build() {
    let clock = MockClock::new();
    let db = std::sync::Arc::new(InMemoryDb::new(clock.clone()));
    let mfa = std::sync::Arc::new(z_auth_mfa::Mfa::new(
        RawMfaConfig::default().hash_key(HASH_KEY).build().unwrap(),
        db.clone(),
    ));
    let result = z_auth::ZAuth::builder(test_config(), repositories(&db))
        .extension(mfa)
        .build();
    assert!(
        matches!(result, Err(z_auth::AuthError::Config(m)) if m.contains(ENV_MFA_ENCRYPTION_KEY))
    );
}

#[tokio::test]
async fn handlers_speak_json_and_redact_secrets() {
    let s = mfa_server(mfa_raw_config().methods(["totp", "email"]));
    let user = register(s.auth(), "api@example.com").await;
    let mfa = s.service();

    let e = handlers::begin_totp(mfa.as_ref(), user.id, Default::default())
        .await
        .unwrap();
    let json = serde_json::to_value(&e).unwrap();
    assert!(
        json["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    assert!(!format!("{e:?}").contains(&e.secret));
    let _: TotpEnrollmentResponse = serde_json::from_value(json).unwrap();

    let code = totp_code(&e.secret, &s.server.clock, &default_totp(), 0);
    let confirmed: EnrollmentConfirmedResponse = handlers::confirm_enrollment(
        mfa.as_ref(),
        user.id,
        e.factor_id,
        serde_json::from_value(serde_json::json!({ "code": code })).unwrap(),
    )
    .await
    .unwrap();
    let codes = confirmed.recovery_codes.clone().unwrap();
    assert!(!format!("{confirmed:?}").contains(&codes[0]));

    let req: BeginDeliveredRequest = serde_json::from_value(serde_json::json!({
        "method": "email"
    }))
    .unwrap();
    let pending = handlers::begin_delivered(mfa.as_ref(), user.id, req)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&pending).unwrap()["method"],
        serde_json::json!("email")
    );

    let status = handlers::status(mfa.as_ref(), user.id).await.unwrap();
    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json["factors"][0]["method"], "totp");
    assert_eq!(
        json["available_methods"],
        serde_json::json!(["totp", "email"])
    );
    assert_eq!(json["recovery_codes_left"], 10);

    // Unknown proof methods are a client error.
    let err = handlers::regenerate_recovery_codes(
        mfa.as_ref(),
        user.id,
        StepUpRequest {
            method: "webauthn".into(),
            code: "x".into(),
        },
    )
    .await
    .unwrap_err();
    assert_eq!((err.status, err.code), (422, "unsupported_second_factor"));

    let err = handlers::remove_factor(
        mfa.as_ref(),
        user.id,
        e.factor_id,
        StepUpRequest {
            method: "recovery_code".into(),
            code: "AAAAA-AAAAA".into(),
        },
    )
    .await
    .unwrap_err();
    assert_eq!((err.status, err.code), (401, "invalid_second_factor"));
}
