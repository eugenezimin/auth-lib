//! `DeliveryConfig::from_source` — the `mfa.delivery` section of a YAML
//! file, environment overrides and error origins.

#![cfg(all(feature = "smtp", feature = "twilio"))]

use std::time::Duration;

use z_auth::conf::config::{ConfigError, ConfigSource};
use z_auth_mfa_sender::config::{SmtpSecurity, TwilioSender};
use z_auth_mfa_sender::{DeliveryConfig, EmailProvider, SmsProvider};

const YAML: &str = r#"
auth:
  jwt:
    issuer: Core Issuer
mfa:
  totp:
    issuer: Acme
  delivery:
    timeout_secs: 4
    email:
      provider: smtp
      from: no-reply@example.com
      smtp:
        host: smtp.example.com
        security: tls
        username: mailer
        password: hunter2
    sms:
      provider: twilio
      twilio:
        account_sid: AC123
        auth_token: token
        messaging_service_sid: MG456
"#;

fn source(yaml: &str) -> ConfigSource {
    ConfigSource::yaml_str(yaml).unwrap()
}

#[test]
fn the_delivery_section_configures_both_providers() {
    let cfg = DeliveryConfig::from_source(&source(YAML)).unwrap();

    // No sender_name: the first fallback, mfa.totp.issuer, applies.
    assert_eq!(cfg.sender_name, "Acme");
    assert_eq!(cfg.timeout, Duration::from_secs(4));
    let EmailProvider::Smtp(smtp) = cfg.email else {
        panic!("expected smtp, got {:?}", cfg.email);
    };
    assert_eq!(smtp.host, "smtp.example.com");
    assert_eq!(smtp.security, SmtpSecurity::Tls);
    assert_eq!(smtp.port, 465, "default port for tls");
    assert_eq!(smtp.from, "no-reply@example.com");
    let (user, pass) = smtp.credentials.unwrap();
    assert_eq!((user.as_str(), pass.expose()), ("mailer", "hunter2"));
    let SmsProvider::Twilio(twilio) = cfg.sms else {
        panic!("expected twilio, got {:?}", cfg.sms);
    };
    assert_eq!(twilio.account_sid, "AC123");
    assert!(matches!(twilio.sender, TwilioSender::MessagingService(ref s) if s == "MG456"));
}

#[test]
fn the_environment_overrides_the_section() {
    let src = source(YAML).with_lookup(|key| match key {
        "AUTH_MFA_SENDER_NAME" => Some("Env Name".into()),
        "AUTH_MFA_SMTP_PORT" => Some("2465".into()),
        "AUTH_MFA_SMS_PROVIDER" => Some("log".into()),
        // Blank counts as unset, so the file's value stays.
        "AUTH_MFA_SMTP_HOST" => Some(" ".into()),
        _ => None,
    });
    let cfg = DeliveryConfig::from_source(&src).unwrap();
    assert_eq!(cfg.sender_name, "Env Name");
    let EmailProvider::Smtp(smtp) = cfg.email else {
        panic!("expected smtp");
    };
    assert_eq!(smtp.port, 2465);
    assert_eq!(smtp.host, "smtp.example.com");
    assert!(matches!(cfg.sms, SmsProvider::Log));
}

#[test]
fn the_core_issuer_is_the_last_sender_name_fallback() {
    let cfg = DeliveryConfig::from_source(&source("auth:\n  jwt:\n    issuer: Core\n")).unwrap();
    assert_eq!(cfg.sender_name, "Core");
    assert!(matches!(cfg.email, EmailProvider::Log));
    assert!(matches!(cfg.sms, SmsProvider::Log));
}

#[test]
fn errors_name_the_path_in_the_file() {
    let bad_port = YAML.replace("security: tls", "security: tls\n        port: many");
    match DeliveryConfig::from_source(&source(&bad_port)) {
        Err(ConfigError::Parse { key, .. }) => {
            assert_eq!(key, "mfa.delivery.email.smtp.port in YAML")
        }
        other => panic!("expected a parse error, got {other:?}"),
    }

    let no_host = YAML.replace("host: smtp.example.com", "");
    match DeliveryConfig::from_source(&source(&no_host)) {
        Err(ConfigError::Missing(what)) => assert_eq!(
            what,
            "AUTH_MFA_SMTP_HOST or mfa.delivery.email.smtp.host \
             (required by AUTH_MFA_EMAIL_PROVIDER=smtp)"
        ),
        other => panic!("expected a missing setting, got {other:?}"),
    }

    let typo = YAML.replace("auth_token: token", "auth_tokn: token");
    match DeliveryConfig::from_source(&source(&typo)) {
        Err(ConfigError::Parse { key, .. }) => {
            assert_eq!(key, "mfa.delivery.sms.twilio.auth_tokn in YAML")
        }
        other => panic!("expected an unknown-key error, got {other:?}"),
    }

    let bad_provider = YAML.replace("provider: twilio", "provider: pigeon");
    match DeliveryConfig::from_source(&source(&bad_provider)) {
        Err(ConfigError::Parse { key, .. }) => assert_eq!(key, "mfa.delivery.sms.provider in YAML"),
        other => panic!("expected a parse error, got {other:?}"),
    }
}

#[test]
fn the_example_file_loads_with_the_defaults() {
    let example = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../z-auth.example.yaml");
    let from_file =
        DeliveryConfig::from_source(&ConfigSource::yaml_file(example).unwrap()).unwrap();
    assert_eq!(
        format!("{from_file:?}"),
        format!("{:?}", DeliveryConfig::default())
    );
}
