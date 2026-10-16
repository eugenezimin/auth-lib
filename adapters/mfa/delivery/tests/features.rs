//! Providers whose Cargo feature is off are refused (run with
//! `--no-default-features --features twilio`).

#![cfg(not(feature = "smtp"))]

use std::collections::HashMap;

use z_auth_mfa_sender::config::{SmtpConfig, SmtpSecurity};
use z_auth_mfa_sender::{DeliveryConfig, EmailProvider, Secret, build};

#[test]
fn a_provider_that_is_not_compiled_in_is_refused() {
    let vars: HashMap<&str, &str> = [
        ("AUTH_MFA_EMAIL_PROVIDER", "smtp"),
        ("AUTH_MFA_EMAIL_FROM", "no-reply@example.com"),
        ("AUTH_MFA_SMTP_HOST", "localhost"),
    ]
    .into();
    let err = DeliveryConfig::from_lookup(|k| vars.get(k).map(|v| v.to_string()))
        .unwrap_err()
        .to_string();
    assert!(err.contains("built without the `smtp` feature"), "{err}");

    // Building such a config by hand fails the same way.
    let cfg = DeliveryConfig {
        email: EmailProvider::Smtp(SmtpConfig {
            host: "localhost".into(),
            port: 25,
            security: SmtpSecurity::None,
            credentials: Some(("u".into(), Secret::new("p"))),
            from: "no-reply@example.com".into(),
        }),
        ..DeliveryConfig::default()
    };
    let err = build(&cfg)
        .err()
        .expect("smtp is not compiled in")
        .to_string();
    assert!(err.contains("built without the `smtp` feature"), "{err}");
}

#[test]
fn log_needs_no_feature() {
    build(&DeliveryConfig::default()).unwrap();
}
