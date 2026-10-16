//! Every provider against a local mock server (no network), the webhook
//! signature, SMTP messages, routing and the configuration.

#![cfg(all(
    feature = "smtp",
    feature = "sendgrid",
    feature = "postmark",
    feature = "mailgun",
    feature = "twilio",
    feature = "webhook"
))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::Value;
use uuid::Uuid;
use wiremock::matchers::{basic_auth, body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use z_auth::AuthError;
use z_auth_mfa::{CodeDelivery, CodePurpose, CodeSender, MfaMethod};
use z_auth_mfa_sender::config::{
    MailgunConfig, PostmarkConfig, SendGridConfig, SmtpConfig, SmtpSecurity, TwilioConfig,
    TwilioSender, WebhookConfig,
};
use z_auth_mfa_sender::constants::{
    MAILGUN_API_EU, WEBHOOK_SIGNATURE_HEADER, WEBHOOK_TIMESTAMP_HEADER,
};
use z_auth_mfa_sender::sms::signature;
use z_auth_mfa_sender::{
    DeliveryConfig, EmailProvider, MethodRouter, Secret, SmsProvider, build, email, mask, message,
};

const CODE: &str = "482915";
const FROM: &str = "no-reply@example.com";
const NAME: &str = "Acme";

fn delivery(method: MfaMethod, to: &str) -> CodeDelivery {
    CodeDelivery {
        user_id: Uuid::new_v4(),
        method,
        destination: to.into(),
        code: CODE.into(),
        purpose: CodePurpose::Login,
        expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn email_cfg(email: EmailProvider) -> DeliveryConfig {
    DeliveryConfig {
        sender_name: NAME.into(),
        email,
        ..DeliveryConfig::default()
    }
}

fn sms_cfg(sms: SmsProvider) -> DeliveryConfig {
    DeliveryConfig {
        sender_name: NAME.into(),
        sms,
        ..DeliveryConfig::default()
    }
}

async fn only_request(server: &MockServer) -> wiremock::Request {
    let mut received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    received.remove(0)
}

fn delivery_failed(err: AuthError, needle: &str) {
    match err {
        AuthError::CodeDeliveryFailed(detail) => assert!(detail.contains(needle), "{detail}"),
        other => panic!("expected CodeDeliveryFailed, got {other:?}"),
    }
}

// ── Email providers ───────────────────────────────────────────────────────────

#[tokio::test]
async fn sendgrid_posts_json_with_a_bearer_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v3/mail/send"))
        .and(header("authorization", "Bearer SG.key"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    let sender = build(&email_cfg(EmailProvider::SendGrid(SendGridConfig {
        api_key: Secret::new("SG.key"),
        from: FROM.into(),
        api_base: server.uri(),
    })))
    .unwrap();
    sender
        .send(delivery(MfaMethod::Email, "bob@example.com"))
        .await
        .unwrap();

    let body: Value = only_request(&server).await.body_json().unwrap();
    assert_eq!(
        body["personalizations"][0]["to"][0]["email"],
        "bob@example.com"
    );
    assert_eq!(body["from"]["email"], FROM);
    assert_eq!(body["from"]["name"], NAME);
    assert_eq!(body["subject"], "Your Acme sign-in code");
    assert_eq!(body["content"][0]["type"], "text/plain");
    assert!(body["content"][0]["value"].as_str().unwrap().contains(CODE));
    assert!(body["content"][1]["value"].as_str().unwrap().contains(CODE));
}

#[tokio::test]
async fn postmark_posts_json_with_the_server_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/email"))
        .and(header("x-postmark-server-token", "pm-token"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let sender = build(&email_cfg(EmailProvider::Postmark(PostmarkConfig {
        server_token: Secret::new("pm-token"),
        message_stream: "outbound".into(),
        from: FROM.into(),
        api_base: server.uri(),
    })))
    .unwrap();
    sender
        .send(delivery(MfaMethod::Email, "bob@example.com"))
        .await
        .unwrap();

    let body: Value = only_request(&server).await.body_json().unwrap();
    assert_eq!(body["To"], "bob@example.com");
    assert_eq!(body["From"], format!("\"{NAME}\" <{FROM}>"));
    assert_eq!(body["MessageStream"], "outbound");
    assert!(body["TextBody"].as_str().unwrap().contains(CODE));
    assert!(body["HtmlBody"].as_str().unwrap().contains(CODE));
}

#[tokio::test]
async fn mailgun_posts_a_form_with_basic_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v3/mg.example.com/messages"))
        .and(basic_auth("api", "mg-key"))
        .and(body_string_contains("to=bob%40example.com"))
        .and(body_string_contains(CODE))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let sender = build(&email_cfg(EmailProvider::Mailgun(MailgunConfig {
        api_key: Secret::new("mg-key"),
        domain: "mg.example.com".into(),
        from: FROM.into(),
        api_base: server.uri(),
    })))
    .unwrap();
    sender
        .send(delivery(MfaMethod::Email, "bob@example.com"))
        .await
        .unwrap();
}

#[tokio::test]
async fn provider_errors_become_code_delivery_failed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).set_body_string("{\"errors\":[\"bad key\"]}"))
        .mount(&server)
        .await;
    let sender = build(&email_cfg(EmailProvider::SendGrid(SendGridConfig {
        api_key: Secret::new("wrong"),
        from: FROM.into(),
        api_base: server.uri(),
    })))
    .unwrap();
    let err = sender
        .send(delivery(MfaMethod::Email, "bob@example.com"))
        .await
        .unwrap_err();
    delivery_failed(err, "sendgrid: 401");

    // Nothing listening at all.
    let sender = build(&email_cfg(EmailProvider::Postmark(PostmarkConfig {
        server_token: Secret::new("t"),
        message_stream: "outbound".into(),
        from: FROM.into(),
        api_base: "http://127.0.0.1:9".into(),
    })))
    .unwrap();
    let err = sender
        .send(delivery(MfaMethod::Email, "bob@example.com"))
        .await
        .unwrap_err();
    delivery_failed(err, "postmark:");
}

#[test]
fn smtp_messages_carry_the_code_in_both_parts() {
    let msg = message::email(
        NAME,
        CodePurpose::Enrollment,
        CODE,
        Utc::now() + Duration::minutes(10),
        Utc::now(),
    );
    let mail = email::build_email(NAME, FROM, "bob@example.com", &msg).unwrap();
    let raw = String::from_utf8(mail.formatted()).unwrap();
    assert!(raw.contains("To: bob@example.com"), "{raw}");
    assert!(raw.contains(&format!("From: {NAME} <{FROM}>")), "{raw}");
    assert!(raw.contains("Subject: Confirm two-factor authentication for Acme"));
    assert!(raw.contains("text/plain") && raw.contains("text/html"));
    assert_eq!(raw.matches(CODE).count(), 2, "code once per part");
    assert!(email::build_email(NAME, FROM, "not an address", &msg).is_err());
}

#[tokio::test]
async fn smtp_transports_build_for_every_security_mode() {
    // Building the TLS configuration needs no network (nor may it panic
    // over the rustls crypto provider).
    for security in [
        SmtpSecurity::StartTls,
        SmtpSecurity::Tls,
        SmtpSecurity::None,
    ] {
        let cfg = email_cfg(EmailProvider::Smtp(SmtpConfig {
            host: "smtp.example.com".into(),
            port: security.default_port(),
            security,
            credentials: Some(("user".into(), Secret::new("pass"))),
            from: FROM.into(),
        }));
        build(&cfg).unwrap();
    }
}

// ── SMS providers ─────────────────────────────────────────────────────────────

fn twilio(server: &MockServer, sender: TwilioSender) -> Arc<dyn CodeSender> {
    build(&sms_cfg(SmsProvider::Twilio(TwilioConfig {
        account_sid: "AC123".into(),
        auth_token: Secret::new("tw-token"),
        sender,
        api_base: server.uri(),
    })))
    .unwrap()
}

#[tokio::test]
async fn twilio_posts_a_form_from_a_number_or_a_messaging_service() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/2010-04-01/Accounts/AC123/Messages.json"))
        .and(basic_auth("AC123", "tw-token"))
        .and(body_string_contains("To=%2B15555550100"))
        .and(body_string_contains(CODE))
        .respond_with(ResponseTemplate::new(201))
        .expect(2)
        .mount(&server)
        .await;

    twilio(&server, TwilioSender::From("+15550001111".into()))
        .send(delivery(MfaMethod::Sms, "+15555550100"))
        .await
        .unwrap();
    twilio(&server, TwilioSender::MessagingService("MG42".into()))
        .send(delivery(MfaMethod::Sms, "+15555550100"))
        .await
        .unwrap();

    let received = server.received_requests().await.unwrap();
    let first = String::from_utf8_lossy(&received[0].body).into_owned();
    let second = String::from_utf8_lossy(&received[1].body).into_owned();
    assert!(first.contains("From=%2B15550001111"), "{first}");
    assert!(second.contains("MessagingServiceSid=MG42"), "{second}");
}

#[tokio::test]
async fn webhook_requests_are_signed_and_authorized() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sms"))
        .and(header("authorization", "Bearer hook-token"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let sender = build(&sms_cfg(SmsProvider::Webhook(WebhookConfig {
        url: format!("{}/sms", server.uri()),
        secret: Some(Secret::new("shared-secret")),
        bearer_token: Some(Secret::new("hook-token")),
    })))
    .unwrap();
    sender
        .send(delivery(MfaMethod::Sms, "+15555550100"))
        .await
        .unwrap();

    let req = only_request(&server).await;
    let ts: i64 = req.headers[WEBHOOK_TIMESTAMP_HEADER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((Utc::now().timestamp() - ts).abs() < 60);
    assert_eq!(
        req.headers[WEBHOOK_SIGNATURE_HEADER].to_str().unwrap(),
        signature("shared-secret", ts, &req.body)
    );
    let body: Value = req.body_json().unwrap();
    assert_eq!(body["to"], "+15555550100");
    assert_eq!(body["code"], CODE);
    assert_eq!(body["purpose"], "login");
    assert_eq!(body["method"], "sms");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("Acme: 482915")
    );
}

#[tokio::test]
async fn webhook_without_secret_or_token_sends_neither_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let sender = build(&sms_cfg(SmsProvider::Webhook(WebhookConfig {
        url: server.uri(),
        secret: None,
        bearer_token: None,
    })))
    .unwrap();
    sender
        .send(delivery(MfaMethod::Sms, "+15555550100"))
        .await
        .unwrap();
    let req = only_request(&server).await;
    assert!(!req.headers.contains_key(WEBHOOK_SIGNATURE_HEADER));
    assert!(!req.headers.contains_key("authorization"));
}

#[test]
fn webhook_signature_matches_a_known_vector() {
    // HMAC-SHA256(key = "key", message = "1700000000.{}"), computed with
    // Python's hmac module.
    assert_eq!(
        signature("key", 1_700_000_000, b"{}"),
        "sha256=9d713ed406bb7076d4123f0dc2c39d2df5c654ed4b0cd56b52c8b4c940bd63ae"
    );
}

// ── Routing ───────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

#[async_trait]
impl CodeSender for Recorder {
    async fn send(&self, d: CodeDelivery) -> Result<(), AuthError> {
        self.0.lock().unwrap().push(d.destination);
        Ok(())
    }
}

#[tokio::test]
async fn codes_are_routed_by_method() {
    let email = Arc::new(Recorder::default());
    let sms = Arc::new(Recorder::default());
    let router = MethodRouter {
        email: email.clone(),
        email_provider: "test",
        sms: sms.clone(),
        sms_provider: "test",
    };
    router
        .send(delivery(MfaMethod::Email, "bob@example.com"))
        .await
        .unwrap();
    router
        .send(delivery(MfaMethod::Sms, "+15555550100"))
        .await
        .unwrap();
    assert!(router.send(delivery(MfaMethod::Totp, "x")).await.is_err());
    assert_eq!(*email.0.lock().unwrap(), ["bob@example.com"]);
    assert_eq!(*sms.0.lock().unwrap(), ["+15555550100"]);
}

#[test]
fn destinations_are_masked_for_logs() {
    assert_eq!(mask("bob@example.com"), "b***@example.com");
    assert_eq!(mask("+15555550100"), "***0100");
}

#[test]
fn messages_name_the_purpose_and_expiry() {
    let now = Utc::now();
    let sms = message::sms(
        "Acme",
        CodePurpose::StepUp,
        CODE,
        now + Duration::seconds(290),
        now,
    );
    assert_eq!(
        sms,
        "Acme: 482915 is your code to confirm a security change. Valid 5 min. Don't share it with anyone."
    );
    let email = message::email(
        "A&B",
        CodePurpose::Login,
        CODE,
        now + Duration::seconds(30),
        now,
    );
    assert!(email.text.contains("expires in 1 minute."));
    assert!(email.html.contains("A&amp;B") && !email.html.contains("A&B"));
}

// ── Configuration ─────────────────────────────────────────────────────────────

fn load(vars: &[(&str, &str)]) -> Result<DeliveryConfig, z_auth::conf::config::ConfigError> {
    let map: HashMap<String, String> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    DeliveryConfig::from_lookup(|k| map.get(k).cloned())
}

fn err(vars: &[(&str, &str)]) -> String {
    load(vars).unwrap_err().to_string()
}

#[test]
fn defaults_log_both_methods() {
    let cfg = load(&[]).unwrap();
    assert_eq!((cfg.email.name(), cfg.sms.name()), ("log", "log"));
    assert_eq!(cfg.sender_name, "z-auth");
    assert_eq!(cfg.timeout.as_secs(), 10);
}

#[test]
fn the_sender_name_falls_back_to_the_issuers() {
    let jwt = [("AUTH_JWT_ISSUER", "jwt-issuer")];
    assert_eq!(load(&jwt).unwrap().sender_name, "jwt-issuer");
    let totp = [jwt[0], ("AUTH_MFA_TOTP_ISSUER", "totp-issuer")];
    assert_eq!(load(&totp).unwrap().sender_name, "totp-issuer");
    let named = [totp[0], totp[1], ("AUTH_MFA_SENDER_NAME", "Acme")];
    assert_eq!(load(&named).unwrap().sender_name, "Acme");
}

#[test]
fn every_provider_names_its_missing_variables() {
    let smtp = ("AUTH_MFA_EMAIL_PROVIDER", "smtp");
    let from = ("AUTH_MFA_EMAIL_FROM", FROM);
    assert!(
        err(&[smtp, from])
            .contains("AUTH_MFA_SMTP_HOST (required by AUTH_MFA_EMAIL_PROVIDER=smtp)")
    );
    assert!(err(&[smtp, ("AUTH_MFA_SMTP_HOST", "h")]).contains("AUTH_MFA_EMAIL_FROM"));
    assert!(
        err(&[("AUTH_MFA_EMAIL_PROVIDER", "sendgrid"), from]).contains("AUTH_MFA_SENDGRID_API_KEY")
    );
    assert!(
        err(&[("AUTH_MFA_EMAIL_PROVIDER", "postmark"), from])
            .contains("AUTH_MFA_POSTMARK_SERVER_TOKEN")
    );
    assert!(
        err(&[
            ("AUTH_MFA_EMAIL_PROVIDER", "mailgun"),
            from,
            ("AUTH_MFA_MAILGUN_API_KEY", "k")
        ])
        .contains("AUTH_MFA_MAILGUN_DOMAIN")
    );
    assert!(
        err(&[
            ("AUTH_MFA_SMS_PROVIDER", "twilio"),
            ("AUTH_MFA_TWILIO_FROM", "+1")
        ])
        .contains("AUTH_MFA_TWILIO_ACCOUNT_SID")
    );
    assert!(err(&[("AUTH_MFA_SMS_PROVIDER", "webhook")]).contains("AUTH_MFA_SMS_WEBHOOK_URL"));
}

#[test]
fn invalid_values_are_rejected() {
    let from = ("AUTH_MFA_EMAIL_FROM", FROM);
    let smtp = [
        ("AUTH_MFA_EMAIL_PROVIDER", "smtp"),
        from,
        ("AUTH_MFA_SMTP_HOST", "h"),
    ];
    assert!(err(&[("AUTH_MFA_EMAIL_PROVIDER", "pigeon")]).contains("AUTH_MFA_EMAIL_PROVIDER"));
    assert!(err(&[("AUTH_MFA_SMS_PROVIDER", "fax")]).contains("AUTH_MFA_SMS_PROVIDER"));
    assert!(
        err(&[
            ("AUTH_MFA_EMAIL_PROVIDER", "sendgrid"),
            ("AUTH_MFA_EMAIL_FROM", "Acme <a@b.c>"),
            ("AUTH_MFA_SENDGRID_API_KEY", "k"),
        ])
        .contains("not an email address")
    );
    assert!(
        err(&[&smtp[..], &[("AUTH_MFA_SMTP_SECURITY", "ssl")]].concat())
            .contains("AUTH_MFA_SMTP_SECURITY")
    );
    assert!(
        err(&[&smtp[..], &[("AUTH_MFA_SMTP_USERNAME", "u")]].concat())
            .contains("AUTH_MFA_SMTP_PASSWORD")
    );
    assert!(
        err(&[&smtp[..], &[("AUTH_MFA_SMTP_PORT", "smtp")]].concat())
            .contains("AUTH_MFA_SMTP_PORT")
    );
    assert!(
        err(&[
            ("AUTH_MFA_SMS_PROVIDER", "webhook"),
            ("AUTH_MFA_SMS_WEBHOOK_URL", "ftp://x")
        ])
        .contains("http(s)")
    );
    assert!(err(&[("AUTH_MFA_DELIVERY_TIMEOUT_SECS", "0")]).contains("greater than 0"));
    let twilio = [
        ("AUTH_MFA_SMS_PROVIDER", "twilio"),
        ("AUTH_MFA_TWILIO_ACCOUNT_SID", "AC1"),
        ("AUTH_MFA_TWILIO_AUTH_TOKEN", "t"),
    ];
    assert!(err(&twilio).contains("AUTH_MFA_TWILIO_FROM or AUTH_MFA_TWILIO_MESSAGING_SERVICE_SID"));
    let both = [
        &twilio[..],
        &[
            ("AUTH_MFA_TWILIO_FROM", "+1"),
            ("AUTH_MFA_TWILIO_MESSAGING_SERVICE_SID", "MG1"),
        ],
    ]
    .concat();
    assert!(err(&both).contains("exactly one"));
}

#[test]
fn providers_load_with_their_settings() {
    let cfg = load(&[
        ("AUTH_MFA_EMAIL_PROVIDER", "SMTP"),
        ("AUTH_MFA_EMAIL_FROM", FROM),
        ("AUTH_MFA_SMTP_HOST", "localhost"),
        ("AUTH_MFA_SMTP_SECURITY", "none"),
        ("AUTH_MFA_SMS_PROVIDER", "twilio"),
        ("AUTH_MFA_TWILIO_ACCOUNT_SID", "AC1"),
        ("AUTH_MFA_TWILIO_AUTH_TOKEN", "t0ken"),
        ("AUTH_MFA_TWILIO_MESSAGING_SERVICE_SID", "MG1"),
        ("AUTH_MFA_SENDER_NAME", "Acme"),
        ("AUTH_MFA_DELIVERY_TIMEOUT_SECS", "3"),
    ])
    .unwrap();
    let EmailProvider::Smtp(smtp) = &cfg.email else {
        panic!("{cfg:?}")
    };
    assert_eq!((smtp.port, smtp.security), (25, SmtpSecurity::None));
    assert!(smtp.credentials.is_none());
    assert!(
        matches!(&cfg.sms, SmsProvider::Twilio(t) if matches!(t.sender, TwilioSender::MessagingService(_)))
    );
    assert_eq!(
        (cfg.sender_name.as_str(), cfg.timeout.as_secs()),
        ("Acme", 3)
    );
    // Secrets never show up in Debug output.
    assert!(!format!("{cfg:?}").contains("t0ken"));
    build(&cfg).unwrap();

    let cfg = load(&[
        ("AUTH_MFA_EMAIL_PROVIDER", "mailgun"),
        ("AUTH_MFA_EMAIL_FROM", FROM),
        ("AUTH_MFA_MAILGUN_API_KEY", "k"),
        ("AUTH_MFA_MAILGUN_DOMAIN", "mg.example.com"),
        ("AUTH_MFA_MAILGUN_REGION", "eu"),
    ])
    .unwrap();
    let EmailProvider::Mailgun(mg) = &cfg.email else {
        panic!()
    };
    assert_eq!(mg.api_base, MAILGUN_API_EU);
    let EmailProvider::Smtp(smtp) = load(&[
        ("AUTH_MFA_EMAIL_PROVIDER", "smtp"),
        ("AUTH_MFA_EMAIL_FROM", FROM),
        ("AUTH_MFA_SMTP_HOST", "smtp.example.com"),
    ])
    .unwrap()
    .email
    else {
        panic!()
    };
    assert_eq!((smtp.port, smtp.security), (587, SmtpSecurity::StartTls));
}
