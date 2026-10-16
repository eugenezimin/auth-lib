//! The text of code messages.

use chrono::{DateTime, Utc};
use z_auth_mfa::CodePurpose;

/// An email: subject, plain-text and HTML bodies.
#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// Whole minutes until `expires_at` (at least 1).
fn minutes(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    (((expires_at - now).num_seconds() + 59) / 60).max(1)
}

fn plural(n: i64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

pub fn email(
    sender_name: &str,
    purpose: CodePurpose,
    code: &str,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> EmailMessage {
    let (subject, intro) = match purpose {
        CodePurpose::Login => (
            format!("Your {sender_name} sign-in code"),
            "Use this code to finish signing in:",
        ),
        CodePurpose::Enrollment => (
            format!("Confirm two-factor authentication for {sender_name}"),
            "Use this code to finish setting up two-factor authentication:",
        ),
        CodePurpose::StepUp => (
            format!("Confirm a security change on {sender_name}"),
            "Use this code to confirm the change to your account's security settings:",
        ),
    };
    let n = minutes(expires_at, now);
    let expiry = format!("The code expires in {n} minute{}.", plural(n));
    let warning = "If you didn't request it, someone may know your password: change it \
                   and don't share this code with anyone.";
    let text = format!("{intro}\n\n    {code}\n\n{expiry}\n\n{warning}\n\n— {sender_name}\n");
    let html = format!(
        "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5\">\
         <p>{intro}</p>\
         <p style=\"font-size:28px;font-weight:bold;letter-spacing:4px;font-family:monospace\">{code}</p>\
         <p>{expiry}</p><p style=\"color:#666\">{warning}</p><p>— {name}</p>\
         </body></html>",
        intro = escape(intro),
        code = escape(code),
        expiry = escape(&expiry),
        warning = escape(warning),
        name = escape(sender_name),
    );
    EmailMessage {
        subject,
        text,
        html,
    }
}

pub fn sms(
    sender_name: &str,
    purpose: CodePurpose,
    code: &str,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> String {
    let what = match purpose {
        CodePurpose::Login => "sign-in code",
        CodePurpose::Enrollment => "code to set up two-factor authentication",
        CodePurpose::StepUp => "code to confirm a security change",
    };
    let n = minutes(expires_at, now);
    format!("{sender_name}: {code} is your {what}. Valid {n} min. Don't share it with anyone.")
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
