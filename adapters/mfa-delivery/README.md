# z-auth-mfa-delivery — email and SMS codes for z-auth-mfa

z-auth-mfa generates, stores and checks email and SMS codes, and hands each one to the host's `CodeSender` to deliver. This crate is that `CodeSender`, for the common providers:

| Method | Providers |
|---|---|
| Email | `smtp` (any SMTP server), `sendgrid`, `postmark`, `mailgun` |
| SMS | `twilio`, `webhook` (a JSON `POST` to your own gateway, signed) |
| Either | `log`: the code is only written to the log — development only |

Each provider is a Cargo feature of the same name, all on by default. Selecting a provider that isn't compiled in is a configuration error.

## Wiring

```rust
use std::sync::Arc;
use z_auth_mfa::{Mfa, config::{MfaConfigLoader, MfaEnvLoader}};
use z_auth_mfa_delivery::DeliveryConfig;

let delivery = DeliveryConfig::from_env()?;            // AUTH_MFA_EMAIL_PROVIDER, AUTH_MFA_SMS_PROVIDER, …
let mfa = Arc::new(
    Mfa::new(MfaEnvLoader.load_settings()?, repo)
        .with_code_sender(z_auth_mfa_delivery::build(&delivery)?),
);
```

`build` returns one `CodeSender` that sends email codes through the email provider and SMS codes through the SMS provider. `email_sender` and `sms_sender` build either alone. `DeliveryConfig` can also be built in code: every type is public, and `DeliveryConfig::from_lookup` reads variables from any source.

`AUTH_MFA_METHODS` (z-auth-mfa) decides which methods users can enroll. The settings below decide how those codes leave the service.

Codes are sent while the user's request waits, so every provider runs with a timeout. A failed send is `AuthError::CodeDeliveryFailed`: 503 `code_delivery_failed` over z-auth's HTTP mapping, with a generic message. The detail (provider, HTTP status, the start of its answer) is in the error for the host to log. Real providers never log codes. At debug level they log `second-factor code sent` with the provider and a masked destination (`b***@example.com`, `***0100`).

## Configuration

`DeliveryConfig::from_env` reads these. Like z-auth's other loaders, it does not read `.env` files itself. Problems are `ConfigError`s naming the variable, e.g. `missing required configuration field: AUTH_MFA_SMTP_HOST (required by AUTH_MFA_EMAIL_PROVIDER=smtp)`.

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_MFA_EMAIL_PROVIDER` | `log` | `log` \| `smtp` \| `sendgrid` \| `postmark` \| `mailgun` |
| `AUTH_MFA_SMS_PROVIDER` | `log` | `log` \| `twilio` \| `webhook` |
| `AUTH_MFA_SENDER_NAME` | `AUTH_MFA_TOTP_ISSUER`, then `AUTH_JWT_ISSUER`, then `z-auth` | In email subjects, SMS texts and the From display name |
| `AUTH_MFA_EMAIL_FROM` | — | From address, required by every email provider except `log`. The provider must allow it (a verified sender or domain) |
| `AUTH_MFA_DELIVERY_TIMEOUT_SECS` | `10` | Per send |

### Email

| Provider | Variables |
|---|---|
| `smtp` | `AUTH_MFA_SMTP_HOST` (required).<br>`AUTH_MFA_SMTP_SECURITY`: `starttls` (default; STARTTLS required, never downgraded), `tls` (implicit TLS) or `none` (no encryption, local development only).<br>`AUTH_MFA_SMTP_PORT`: 587 / 465 / 25 by security.<br>`AUTH_MFA_SMTP_USERNAME` + `AUTH_MFA_SMTP_PASSWORD`: both or neither |
| `sendgrid` | `AUTH_MFA_SENDGRID_API_KEY`, a key with the Mail Send permission |
| `postmark` | `AUTH_MFA_POSTMARK_SERVER_TOKEN`.<br>`AUTH_MFA_POSTMARK_MESSAGE_STREAM` (default `outbound`) |
| `mailgun` | `AUTH_MFA_MAILGUN_API_KEY`, `AUTH_MFA_MAILGUN_DOMAIN`.<br>`AUTH_MFA_MAILGUN_REGION`: `us` (default) or `eu` |

Emails are multipart, plain text and HTML. The subject depends on the purpose: `Your <name> sign-in code`, `Confirm two-factor authentication for <name>`, or `Confirm a security change on <name>`. The body states how long the code is valid.

For local development, [Mailpit](https://mailpit.axllent.org) catches every email in a web inbox at http://localhost:8025. Start it with `docker run -p 8025:8025 -p 1025:1025 axllent/mailpit`, then set:

```sh
AUTH_MFA_EMAIL_PROVIDER=smtp
AUTH_MFA_SMTP_HOST=localhost
AUTH_MFA_SMTP_PORT=1025
AUTH_MFA_SMTP_SECURITY=none
AUTH_MFA_EMAIL_FROM=no-reply@example.com
```

### SMS

| Provider | Variables |
|---|---|
| `twilio` | `AUTH_MFA_TWILIO_ACCOUNT_SID`, `AUTH_MFA_TWILIO_AUTH_TOKEN`.<br>Exactly one of `AUTH_MFA_TWILIO_FROM` (a Twilio number in E.164, or an alphanumeric sender ID) or `AUTH_MFA_TWILIO_MESSAGING_SERVICE_SID` |
| `webhook` | `AUTH_MFA_SMS_WEBHOOK_URL` (http or https).<br>Optional `AUTH_MFA_SMS_WEBHOOK_SECRET` and `AUTH_MFA_SMS_WEBHOOK_BEARER_TOKEN` |

The SMS text is `<name>: 482915 is your sign-in code. Valid 5 min. Don't share it with anyone.`, adapted to the purpose.

#### The webhook

Each code is one `POST` with `Content-Type: application/json`:

```json
{
  "to": "+15555550100",
  "message": "Acme: 482915 is your sign-in code. Valid 5 min. Don't share it with anyone.",
  "code": "482915",
  "purpose": "login",
  "method": "sms",
  "expires_at": "2026-10-16T12:05:00+00:00",
  "user_id": "1f0c…"
}
```

- `purpose` is `login`, `enrollment` or `step_up`.
- Send `message` as it is, or build your own text from `code`.
- Any 2xx answer counts as delivered.

With `AUTH_MFA_SMS_WEBHOOK_SECRET` set, each request carries two headers:

- `X-ZAuth-Timestamp`: Unix seconds.
- `X-ZAuth-Signature`: `sha256=<hex HMAC-SHA256(secret, "{timestamp}.{raw body}")>`.

Verify the signature over the raw bytes, and reject old timestamps:

```python
expected = "sha256=" + hmac.new(secret, ts.encode() + b"." + raw_body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(expected, signature_header) and abs(time.time() - int(ts)) < 300
```

`AUTH_MFA_SMS_WEBHOOK_BEARER_TOKEN` adds `Authorization: Bearer <token>`, for gateways that check a token instead of (or as well as) the signature.

## Notes

- **Resend cooldown.** `AUTH_MFA_CODE_RESEND_SECS` (z-auth-mfa) applies per sign-in attempt, not per method. When a code was sent automatically by email, asking for an SMS code for the same sign-in has to wait for the cooldown.
- **TLS.** SMTP and HTTPS both use rustls with the aws-lc-rs provider and the platform's certificate store.
- **Timeouts.** A slow provider holds the request open for up to `AUTH_MFA_DELIVERY_TIMEOUT_SECS`. Keep it short; the user can ask for another code.

## Tests

```sh
cargo test -p z-auth-mfa-delivery                                          # every provider against a local mock server
cargo test -p z-auth-mfa-delivery --no-default-features --features twilio  # providers that aren't compiled in are refused
```
