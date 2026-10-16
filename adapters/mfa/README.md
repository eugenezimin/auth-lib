# z-auth-mfa — two-factor authentication for z-auth

`z-auth` verifies passwords. This crate adds a second factor: the service application imports it and plugs it into `ZAuth` through z-auth's `Extension` port. Everything is configured through `AUTH_MFA_*` variables (or a `RawMfaConfig`), separate from z-auth's own settings.

Supported factors:

- **TOTP**: authenticator apps (RFC 6238; SHA-1, SHA-256 or SHA-512; 6–8 digits).
- **Email and SMS codes**: z-auth-mfa generates and checks them, and the host's `CodeSender` delivers them.
- **Recovery codes**: issued with a user's first factor, each usable once.

## Wiring

```rust
use std::sync::Arc;
use z_auth::{ZAuth, conf::config::{ConfigLoader, EnvLoader}};
use z_auth_mfa::{Mfa, config::{MfaConfigLoader, MfaEnvLoader}};

let mfa = Arc::new(
    Mfa::new(
        MfaEnvLoader.load_settings()?,                        // AUTH_MFA_*
        Arc::new(z_auth_postgres::PgMfaRepository::new(pool.clone())), // feature `mfa`
    )
    .with_code_sender(Arc::new(my_mailer)),                   // with email / sms only
);
let auth = ZAuth::builder(EnvLoader.load_config()?, repos)
    .extension(mfa.clone())
    .build()?;                // checks the setup, installs the second-factor gate
let mfa_service = mfa.service().unwrap();   // enrollment and factor management
// every few minutes, auth.tick() purges expired challenges and enrollments
```

`build()` fails with `AuthError::Config` in two cases: when `AUTH_MFA_METHODS` lists `email` or `sms` but no `CodeSender` was given, and when there is neither `AUTH_MFA_ENCRYPTION_KEY` nor a custom `SecretSealer`.

## Logging in

`login()` returns either tokens or a challenge.

```rust
match auth.authentication().login(credentials, ctx.clone()).await? {
    LoginOutcome::Tokens(pair) => { /* no second factor needed */ }
    LoginOutcome::SecondFactor(challenge) => {
        // challenge.methods: e.g. ["totp", "recovery_code"]
        // challenge.delivery: set when an email / SMS code was already sent
        let pair = auth.authentication().complete_login(SecondFactorProof {
            challenge_token: challenge.challenge_token,
            method: Some("totp".into()),        // or None: whatever the code is
            code: "123456".into(),
        }, ctx).await?;
    }
}
```

Over HTTP, z-auth's `handlers::login` answers `{"status": "second_factor_required", "challenge_token": …}`. Its `handlers::complete_login` serves `POST /login/second-factor`, and `z_auth_mfa::api::handlers::send_login_code` sends or re-sends an email / SMS code for a pending login.

The password step opens no session and evicts none. The second step opens the session, and its tokens carry `amr`: `["mfa", "otp", "pwd"]` for TOTP, email and recovery codes, and `["mfa", "pwd", "sms"]` for SMS. Refreshes keep it. Guard sensitive routes with `auth.authorizer().require_mfa(&claims)`.

### Guarantees

- A challenge accepts `AUTH_MFA_CHALLENGE_MAX_ATTEMPTS` codes. Each attempt is counted before the code is checked, so parallel guesses can't exceed it. A challenge is single use and expires after `AUTH_MFA_CHALLENGE_TTL_SECS`. With `AUTH_MFA_CHALLENGE_MATCH`, the second step must come from the same client.
- Failures across challenges count per user. `AUTH_MFA_LOCKOUT_THRESHOLD` of them within `AUTH_MFA_LOCKOUT_WINDOW_SECS` lock the user out of second-factor checks for `AUTH_MFA_LOCKOUT_SECS`. Only someone who knows the password can cause a lockout.
- Each TOTP time step is accepted once: a compare-and-swap on the factor's last step. Every candidate in the skew window is compared in constant time.
- Unknown, expired, used and forged challenge tokens all fail with the same `challenge_expired`.

## Enrollment and management (`MfaService`)

| Operation | Notes |
|---|---|
| `begin_totp_enrollment(user, label)` | Returns the base32 secret and an `otpauth://` URI to show as a QR code. The factor stays pending until confirmed, for up to `AUTH_MFA_ENROLLMENT_TTL_SECS` |
| `begin_delivered_enrollment(user, method, destination, label)` | Email defaults to the account's address; SMS needs an E.164 number. Sends a code |
| `resend_enrollment_code(user, factor)` | Bounded by `AUTH_MFA_CODE_RESEND_SECS` and `AUTH_MFA_CODE_MAX_SENDS` |
| `confirm_enrollment(user, factor, code)` | Activates the factor. With the user's first factor, recovery codes are returned once |
| `status(user)`, `factors(user)` | Active factors, whether the policy requires one, recovery codes left |
| `send_step_up_code(user, method)` | An email / SMS code for a step-up proof |
| `regenerate_recovery_codes(user, proof)` | Needs a fresh code (`StepUpProof`); replaces the old set |
| `remove_factor(user, factor, proof)` | Needs a fresh code. With the last factor, the recovery codes go too |
| `reset(user)` | Administrative, no proof: deletes every factor and recovery code (e.g. a lost phone, after your own identity checks) |
| `send_login_code(challenge_token, method)` | Before login completes; the challenge token is the credential |

With `AUTH_MFA_END_SESSIONS_ON_REMOVAL` (on by default), `remove_factor` and `reset` end the user's sessions with `RevocationReason::SecondFactorChanged`.

`z_auth_mfa::api` has framework-agnostic DTOs and handlers for all of these. Handlers take the `user_id` from a token the host verified. Enrollment works with password-only tokens, so required-but-unenrolled users can enroll.

## Configuration

`MfaEnvLoader` reads these; `RawMfaConfig` has a setter for each.

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_MFA_ENFORCEMENT` | `optional` | `off`: never challenge. `optional`: challenge users who enrolled. `required`: every user needs a factor. `roles`: users with `AUTH_MFA_REQUIRED_ROLES` need one, others are challenged if they enrolled |
| `AUTH_MFA_REQUIRED_ROLES` | — | Role codes, comma-separated (with `roles`) |
| `AUTH_MFA_UNENROLLED` | `allow` | A required user without a factor gets password-only tokens (`allow`, so they can enroll) or is refused with `second_factor_not_enrolled` (`deny`) |
| `AUTH_MFA_METHODS` | `totp` | Enabled factors, preferred first: any of `totp`, `email`, `sms` |
| `AUTH_MFA_ENCRYPTION_KEY` | required* | Base64, 32 bytes. Seals TOTP secrets and destinations (*unless a custom `SecretSealer` is given) |
| `AUTH_MFA_PREVIOUS_ENCRYPTION_KEYS` | — | Comma-separated base64 keys, still accepted for opening |
| `AUTH_MFA_HASH_KEY` | required | Base64, ≥ 32 bytes. HMAC key for codes, recovery codes and challenge tokens |
| `AUTH_MFA_TOTP_ISSUER` | `AUTH_JWT_ISSUER` | Name shown in authenticator apps |
| `AUTH_MFA_TOTP_ALGORITHM` | `sha1` | `sha1` \| `sha256` \| `sha512` (most apps only support `sha1`) |
| `AUTH_MFA_TOTP_DIGITS` | `6` | 6–8 |
| `AUTH_MFA_TOTP_PERIOD_SECS` | `30` | |
| `AUTH_MFA_TOTP_SKEW_STEPS` | `1` | Steps accepted on either side of the current one, 0–5 |
| `AUTH_MFA_TOTP_SECRET_BYTES` | `20` | 16–64 |
| `AUTH_MFA_ENROLLMENT_TTL_SECS` | `600` | |
| `AUTH_MFA_RECOVERY_CODE_COUNT` | `10` | 0 disables recovery codes |
| `AUTH_MFA_RECOVERY_CODE_LENGTH` | `10` | Characters (Crockford base32, shown in groups of five), 8–32 |
| `AUTH_MFA_CHALLENGE_TTL_SECS` | `300` | |
| `AUTH_MFA_CHALLENGE_MAX_ATTEMPTS` | `5` | |
| `AUTH_MFA_CHALLENGE_MATCH` | `none` | Or any of `ip`, `user_agent`, `fingerprint`: must match between the two steps |
| `AUTH_MFA_LOCKOUT_THRESHOLD` | `10` | Failures per window; 0 never locks |
| `AUTH_MFA_LOCKOUT_WINDOW_SECS` | `900` | |
| `AUTH_MFA_LOCKOUT_SECS` | `900` | |
| `AUTH_MFA_CODE_DIGITS` | `6` | Email / SMS codes, 6–10 |
| `AUTH_MFA_CODE_TTL_SECS` | `300` | |
| `AUTH_MFA_CODE_RESEND_SECS` | `30` | Minimum gap between sends |
| `AUTH_MFA_CODE_MAX_SENDS` | `5` | Sends while a code is valid |
| `AUTH_MFA_AUTO_SEND` | `true` | Send a code at login when the user has no TOTP factor |
| `AUTH_MFA_END_SESSIONS_ON_REMOVAL` | `true` | |
| `AUTH_MFA_PURGE_INTERVAL_SECS` | `300` | How often `tick` purges |
| `AUTH_MFA_PURGE_RETENTION_SECS` | `86400` | How long expired rows are kept |

Generate the keys with `cargo run -p z-auth-mfa --example mfa_keygen`.

## Keys and secrets at rest

- TOTP secrets and email / SMS destinations are sealed with XChaCha20-Poly1305 (feature `aead`, on by default). Each value gets a random nonce and is bound to its user and factor ids, so a value copied to another row doesn't open. Only a masked hint of each destination (`j***@example.com`, `*******4567`) is stored in clear. To use a KMS instead, implement `SecretSealer` and pass it with `Mfa::with_sealer`.
- To rotate the encryption key, set the new one and move the old one to `AUTH_MFA_PREVIOUS_ENCRYPTION_KEYS`. Sealed values carry their key id. Losing a key makes every factor sealed with it unusable (TOTP secrets and email / SMS destinations alike); recovery codes and `reset` still work.
- Recovery codes, email / SMS codes and challenge secrets are stored only as HMAC-SHA256 under `AUTH_MFA_HASH_KEY`, so a leaked database can't be replayed or brute-forced offline. Changing the hash key invalidates every recovery code and pending challenge.

## Deployments

- **Shared mode**: every instance uses the same database and the same `AUTH_MFA_*` keys.
- **Federation mode**: second factors belong to the authority (UMS). Register the extension there, and route the enrollment endpoints and `POST /login/second-factor` to it. Session stores refuse `complete_login` like `login`. They need no z-auth-mfa: the `amr` of a session is synced with it, and `require_mfa` works everywhere.

## Storage

The crate ships no database code. Implement `MfaRepository`, or use `z-auth-postgres` with feature `mfa` (`PgMfaRepository`, migration set `migrations_mfa/`, `setup_db --mfa`). The trait documents which methods must be atomic.
