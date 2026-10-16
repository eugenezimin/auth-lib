# z-auth

[![CI](https://github.com/eugenezimin/z-auth/actions/workflows/ci.yml/badge.svg?event=pull_request)](https://github.com/eugenezimin/z-auth/actions/workflows/ci.yml)
[![Release](https://github.com/eugenezimin/z-auth/actions/workflows/release.yml/badge.svg)](https://github.com/eugenezimin/z-auth/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/eugenezimin/z-auth?include_prereleases&sort=semver)](https://github.com/eugenezimin/z-auth/releases/latest)

A storage- and transport-agnostic authentication library for Rust.

z-auth defines the auth domain (users, roles, permissions, sessions, tokens) and the ports (traits) it needs from the outside world. The host application supplies the adapters: database repositories, HTTP routing, cluster transport. The library ships no database driver and no web server.

## Crates

| Crate | Path | What it is |
|---|---|---|
| `z-auth` | `.` | The core: registration, login, sessions, Ed25519 access tokens, HMAC refresh tokens, revocation, RBAC and permissions, and the `ZAuth` facade |
| `z-auth-cluster` | [`adapters/cluster`](adapters/cluster/README.md) | Optional clustering as a z-auth `Extension`: shared mode (one database) and federation mode (database per service) |
| `z-auth-mfa` | [`adapters/mfa`](adapters/mfa/README.md) | Optional two-factor authentication as a z-auth `Extension`: TOTP, email / SMS codes and recovery codes, configured through `AUTH_MFA_*` |
| `z-auth-mfa-delivery` | [`adapters/mfa-delivery`](adapters/mfa-delivery/README.md) | Delivery of z-auth-mfa's email / SMS codes: SMTP, SendGrid, Postmark, Mailgun, Twilio or a signed webhook, chosen through `AUTH_MFA_*_PROVIDER` |
| `z-auth-postgres` | [`adapters/postgres`](adapters/postgres/README.md) | Reference PostgreSQL adapter (sqlx) with migrations and the `setup_db` binary, including the cluster and mfa stores behind features |
| `z-auth-testkit` | `testkit` | In-memory adapters and helpers for the test suites (not published) |

## Quick start

```sh
cp env.example .env
cargo run --example keygen                    # generate signing keys and the refresh secret
cargo run -p z-auth-postgres --bin setup_db   # create the database and apply migrations
cargo test --workspace --exclude z-auth-postgres --all-features
```

With two-factor authentication, also generate its keys and create its tables:

```sh
cargo run -p z-auth-mfa --example mfa_keygen                       # AUTH_MFA_ENCRYPTION_KEY, AUTH_MFA_HASH_KEY
cargo run -p z-auth-postgres --features mfa --bin setup_db -- --mfa
```

`login()` returns `LoginOutcome::Tokens` or, when a second factor is needed, `LoginOutcome::SecondFactor` with a challenge that `complete_login()` answers. Access tokens carry the session's authentication methods (`amr`), which `Authorizer::require_mfa` checks.

See the crate-level documentation (`cargo doc --open`) for the module layout and wiring.

## CI and releases

- Every pull request to `main` runs format, clippy, tests (including the PostgreSQL adapter against a PostgreSQL 16 service), feature-combination builds, docs and a security audit.
- Pushing a `v*` tag that matches the crate version (e.g. `v0.3.0`) builds release binaries (`setup_db`, `keygen`, `mfa_keygen`) for Linux x86_64 and macOS arm64 and publishes them, with SHA-256 checksums, on [GitHub Releases](https://github.com/eugenezimin/z-auth/releases).
