# z-auth

[![CI](https://github.com/eugenezimin/auth-lib/actions/workflows/ci.yml/badge.svg?event=pull_request)](https://github.com/eugenezimin/auth-lib/actions/workflows/ci.yml)
[![Release](https://github.com/eugenezimin/auth-lib/actions/workflows/release.yml/badge.svg)](https://github.com/eugenezimin/auth-lib/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/eugenezimin/auth-lib?include_prereleases&sort=semver)](https://github.com/eugenezimin/auth-lib/releases/latest)

A storage- and transport-agnostic authentication library for Rust.

z-auth defines the auth domain (users, roles, permissions, sessions, tokens) and the ports (traits) it needs from the outside world. The host application supplies the adapters: database repositories, HTTP routing, cluster transport. The library ships no database driver and no web server.

## Crates

| Crate | Path | What it is |
|---|---|---|
| `z-auth` | `.` | The core: registration, login, sessions, Ed25519 access tokens, HMAC refresh tokens, revocation, RBAC and permissions, and the `ZAuth` facade |
| `z-auth-cluster` | [`adapters/cluster`](adapters/cluster/README.md) | Optional clustering as a z-auth `Extension`: shared mode (one database) and federation mode (database per service) |
| `z-auth-postgres` | [`adapters/postgres`](adapters/postgres/README.md) | Reference PostgreSQL adapter (sqlx) with migrations and the `setup_db` binary |
| `z-auth-testkit` | `testkit` | In-memory adapters and helpers for the test suites (not published) |

## Quick start

```sh
cp env.example .env
cargo run --example keygen                    # generate signing keys and the refresh secret
cargo run -p z-auth-postgres --bin setup_db   # create the database and apply migrations
cargo test --workspace --exclude z-auth-postgres --all-features
```

See the crate-level documentation (`cargo doc --open`) for the module layout and wiring.

## CI and releases

- Every pull request to `main` runs format, clippy, tests (including the PostgreSQL adapter against a PostgreSQL 16 service), feature-combination builds, docs and a security audit.
- Pushing a `v*` tag that matches the crate version (e.g. `v0.2.0`) builds release binaries (`setup_db`, `keygen`) for Linux x86_64 and macOS arm64 and publishes them, with SHA-256 checksums, on [GitHub Releases](https://github.com/eugenezimin/auth-lib/releases).
