# setup_db — Database Setup Script

A small Rust binary that bootstraps the `auth` PostgreSQL database from scratch.
It reads the schema from `src/data_models/postgres.sql` and handles everything —
creating the database, running the migration, and protecting existing data.

---

## Prerequisites

- PostgreSQL installed and running locally
- Rust toolchain (`cargo`)

---

## Configuration

Create a `.env` file in the **project root**:

```env
DB_HOST=localhost
DB_PORT=5432          # optional, defaults to 5432
DB_USER=postgres
DB_PASSWORD=secret
DB_NAME=auth          # optional, defaults to "auth"
```

Real environment variables take priority over `.env` if both are present.

---

## Installation

Add the following to your `Cargo.toml`:

```toml
[[bin]]
name = "setup_db"
path = "src/bin/setup_db.rs"

[dependencies]
tokio          = { version = "1", features = ["full"] }
tokio-postgres = { version = "0.7" }
```

Place `setup_db.rs` in `src/bin/`.

---

## Usage

Run from the **project root**:

```bash
cargo run --bin setup_db
```

---

## What it does

1. **Loads `.env`** from the project root (skips silently if absent)
2. **Checks the PostgreSQL server** — if unreachable or credentials are wrong, prints a specific error and exits
3. **Creates the database** if it doesn't exist yet
4. **Inspects existing tables** — if any contain data, asks for confirmation before proceeding:
   ```
   ⚠️  Existing tables with data were found in database 'auth'.
      Drop everything and re-create? [y/N]:
   ```
   Answering `N` exits with no changes made.
5. **Runs the migration** from `src/data_models/postgres.sql` — drops old tables, creates new ones, applies foreign keys and indexes
6. Exits with a success message
