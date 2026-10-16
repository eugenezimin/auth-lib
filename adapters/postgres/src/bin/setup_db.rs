//! Database setup script for the auth service.
//!
//! Run with:  cargo run -p z-auth-postgres --bin setup_db [-- --reset]
//! Cluster:   cargo run -p z-auth-postgres --features shared --bin setup_db -- --cluster
//! 2FA:       cargo run -p z-auth-postgres --features mfa --bin setup_db -- --mfa
//!
//! Reads connection details from the environment (a `.env` file in the
//! current directory is loaded first, if present).  Expected variables:
//!   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME (optional – defaults to "auth")
//! When AUTH_CONFIG_FILE names a YAML file, its `database` section is read
//! as well, and the variables above override it.
//!
//! 1. Creates the database if it does not exist.
//! 2. Replaces a *legacy* schema (tables created before versioned
//!    migrations, i.e. without `_sqlx_migrations`) — asking first if any
//!    table holds data.  `--reset` does the same for any schema (dev only).
//! 3. Applies pending migrations from `adapters/postgres/migrations`, which
//!    are embedded at compile time, so the binary runs from any directory.
//!    With `--cluster` (feature `shared`) it then applies z-auth-cluster's
//!    set from `migrations_cluster` (versions from 1001), and with `--mfa`
//!    (feature `mfa`) z-auth-mfa's set from `migrations_mfa` (versions from
//!    2001).
//!    A database built with the migrations replaced by the current baseline
//!    (the old 0001–0008) is refused with a hint to rerun with `--reset`.

use std::collections::HashSet;
use std::io::{self, Write};
use std::ops::Range;

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use z_auth::conf::config::ConfigSource;
#[cfg(feature = "shared")]
use z_auth_postgres::CLUSTER_MIGRATOR;
#[cfg(feature = "mfa")]
use z_auth_postgres::MFA_MIGRATOR;
use z_auth_postgres::{MIGRATOR, PgConfig, constants::ADMIN_DB_NAME, pool::connect_options};

/// Every table z-auth has ever created: the current schema, the names
/// used before the baseline (old migrations 0001–0008), and `revoked_tokens`
/// from pre-migration databases.
const MANAGED_TABLES: &[&str] = &[
    // current schema
    "mfa_challenges",
    "mfa_recovery_codes",
    "mfa_factors",
    "mfa_user_state",
    "cluster_sync_freshness",
    "cluster_feed_cursors",
    "cluster_change_feed",
    "cluster_sync_site",
    "cluster_catalog_snapshot",
    "cluster_account_snapshots",
    "cluster_nodes",
    "security_verifying_keys",
    "security_token_revocations",
    "security_session_fork_aliases",
    "security_session_generations",
    "security_sessions",
    "security_role_grants",
    "security_user_grants",
    "security_permission_options",
    "security_permissions",
    "identity_role_assignments",
    "identity_users",
    "identity_roles",
    // before the baseline
    "sync_freshness",
    "sync_cursors",
    "sync_changes",
    "sync_site",
    "catalog_snapshot",
    "account_snapshots",
    "verifying_keys",
    "revocations",
    "session_generation_aliases",
    "session_generations",
    "sessions",
    "role_permission_grants",
    "user_permission_grants",
    "permission_options",
    "permissions",
    "users_roles",
    "users",
    "roles",
    // pre-migration
    "revoked_tokens",
];

/// Enum types created by the migrations (`node_status` only before the
/// baseline).
const MANAGED_TYPES: &[&str] = &[
    "session_status",
    "revocation_scope",
    "revocation_reason",
    "revocation_status",
    "permission_kind",
    "node_state",
    "heartbeat_status",
    "verifying_key_status",
    "mfa_method",
    "mfa_factor_status",
    "mfa_totp_algorithm",
    "node_status",
];

/// Free-standing sequences, current and before the baseline.
const MANAGED_SEQUENCES: &[&str] = &[
    "security_permission_position_seq",
    "cluster_account_snapshot_version_seq",
    "cluster_change_feed_seq",
    "permission_position_seq",
    "account_snapshot_version_seq",
    "sync_change_seq",
];

/// Change-feed functions, current and before the baseline.
const MANAGED_FUNCTIONS: &[&str] = &[
    "cluster_feed_capture",
    "cluster_feed_record",
    "sync_capture",
    "sync_record_change",
];

/// sqlx's bookkeeping table.
const MIGRATIONS_TABLE: &str = "_sqlx_migrations";

/// The cluster set's versions (`migrations_cluster/`).
const CLUSTER_VERSIONS: Range<i64> = 1000..2000;
/// The mfa set's versions (`migrations_mfa/`).
#[cfg_attr(not(feature = "mfa"), allow(dead_code))]
const MFA_VERSIONS: Range<i64> = 2000..3000;

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!();
    println!("╔══════════════════════════════════════╗");
    println!("║      Auth DB – Setup Script          ║");
    println!("╚══════════════════════════════════════╝");
    println!();

    // 1. Load .env
    load_env();

    // 2. Read config
    let cluster = std::env::args().any(|a| a == "--cluster");
    #[cfg(not(feature = "shared"))]
    if cluster {
        fatal(
            "--cluster needs the `shared` feature:\n    → cargo run -p z-auth-postgres \
             --features shared --bin setup_db -- --cluster",
        );
    }
    let mfa = std::env::args().any(|a| a == "--mfa");
    #[cfg(not(feature = "mfa"))]
    if mfa {
        fatal(
            "--mfa needs the `mfa` feature:\n    → cargo run -p z-auth-postgres \
             --features mfa --bin setup_db -- --mfa",
        );
    }
    // AUTH_CONFIG_FILE's `database` section, with DB_* on top.
    let source = ConfigSource::standard().unwrap_or_else(|e| fatal(&e.to_string()));
    let cfg = PgConfig::from_source(&source).unwrap_or_else(|e| fatal(&e));
    let db_name = cfg.name.clone();

    println!("  Host     : {}:{}", cfg.host, cfg.port);
    println!("  User     : {}", cfg.user);
    println!("  Database : {}", db_name);
    println!();

    // 3. Connect to the maintenance database to create our target db
    let admin_pool = connect(&cfg.connection_url_for(ADMIN_DB_NAME), ADMIN_DB_NAME).await;

    // 4. Ensure the target database exists
    ensure_database_exists(&admin_pool, &db_name).await;
    admin_pool.close().await;

    // 5. Connect to the target database
    let pool = connect(&cfg.connection_url(), &db_name).await;

    // 6. Replace a legacy (pre-migration) schema, or everything on --reset
    let reset = std::env::args().any(|a| a == "--reset");
    let tracked = table_exists(&pool, MIGRATIONS_TABLE).await;
    let legacy = !tracked && any_managed_table_exists(&pool).await;
    if reset || legacy {
        if reset {
            println!("  → --reset: dropping every z-auth table, type and migration record.");
        } else {
            println!(
                "  → Found tables created before versioned migrations; they must be replaced."
            );
        }
        if check_existing_data(&pool).await {
            confirm_or_exit(&db_name);
        }
        drop_schema(&pool).await;
    } else {
        println!("  → No legacy schema found.");
    }
    println!();

    // 7. Apply pending migrations: core, then (with --cluster / --mfa) the
    //    cluster and mfa sets
    check_baseline(&pool).await;
    apply_migrations(&pool, &MIGRATOR, "core").await;
    #[cfg(feature = "shared")]
    if cluster {
        apply_migrations(&pool, &CLUSTER_MIGRATOR, "cluster").await;
    }
    #[cfg(feature = "mfa")]
    if mfa {
        apply_migrations(&pool, &MFA_MIGRATOR, "mfa").await;
    }

    println!();
    println!("✅  Database '{}' is up to date.", db_name);
    println!();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_env() {
    let path = std::path::Path::new(".env");
    if !path.exists() {
        println!("  ℹ️  No .env file found – relying on environment variables.");
        println!();
        return;
    }
    let content = std::fs::read_to_string(path).expect("Failed to read .env file");
    for (key, value) in content.lines().filter_map(parse_env_line) {
        if std::env::var(key).is_err() {
            unsafe { std::env::set_var(key, value) };
        }
    }
    println!("  ✓ Loaded .env");
}

/// Parses one `.env` line into its key and value.
///
/// Blank lines, `#` comments and lines without `=` yield `None`.  A value in
/// matching single or double quotes is taken as written (double quotes also
/// accept `\"` and `\\`), and whatever follows the closing quote is ignored.
/// An unquoted value ends at a `#` preceded by whitespace, so
/// `DB_NAME=auth  # optional` is `auth` while `DB_PASSWORD=pa#ss` keeps its `#`.
fn parse_env_line(line: &str) -> Option<(&str, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, raw) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, parse_env_value(raw)))
}

fn parse_env_value(raw: &str) -> String {
    let value = raw.trim_start();
    if let Some(quote) = value.chars().next().filter(|c| matches!(c, '"' | '\''))
        && let Some(inner) = unquote(&value[1..], quote)
    {
        return inner;
    }
    // Unquoted (or an unclosed quote): a `#` after whitespace starts a comment.
    let mut after_space = value.len() != raw.len();
    for (i, c) in value.char_indices() {
        if c == '#' && after_space {
            return value[..i].trim_end().to_string();
        }
        after_space = c.is_whitespace();
    }
    value.trim_end().to_string()
}

/// The text up to the closing `quote`, or `None` if the quote is never closed.
fn unquote(rest: &str, quote: char) -> Option<String> {
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c == quote => return Some(out),
            '\\' if quote == '"' => match chars.next()? {
                escaped @ ('"' | '\\') => out.push(escaped),
                other => {
                    out.push('\\');
                    out.push(other);
                }
            },
            c => out.push(c),
        }
    }
    None
}

fn fatal(msg: &str) -> ! {
    eprintln!();
    eprintln!("❌  {}", msg);
    eprintln!();
    std::process::exit(1);
}

/// Connect to Postgres via a URL; exits with a user-friendly message on failure.
async fn connect(url: &str, dbname: &str) -> PgPool {
    let options = connect_options(url).unwrap_or_else(|e| fatal(&format!("Bad DB URL: {e}")));
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap_or_else(|e| {
            diagnose_connection_error(&e.to_string(), dbname);
        })
}

fn diagnose_connection_error(msg: &str, dbname: &str) -> ! {
    eprintln!();
    if msg.contains("Connection refused") || msg.contains("No such file") {
        eprintln!("❌  Cannot reach PostgreSQL.");
        eprintln!("    → Make sure PostgreSQL is installed and running.");
        eprintln!("    → On macOS:  brew services start postgresql");
        eprintln!("    → On Linux:  sudo systemctl start postgresql");
    } else if msg.contains("password authentication") || msg.contains("role") {
        eprintln!("❌  Authentication failed.");
        eprintln!("    → Check DB_USER and DB_PASSWORD in your .env file.");
    } else if msg.contains("does not exist") {
        eprintln!("❌  Could not connect to database '{}'.", dbname);
    } else {
        eprintln!("❌  Failed to connect to PostgreSQL: {}", msg);
    }
    eprintln!();
    std::process::exit(1);
}

async fn ensure_database_exists(admin: &PgPool, db_name: &str) {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(db_name)
            .fetch_one(admin)
            .await
            .expect("Failed to query pg_database");

    if exists {
        println!("  ✓ Database '{}' already exists.", db_name);
    } else {
        // Database name cannot be parameterised in DDL.
        let sql = format!("CREATE DATABASE \"{}\"", db_name);
        sqlx::query(&sql)
            .execute(admin)
            .await
            .unwrap_or_else(|e| fatal(&format!("Failed to create database '{}': {}", db_name, e)));
        println!("  ✓ Created database '{}'.", db_name);
    }
    println!();
}

/// Returns true if any managed table exists AND contains at least one row.
async fn check_existing_data(pool: &PgPool) -> bool {
    for table in MANAGED_TABLES {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = $1
            )",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .expect("Failed to check table existence");

        if !exists {
            continue;
        }

        let sql = format!("SELECT EXISTS(SELECT 1 FROM \"public\".\"{table}\" LIMIT 1)");
        let has_rows: bool = sqlx::query_scalar(&sql)
            .fetch_one(pool)
            .await
            .expect("Failed to query table");

        if has_rows {
            println!("  ⚠️  Table '{}' contains data.", table);
            return true;
        }
    }
    false
}

async fn table_exists(pool: &PgPool, table: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = $1
        )",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .expect("Failed to check table existence")
}

async fn any_managed_table_exists(pool: &PgPool) -> bool {
    for table in MANAGED_TABLES {
        if table_exists(pool, table).await {
            return true;
        }
    }
    false
}

fn confirm_or_exit(db_name: &str) {
    println!(
        "⚠️  Existing tables with data were found in database '{}'.",
        db_name
    );
    print!("   Drop everything and re-create? [y/N]: ");
    io::stdout().flush().unwrap();

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .expect("Failed to read input");

    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        println!();
        println!("  → Aborted. No changes were made.");
        println!();
        std::process::exit(0);
    }
}

async fn drop_schema(pool: &PgPool) {
    let tables = MANAGED_TABLES.iter().chain([&MIGRATIONS_TABLE]);
    let statements = tables
        .map(|t| format!("DROP TABLE IF EXISTS \"{t}\" CASCADE"))
        .chain(
            MANAGED_FUNCTIONS
                .iter()
                .map(|f| format!("DROP FUNCTION IF EXISTS \"{f}\" CASCADE")),
        )
        .chain(
            MANAGED_SEQUENCES
                .iter()
                .map(|s| format!("DROP SEQUENCE IF EXISTS \"{s}\" CASCADE")),
        )
        .chain(
            MANAGED_TYPES
                .iter()
                .map(|t| format!("DROP TYPE IF EXISTS \"{t}\" CASCADE")),
        );
    for stmt in statements {
        print!("  → {stmt}");
        sqlx::query(&stmt)
            .execute(pool)
            .await
            .unwrap_or_else(|e| fatal(&format!("Failed: {stmt}\nError: {e}")));
        println!("  ✓");
    }
}

/// Every migration set compiled in, with the versions it owns.
fn known_migrators() -> Vec<(Range<i64>, &'static Migrator)> {
    #[allow(unused_mut)]
    let mut sets = vec![(0..CLUSTER_VERSIONS.start, &MIGRATOR)];
    #[cfg(feature = "shared")]
    sets.push((CLUSTER_VERSIONS, &CLUSTER_MIGRATOR));
    #[cfg(feature = "mfa")]
    sets.push((MFA_VERSIONS, &MFA_MIGRATOR));
    sets
}

async fn applied_migrations(pool: &PgPool) -> Vec<(i64, Vec<u8>)> {
    if table_exists(pool, MIGRATIONS_TABLE).await {
        sqlx::query_as(&format!("SELECT version, checksum FROM {MIGRATIONS_TABLE}"))
            .fetch_all(pool)
            .await
            .expect("Failed to read applied migrations")
    } else {
        Vec::new()
    }
}

/// Applied migrations that are unknown or changed mean the database was
/// built with the migrations the current baseline replaced.  A set's
/// versions are only checked when this binary knows that set.
async fn check_baseline(pool: &PgPool) {
    let sets = known_migrators();
    let replaced = applied_migrations(pool)
        .await
        .iter()
        .any(|(version, checksum)| {
            let Some((_, set)) = sets.iter().find(|(range, _)| range.contains(version)) else {
                return false; // a set this binary was built without
            };
            set.iter()
                .find(|m| m.version == *version && !m.migration_type.is_down_migration())
                .is_none_or(|m| m.checksum.as_ref() != checksum.as_slice())
        });
    if replaced {
        fatal(
            "This database was built with migrations that the current baseline \
             replaced (the old 0001–0008).\n    → Rebuild it: cargo run -p \
             z-auth-postgres --bin setup_db -- --reset",
        );
    }
}

async fn apply_migrations(pool: &PgPool, migrator: &Migrator, set: &str) {
    let applied: HashSet<i64> = applied_migrations(pool)
        .await
        .into_iter()
        .map(|(version, _)| version)
        .collect();
    let pending: Vec<_> = migrator
        .iter()
        .filter(|m| !m.migration_type.is_down_migration() && !applied.contains(&m.version))
        .collect();

    if pending.is_empty() {
        let known = migrator
            .iter()
            .filter(|m| applied.contains(&m.version))
            .count();
        println!("  ✓ No pending {set} migrations ({known} applied).");
        return;
    }
    for m in &pending {
        println!("  → Applying {set} {:04} {}", m.version, m.description);
    }
    migrator
        .run(pool)
        .await
        .unwrap_or_else(|e| fatal(&format!("Migration failed: {e}")));
    println!("  ✓ Applied {} {set} migration(s).", pending.len());
}

#[cfg(test)]
mod tests {
    use super::parse_env_line;

    fn parsed(line: &str) -> Option<(String, String)> {
        parse_env_line(line).map(|(k, v)| (k.to_string(), v))
    }

    fn value(line: &str) -> String {
        parse_env_line(line).expect("a key and value").1
    }

    #[test]
    fn skips_blank_lines_comments_and_lines_without_a_key() {
        assert_eq!(parsed(""), None);
        assert_eq!(parsed("   "), None);
        assert_eq!(parsed("# DB_HOST=localhost"), None);
        assert_eq!(parsed("   # indented comment"), None);
        assert_eq!(parsed("NOT_AN_ASSIGNMENT"), None);
        assert_eq!(parsed("=value"), None);
    }

    #[test]
    fn trims_the_key_and_a_plain_value() {
        assert_eq!(
            parsed("  DB_HOST =  localhost  "),
            Some(("DB_HOST".into(), "localhost".into()))
        );
        assert_eq!(value("DB_PASSWORD="), "");
        assert_eq!(
            value("URL=postgres://u:p@h/db?a=b"),
            "postgres://u:p@h/db?a=b"
        );
    }

    #[test]
    fn strips_inline_comments_after_whitespace() {
        assert_eq!(
            value("DB_NAME=auth                  # optional – defaults to \"auth\" if omitted"),
            "auth"
        );
        assert_eq!(value("DB_MAX_POOL_SIZE=10           # optional"), "10");
        assert_eq!(value("DB_PORT=5432\t# tab before the comment"), "5432");
        assert_eq!(
            value("AUTH_JWT_SIGNING_KEY=   # paste the keygen output here"),
            ""
        );
    }

    #[test]
    fn keeps_a_hash_that_is_part_of_the_value() {
        assert_eq!(value("DB_PASSWORD=pa#ss"), "pa#ss");
        assert_eq!(value("DB_PASSWORD=#secret"), "#secret");
        assert_eq!(value("DB_PASSWORD=pa#ss # comment"), "pa#ss");
    }

    #[test]
    fn takes_quoted_values_as_written() {
        assert_eq!(
            value("DB_PASSWORD=\"s3cr3t # not a comment\""),
            "s3cr3t # not a comment"
        );
        assert_eq!(value("DB_PASSWORD='it''s'  # trailing comment"), "it");
        assert_eq!(value("DB_PASSWORD='C:\\path'"), "C:\\path");
        assert_eq!(value("DB_PASSWORD=\"  padded  \"  # comment"), "  padded  ");
        assert_eq!(
            value("DB_PASSWORD=\"say \\\"hi\\\" \\\\ ok\""),
            "say \"hi\" \\ ok"
        );
        assert_eq!(value("DB_PASSWORD=\"a\\nb\""), "a\\nb");
        assert_eq!(value("DB_PASSWORD=\"\""), "");
    }

    #[test]
    fn leaves_an_unclosed_quote_in_the_value() {
        assert_eq!(value("DB_PASSWORD=\"abc"), "\"abc");
        assert_eq!(value("DB_PASSWORD='abc  # comment"), "'abc");
    }

    #[test]
    fn env_example_parses_without_comment_residue() {
        let example = include_str!("../../../../env.example");
        let pairs: Vec<(&str, String)> = example.lines().filter_map(parse_env_line).collect();
        let get = |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("{key} missing from env.example"))
        };
        assert_eq!(get("DB_HOST"), "localhost");
        assert_eq!(get("DB_NAME"), "auth");
        assert_eq!(get("DB_PORT").parse::<u16>(), Ok(5432));
        assert_eq!(get("DB_MAX_POOL_SIZE").parse::<u32>(), Ok(10));
        assert_eq!(get("DB_CONNECT_TIMEOUT_SECS").parse::<u64>(), Ok(5));
        for (key, value) in &pairs {
            assert!(!value.contains('#'), "{key} kept a comment: {value:?}");
        }
    }
}
