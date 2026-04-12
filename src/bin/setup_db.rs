//! Database setup script for the auth service.
//!
//! Run with:  cargo run --bin setup_db
//!
//! Reads connection details from a `.env` file in the project root.
//! Expected variables:
//!   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME (optional – defaults to "auth")
//!
//! Migration SQL is read at runtime from `src/model/migrations/postgres.sql`
//! (path relative to the project root, i.e. where you run `cargo` from).

use std::io::{self, Write};

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

// ── SQL file path ─────────────────────────────────────────────────────────────

const SQL_FILE: &str = "src/model/migrations/postgres.sql";

const MANAGED_TABLES: &[&str] = &["sessions", "user_roles", "users", "roles"];

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
    let db_host = env_or_exit("DB_HOST");
    let db_port: u16 = env_var("DB_PORT")
        .unwrap_or_else(|| "5432".into())
        .parse()
        .unwrap_or_else(|_| fatal("DB_PORT is not a valid port number."));
    let db_user = env_or_exit("DB_USER");
    let db_password = env_or_exit("DB_PASSWORD");
    let db_name = env_var("DB_NAME").unwrap_or_else(|| "auth".into());

    println!("  Host     : {}:{}", db_host, db_port);
    println!("  User     : {}", db_user);
    println!("  Database : {}", db_name);
    println!();

    // 3. Connect to the default `postgres` database to create our target db
    let admin_url = format!(
        "postgres://{}:{}@{}:{}/postgres",
        db_user, db_password, db_host, db_port
    );
    let admin_pool = connect(&admin_url, "postgres").await;

    // 4. Ensure the target database exists
    ensure_database_exists(&admin_pool, &db_name).await;
    admin_pool.close().await;

    // 5. Connect to the target database
    let db_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        db_user, db_password, db_host, db_port, db_name
    );
    let pool = connect(&db_url, &db_name).await;

    // 6. Check for existing tables / data
    let has_data = check_existing_data(&pool).await;

    if has_data {
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

        match answer.trim().to_lowercase().as_str() {
            "y" | "yes" => {
                println!();
                println!("  → Dropping existing schema…");
            }
            _ => {
                println!();
                println!("  → Aborted. No changes were made.");
                println!();
                std::process::exit(0);
            }
        }
    } else {
        println!("  → No conflicting data found. Proceeding with fresh setup…");
        println!();
    }

    // 7. Load SQL file and run migration
    let statements = load_sql_statements();
    run_migration(&pool, &statements).await;

    println!();
    println!(
        "✅  Database '{}' is ready. All tables created successfully.",
        db_name
    );
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
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"').trim_matches('\'');
            if std::env::var(key).is_err() {
                unsafe { std::env::set_var(key, value) };
            }
        }
    }
    println!("  ✓ Loaded .env");
}

fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn env_or_exit(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!();
        eprintln!("❌  Missing required environment variable: {}", key);
        eprintln!("    Add it to your .env file or export it before running.");
        eprintln!();
        std::process::exit(1);
    })
}

fn fatal(msg: &str) -> ! {
    eprintln!();
    eprintln!("❌  {}", msg);
    eprintln!();
    std::process::exit(1);
}

/// Connect to Postgres via a URL; exits with a user-friendly message on failure.
async fn connect(url: &str, dbname: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
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

fn load_sql_statements() -> Vec<String> {
    let path = std::path::Path::new(SQL_FILE);
    if !path.exists() {
        fatal(&format!(
            "SQL file not found: {}\n    Make sure you run `cargo run --bin setup_db` from the project root.",
            SQL_FILE
        ));
    }

    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| fatal(&format!("Cannot read {}: {}", SQL_FILE, e)));

    println!("  ✓ Loaded SQL from {}", SQL_FILE);

    let cleaned: String = raw
        .lines()
        .map(|line| {
            if let Some(pos) = line.find("--") {
                &line[..pos]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    cleaned
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn run_migration(pool: &PgPool, statements: &[String]) {
    println!("  Running migration ({} statements)…", statements.len());
    println!();

    for stmt in statements {
        let flat: String = stmt.split_whitespace().collect::<Vec<&str>>().join(" ");
        let label = if flat.len() > 80 {
            format!("{}…", &flat[..80])
        } else {
            flat.clone()
        };

        print!("  → Executing: {}", label);

        sqlx::query(stmt).execute(pool).await.unwrap_or_else(|e| {
            fatal(&format!(
                "Migration failed on statement:\n  {}\nError: {}",
                label, e
            ))
        });

        println!("  ✓");
    }
}
