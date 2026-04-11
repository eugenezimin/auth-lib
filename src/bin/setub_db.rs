//! Database setup script for the auth service.
//!
//! Run with:  cargo run --bin setup_db
//!
//! Reads connection details from a `.env` file in the project root.
//! Expected variables:
//!   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME (optional – defaults to "auth")
//!
//! Migration SQL is read at runtime from `src/data_models/postgres.sql`
//! (path relative to the project root, i.e. where you run `cargo` from).

use std::io::{self, Write};

use tokio_postgres::{Client, Config, Error as PgError, NoTls};

// ── SQL file path ─────────────────────────────────────────────────────────────

const SQL_FILE: &str = "src/data_models/postgres.sql";

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
        .unwrap_or_else(|_| {
            fatal("DB_PORT is not a valid port number.");
        });
    let db_user = env_or_exit("DB_USER");
    let db_password = env_or_exit("DB_PASSWORD");
    let db_name = env_var("DB_NAME").unwrap_or_else(|| "auth".into());

    println!("  Host     : {}:{}", db_host, db_port);
    println!("  User     : {}", db_user);
    println!("  Database : {}", db_name);
    println!();

    // 3. Connect to the *default* postgres database to check server availability
    //    and create our target database if missing.
    let admin_client = connect(&db_host, db_port, &db_user, &db_password, "postgres").await;

    // 4. Ensure the target database exists
    ensure_database_exists(&admin_client, &db_name).await;
    drop(admin_client); // release admin connection

    // 5. Connect to the target database
    let client = connect(&db_host, db_port, &db_user, &db_password, &db_name).await;

    // 6. Check for existing tables / data
    let has_data = check_existing_data(&client).await;

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
    run_migration(&client, &statements).await;

    println!();
    println!(
        "✅  Database '{}' is ready. All tables created successfully.",
        db_name
    );
    println!();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Load a `.env` file from the current working directory (best-effort).
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
            // Don't override already-set variables so the real env takes priority.
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

/// Connect to Postgres; exits with a user-friendly message on failure.
async fn connect(host: &str, port: u16, user: &str, password: &str, dbname: &str) -> Client {
    let mut config = Config::new();
    config
        .host(host)
        .port(port)
        .user(user)
        .password(password)
        .dbname(dbname);

    match config.connect(NoTls).await {
        Ok((client, connection)) => {
            // Drive the connection in the background.
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("  ⚠️  Connection error: {}", e);
                }
            });
            client
        }
        Err(e) => {
            diagnose_connection_error(&e, host, port, user, dbname);
        }
    }
}

/// Print a helpful diagnosis for common connection errors, then exit.
fn diagnose_connection_error(e: &PgError, host: &str, port: u16, user: &str, dbname: &str) -> ! {
    eprintln!();
    let msg = e.to_string();

    if msg.contains("Connection refused") || msg.contains("No such file or directory") {
        eprintln!("❌  Cannot reach PostgreSQL at {}:{}.", host, port);
        eprintln!("    → Make sure PostgreSQL is installed and running.");
        eprintln!("    → On macOS:  brew services start postgresql");
        eprintln!("    → On Linux:  sudo systemctl start postgresql");
    } else if msg.contains("password authentication failed") || msg.contains("role") {
        eprintln!("❌  Authentication failed for user '{}'.", user);
        eprintln!("    → Check DB_USER and DB_PASSWORD in your .env file.");
    } else if msg.contains("database") && msg.contains("does not exist") {
        // We'll handle this case normally for the target db; for postgres db it's fatal.
        eprintln!("❌  Could not connect to database '{}'.", dbname);
        eprintln!("    → The 'postgres' default database appears to be missing.");
        eprintln!("    → Your PostgreSQL installation may be incomplete.");
    } else {
        eprintln!("❌  Failed to connect to PostgreSQL: {}", e);
    }

    eprintln!();
    std::process::exit(1);
}

/// Create the target database if it doesn't already exist.
async fn ensure_database_exists(admin: &Client, db_name: &str) {
    let exists: bool = admin
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
            &[&db_name],
        )
        .await
        .expect("Failed to query pg_database")
        .get(0);

    if exists {
        println!("  ✓ Database '{}' already exists.", db_name);
    } else {
        // Database name cannot be parameterised in DDL.
        let sql = format!("CREATE DATABASE \"{}\"", db_name);
        admin
            .execute(&sql, &[])
            .await
            .unwrap_or_else(|e| fatal(&format!("Failed to create database '{}': {}", db_name, e)));
        println!("  ✓ Created database '{}'.", db_name);
    }
    println!();
}

/// Returns true if any managed table exists AND contains at least one row.
async fn check_existing_data(client: &Client) -> bool {
    for table in MANAGED_TABLES {
        // Check whether the table exists in public schema
        let exists: bool = client
            .query_one(
                "SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = $1
                )",
                &[table],
            )
            .await
            .expect("Failed to check table existence")
            .get(0);

        if !exists {
            continue;
        }

        let sql = format!("SELECT EXISTS(SELECT 1 FROM \"public\".\"{table}\" LIMIT 1)");
        let has_rows: bool = client
            .query_one(&sql, &[])
            .await
            .expect("Failed to query table")
            .get(0);

        if has_rows {
            println!("  ⚠️  Table '{}' contains data.", table);
            return true;
        }
    }
    false
}

/// Read `src/data_models/postgres.sql`, strip comments and blank lines,
/// then split on `;` to produce individual executable statements.
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

    // Strip single-line comments (-- …) and collect non-blank lines.
    let cleaned: String = raw
        .lines()
        .map(|line| {
            // Remove inline comment portion
            if let Some(pos) = line.find("--") {
                &line[..pos]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Split on semicolons → individual statements
    cleaned
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Execute every statement parsed from the SQL file sequentially.
async fn run_migration(client: &Client, statements: &[String]) {
    println!("  Running migration ({} statements)…", statements.len());
    println!();

    for stmt in statements {
        // Build a single-line label for display
        let flat: String = stmt
            .chars()
            .map(|c| if c == '\n' { ' ' } else { c })
            .collect();
        let label = if flat.len() > 72 {
            format!("{}…", &flat[..72])
        } else {
            flat.clone()
        };

        client
            .execute(stmt.as_str(), &[])
            .await
            .unwrap_or_else(|e| {
                fatal(&format!(
                    "Migration failed on statement:\n  {}\nError: {}",
                    label, e
                ))
            });

        println!("  ✓ {}", label);
    }
}
