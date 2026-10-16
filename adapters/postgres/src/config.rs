//! PostgreSQL connection settings.
//!
//! Database configuration belongs to the adapter / host application, not to
//! z-auth itself.

use std::time::Duration;

use z_auth::conf::config::{ConfigSource, Section};

use crate::constants::*;

#[derive(Clone)]
pub struct PgConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub name: String,
    /// Maximum number of connections kept in the pool.
    pub max_pool_size: u32,
    /// How long to wait for a connection before giving up.
    pub connect_timeout: Duration,
}

impl PgConfig {
    /// Read `DB_*` environment variables.  `DB_HOST`, `DB_USER` and
    /// `DB_PASSWORD` are required; everything else has a default.
    pub fn from_env() -> Result<Self, String> {
        Self::from_source(&ConfigSource::env())
    }

    /// Read the `database` section of a [`ConfigSource`]; the `DB_*`
    /// environment variables override the file.  `host`, `user` and
    /// `password` are required; everything else has a default.
    pub fn from_source(source: &ConfigSource) -> Result<Self, String> {
        let s = source
            .section(SECTION, KEYS, &[])
            .map_err(|e| e.to_string())?;
        let required = |key: &str| {
            s.get(key)
                .map(|v| v.value)
                .ok_or_else(|| match KEYS.iter().find(|k| k.env == key) {
                    Some(k) if source.has_file() => format!("missing {key} or {}", k.path),
                    _ => format!("missing env var {key}"),
                })
        };
        fn parsed<T: std::str::FromStr>(s: &Section, key: &str) -> Result<Option<T>, String>
        where
            T::Err: std::fmt::Display,
        {
            s.get(key)
                .map(|v| {
                    v.value
                        .parse::<T>()
                        .map_err(|e| format!("invalid {}: {e}", v.origin))
                })
                .transpose()
        }

        Ok(Self {
            host: required(ENV_DB_HOST)?,
            port: parsed(&s, ENV_DB_PORT)?.unwrap_or(DEFAULT_PORT),
            user: required(ENV_DB_USER)?,
            password: required(ENV_DB_PASSWORD)?,
            name: s
                .get(ENV_DB_NAME)
                .map(|v| v.value)
                .unwrap_or_else(|| DEFAULT_DB_NAME.into()),
            max_pool_size: parsed::<u64>(&s, ENV_DB_MAX_POOL_SIZE)?
                .map(|v| v as u32)
                .unwrap_or(DEFAULT_MAX_POOL_SIZE),
            connect_timeout: Duration::from_secs(
                parsed(&s, ENV_DB_CONNECT_TIMEOUT_SECS)?.unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS),
            ),
        })
    }

    /// `postgres://user:password@host:port/name`
    pub fn connection_url(&self) -> String {
        self.connection_url_for(&self.name)
    }

    /// Same as [`connection_url`](Self::connection_url) but for another
    /// database on the same server (e.g. the `postgres` maintenance DB).
    pub fn connection_url_for(&self, db_name: &str) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, db_name,
        )
    }
}

/// Redacts `password` so configs can be logged safely.
impl std::fmt::Debug for PgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("name", &self.name)
            .field("max_pool_size", &self.max_pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = "
database:
  host: db.internal
  port: 6432
  user: auth
  password: from-file
  name: auth_prod
  max_pool_size: 20
  connect_timeout_secs: 2
";

    #[test]
    fn the_database_section_is_read() {
        let cfg = PgConfig::from_source(&ConfigSource::yaml_str(YAML).unwrap()).unwrap();
        assert_eq!((cfg.host.as_str(), cfg.port), ("db.internal", 6432));
        assert_eq!(
            (cfg.user.as_str(), cfg.password.as_str()),
            ("auth", "from-file")
        );
        assert_eq!(cfg.name, "auth_prod");
        assert_eq!(cfg.max_pool_size, 20);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(2));
    }

    #[test]
    fn the_environment_overrides_the_file() {
        let source = ConfigSource::yaml_str(YAML)
            .unwrap()
            .with_lookup(|key| (key == ENV_DB_PASSWORD).then(|| "from-env".into()));
        let cfg = PgConfig::from_source(&source).unwrap();
        assert_eq!(cfg.password, "from-env");
        assert_eq!(cfg.host, "db.internal");
    }

    #[test]
    fn errors_name_the_variable_and_the_path() {
        let source = ConfigSource::yaml_str("database:\n  host: h\n  user: u\n").unwrap();
        assert_eq!(
            PgConfig::from_source(&source).unwrap_err(),
            "missing DB_PASSWORD or database.password"
        );

        let env_only = ConfigSource::from_lookup(|key| (key == ENV_DB_HOST).then(|| "h".into()));
        assert_eq!(
            PgConfig::from_source(&env_only).unwrap_err(),
            "missing env var DB_USER"
        );

        let bad = YAML.replace("port: 6432", "port: high");
        let err = PgConfig::from_source(&ConfigSource::yaml_str(&bad).unwrap()).unwrap_err();
        assert!(err.starts_with("invalid database.port in YAML"), "{err}");

        let typo = YAML.replace("max_pool_size", "pool_size");
        let err = PgConfig::from_source(&ConfigSource::yaml_str(&typo).unwrap()).unwrap_err();
        assert!(err.contains("database.pool_size in YAML"), "{err}");
    }

    #[test]
    fn the_example_file_loads_with_the_password_from_the_environment() {
        let example = concat!(env!("CARGO_MANIFEST_DIR"), "/../../z-auth.example.yaml");
        let source = ConfigSource::yaml_file(example)
            .unwrap()
            .with_lookup(|key| (key == ENV_DB_PASSWORD).then(|| "secret".into()));
        let cfg = PgConfig::from_source(&source).unwrap();
        assert_eq!(
            cfg.connection_url(),
            "postgres://postgres:secret@localhost:5432/auth"
        );
        assert_eq!(cfg.max_pool_size, DEFAULT_MAX_POOL_SIZE);
        assert_eq!(
            cfg.connect_timeout,
            Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)
        );
    }
}
