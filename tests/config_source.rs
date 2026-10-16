//! Config loading from a `ConfigSource` — YAML file, environment overrides,
//! unknown keys and error origins.
#![cfg(feature = "yaml")]

use std::collections::HashMap;
use std::time::Duration;

use z_auth::conf::config::{
    AuthzMode, ConfigError, ConfigLoader, ConfigSource, EnvLoader, Key, SourceLoader,
};
use z_auth::conf::constants::*;

// 32 bytes of 0x07 / 0x09, base64.
const KEY_A: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
const KEY_B: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";

const FULL: &str = r#"
auth:
  jwt:
    signing_key: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=
    verifying_keys:
      - BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=
      - CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=
    issuer: yaml-issuer
    access_ttl_secs: 60
    leeway_secs: 5
  session:
    refresh_secret: CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=
    idle_timeout_secs: 600
    absolute_timeout_secs: 3600
    history_size: 4
    refresh_grace_secs: 10
    ip_binding: true
    retry_match: [ip, fingerprint]
    max_sessions_per_user: 3
  password:
    min_length: 12
    require_uppercase: false
    require_digit: false
  authz:
    mode: combined
server:
  port: 8080
"#;

fn lookup(
    pairs: &[(&'static str, &'static str)],
) -> impl Fn(&str) -> Option<String> + Send + Sync + 'static {
    let map: HashMap<&'static str, &'static str> = pairs.iter().copied().collect();
    move |key| map.get(key).map(|v| v.to_string())
}

fn load(yaml: &str) -> Result<z_auth::conf::config::AuthConfig, ConfigError> {
    SourceLoader::new(ConfigSource::yaml_str(yaml)?).load_config()
}

fn parse_error_key(r: Result<impl std::fmt::Debug, ConfigError>) -> String {
    match r {
        Err(ConfigError::Parse { key, .. }) => key,
        other => panic!("expected a parse error, got {other:?}"),
    }
}

#[test]
fn every_core_setting_loads_from_the_auth_section() {
    let cfg = load(FULL).unwrap();

    assert_eq!(cfg.jwt.signing_key, Some([7u8; 32]));
    assert_eq!(cfg.jwt.verifying_keys, vec![[7u8; 32], [9u8; 32]]);
    assert_eq!(cfg.jwt.issuer, "yaml-issuer");
    assert_eq!(cfg.jwt.access_token_ttl, Duration::from_secs(60));
    assert_eq!(cfg.jwt.leeway, Duration::from_secs(5));
    assert_eq!(cfg.session.refresh_secret.as_deref(), Some(&[9u8; 32][..]));
    assert_eq!(cfg.session.idle_timeout, Duration::from_secs(600));
    assert_eq!(cfg.session.absolute_timeout, Duration::from_secs(3600));
    assert_eq!(cfg.session.history_size, 4);
    assert_eq!(cfg.session.refresh_grace, Duration::from_secs(10));
    assert!(cfg.session.ip_binding);
    let m = cfg.session.retry_match;
    assert!(m.ip && m.fingerprint && !m.user_agent);
    assert_eq!(cfg.session.max_sessions_per_user, 3);
    assert_eq!(cfg.password.min_length, 12);
    assert!(!cfg.password.require_uppercase && !cfg.password.require_digit);
    assert_eq!(cfg.authz.mode, AuthzMode::Combined);
}

#[test]
fn environment_overrides_the_file() {
    let source = ConfigSource::yaml_str(FULL).unwrap().with_lookup(lookup(&[
        (ENV_JWT_ISSUER, "env-issuer"),
        (ENV_JWT_VERIFYING_KEYS, KEY_B),
        (ENV_PASSWORD_MIN_LENGTH, "20"),
    ]));
    let cfg = SourceLoader::new(source).load_config().unwrap();

    assert_eq!(cfg.jwt.issuer, "env-issuer");
    assert_eq!(cfg.jwt.verifying_keys, vec![[9u8; 32]]);
    assert_eq!(cfg.password.min_length, 20);
    // Not overridden: still from the file.
    assert_eq!(cfg.jwt.access_token_ttl, Duration::from_secs(60));
    assert_eq!(cfg.authz.mode, AuthzMode::Combined);
}

#[test]
fn missing_settings_fall_back_to_defaults() {
    let cfg = load("auth:\n  jwt:\n    issuer: only-this\n").unwrap();
    assert_eq!(cfg.jwt.issuer, "only-this");
    assert_eq!(
        cfg.jwt.access_token_ttl.as_secs(),
        DEFAULT_ACCESS_TOKEN_TTL_SECS
    );
    assert_eq!(cfg.session.history_size, DEFAULT_SESSION_HISTORY_SIZE);

    // An empty document, an absent section and null values are all "unset".
    for yaml in [
        "",
        "server:\n  port: 1\n",
        "auth:\n  jwt:\n    issuer: ~\n",
        "auth:\n",
    ] {
        let cfg = load(yaml).unwrap();
        assert_eq!(cfg.jwt.issuer, DEFAULT_JWT_ISSUER, "{yaml:?}");
    }
}

#[test]
fn lists_accept_a_sequence_or_a_comma_string() {
    let cfg = load(&format!(
        "auth:\n  jwt:\n    verifying_keys: \"{KEY_A}, {KEY_B}\"\n  session:\n    retry_match: user_agent\n"
    ))
    .unwrap();
    assert_eq!(cfg.jwt.verifying_keys, vec![[7u8; 32], [9u8; 32]]);
    assert!(cfg.session.retry_match.user_agent && !cfg.session.retry_match.ip);
}

#[test]
fn unknown_keys_in_the_section_are_rejected() {
    let typo = load("auth:\n  jwt:\n    isuer: x\n");
    assert_eq!(parse_error_key(typo), "auth.jwt.isuer in YAML");

    let group = load("auth:\n  tokens:\n    ttl: 5\n");
    assert!(parse_error_key(group).starts_with("auth.tokens"));

    let empty_group = load("auth:\n  sessions: {}\n");
    assert_eq!(parse_error_key(empty_group), "auth.sessions in YAML");

    let scalar_section = load("auth: 5\n");
    assert_eq!(parse_error_key(scalar_section), "auth in YAML");
}

#[test]
fn errors_name_the_path_or_the_variable() {
    let bad = load("auth:\n  jwt:\n    access_ttl_secs: soon\n");
    assert_eq!(parse_error_key(bad), "auth.jwt.access_ttl_secs in YAML");

    let bad_bool = load("auth:\n  session:\n    ip_binding: maybe\n");
    assert_eq!(parse_error_key(bad_bool), "auth.session.ip_binding in YAML");

    let source = ConfigSource::yaml_str(FULL)
        .unwrap()
        .with_lookup(lookup(&[(ENV_JWT_LEEWAY_SECS, "-1")]));
    let from_env = SourceLoader::new(source).load_config();
    assert_eq!(parse_error_key(from_env), ENV_JWT_LEEWAY_SECS);

    let nested_list = load("auth:\n  jwt:\n    verifying_keys: [[a]]\n");
    assert_eq!(
        parse_error_key(nested_list),
        "auth.jwt.verifying_keys in YAML"
    );

    let not_yaml = ConfigSource::yaml_str("auth: [unclosed\n");
    assert_eq!(parse_error_key(not_yaml), "YAML");

    let not_a_mapping = ConfigSource::yaml_str("- auth\n");
    assert_eq!(parse_error_key(not_a_mapping), "YAML");
}

#[test]
fn lookup_without_a_file_behaves_like_the_environment() {
    let source = ConfigSource::from_lookup(lookup(&[
        (ENV_JWT_ISSUER, "from-lookup"),
        (ENV_AUTHZ_MODE, "permissions"),
    ]));
    assert!(!source.has_file());
    let cfg = SourceLoader::new(source).load_config().unwrap();
    assert_eq!(cfg.jwt.issuer, "from-lookup");
    assert_eq!(cfg.authz.mode, AuthzMode::Permissions);
}

#[test]
fn hosts_can_read_their_own_sections() {
    const PORT: Key = Key::new("APP_PORT", "server.port");
    let source = ConfigSource::yaml_str(FULL).unwrap();
    let port = source.get(&PORT).unwrap();
    assert_eq!(port.value, "8080");
    assert_eq!(port.origin, "server.port in YAML");

    let source = source.with_lookup(lookup(&[("APP_PORT", "9090")]));
    assert_eq!(source.get(&PORT).unwrap().value, "9090");
    assert_eq!(source.get(&PORT).unwrap().origin, "APP_PORT");
}

#[test]
fn yaml_file_and_auth_config_file() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join("z-auth-config-source-test.yaml");
    std::fs::write(&path, "auth:\n  jwt:\n    issuer: from-file\n").unwrap();

    let cfg = SourceLoader::new(ConfigSource::yaml_file(&path).unwrap())
        .load_config()
        .unwrap();
    assert_eq!(cfg.jwt.issuer, "from-file");

    let missing = ConfigSource::yaml_file(dir.join("does-not-exist.yaml"));
    assert!(parse_error_key(missing).ends_with("does-not-exist.yaml"));

    // SAFETY: this is the only test in this binary that touches the process
    // environment, and it only uses AUTH_CONFIG_FILE / AUTH_JWT_ISSUER.
    unsafe { std::env::set_var(ENV_CONFIG_FILE, &path) };
    let from_file = SourceLoader::new(ConfigSource::standard().unwrap()).load_config();
    unsafe { std::env::set_var(ENV_JWT_ISSUER, "env-wins") };
    let overridden = SourceLoader::new(ConfigSource::standard().unwrap()).load_config();
    unsafe { std::env::remove_var(ENV_CONFIG_FILE) };
    let env_only = EnvLoader.load_config();
    unsafe { std::env::remove_var(ENV_JWT_ISSUER) };

    assert_eq!(from_file.unwrap().jwt.issuer, "from-file");
    assert_eq!(overridden.unwrap().jwt.issuer, "env-wins");
    assert_eq!(env_only.unwrap().jwt.issuer, "env-wins");
}
