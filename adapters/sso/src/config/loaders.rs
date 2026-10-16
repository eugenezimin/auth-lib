//! z-auth-sso configuration loaders: [`SsoEnvLoader`] (environment),
//! [`SsoSourceLoader`] (the `sso` section of a YAML file and / or the
//! environment) and [`SsoDirectLoader`] (a pre-filled [`RawSsoConfig`]),
//! plus the validation behind [`RawSsoConfig::build`].
//!
//! Providers live under `sso.providers.<name>`, one mapping each; every
//! setting can be overridden (or, with `AUTH_SSO_PROVIDERS`, given only)
//! through `AUTH_SSO_<NAME>_<SETTING>`:
//!
//! ```rust,no_run
//! use z_auth::conf::config::ConfigSource;
//! use z_auth_sso::config::{SsoConfigLoader, SsoSourceLoader};
//!
//! // AUTH_CONFIG_FILE's `sso` section, with the environment on top
//! // (client secrets typically come from AUTH_SSO_<NAME>_CLIENT_SECRET).
//! let source = ConfigSource::standard().expect("config file");
//! let settings = SsoSourceLoader::new(source).load_settings().expect("sso config");
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use z_auth::conf::config::{ConfigError, ConfigSource, Setting};
use z_auth::identity::external::{LinkPolicy, ProviderPolicy, Provisioning};

use crate::config::model::{
    ClaimMap, GitHubEndpoints, OAuth2Endpoints, OidcEndpoints, ProviderKind, ProviderSettings,
    RawProvider, RawSsoConfig, SsoSettings, TokenAuth,
};
use crate::constants::*;

/// Any source of a [`RawSsoConfig`].
pub trait SsoConfigLoader: Send + Sync {
    fn load(&self) -> Result<RawSsoConfig, ConfigError>;

    /// Load and validate into [`SsoSettings`].
    fn load_settings(&self) -> Result<SsoSettings, ConfigError> {
        self.load()?.build()
    }
}

/// Reads the `AUTH_SSO_*` environment variables (providers named by
/// `AUTH_SSO_PROVIDERS`).  Same as `SsoSourceLoader::new(ConfigSource::env())`.
pub struct SsoEnvLoader;

/// Reads the `sso` section of a [`ConfigSource`]; the environment overrides
/// the file.
pub struct SsoSourceLoader {
    pub source: ConfigSource,
}

impl SsoSourceLoader {
    pub fn new(source: ConfigSource) -> Self {
        Self { source }
    }
}

/// A caller-supplied [`RawSsoConfig`].
pub struct SsoDirectLoader {
    pub raw_config: RawSsoConfig,
}

impl SsoDirectLoader {
    pub fn new(raw_config: RawSsoConfig) -> Self {
        Self { raw_config }
    }
}

impl SsoConfigLoader for SsoDirectLoader {
    fn load(&self) -> Result<RawSsoConfig, ConfigError> {
        Ok(self.raw_config.clone())
    }
}

impl SsoConfigLoader for SsoEnvLoader {
    fn load(&self) -> Result<RawSsoConfig, ConfigError> {
        SsoSourceLoader::new(ConfigSource::env()).load()
    }
}

impl SsoConfigLoader for SsoSourceLoader {
    fn load(&self) -> Result<RawSsoConfig, ConfigError> {
        let s = self.source.section(SECTION, KEYS, &[PROVIDERS_PATH])?;
        let flow_ttl_secs = match s.get(ENV_SSO_FLOW_TTL_SECS) {
            None => None,
            Some(v) => Some(parse(&v)?),
        };

        // Named in the file, or through the environment alone.
        let mut names: BTreeSet<String> =
            self.source.children(PROVIDERS_PATH).into_iter().collect();
        if let Some(listed) = self.source.get_env(ENV_SSO_PROVIDERS) {
            names.extend(
                listed
                    .value
                    .split(',')
                    .map(|n| n.trim().to_string())
                    .filter(|n| !n.is_empty()),
            );
        }
        let all: Vec<&str> = COMMON_KEYS
            .iter()
            .chain(OIDC_KEYS)
            .chain(OAUTH2_KEYS)
            .chain(GITHUB_KEYS)
            .copied()
            .collect();
        let mut providers = Vec::new();
        for name in names {
            check_name(&name)?;
            let path = format!("{PROVIDERS_PATH}.{name}");
            self.source.check_keys(&path, &all)?;
            let mut settings = BTreeMap::new();
            for key in &all {
                let env = provider_env(&name, key);
                let setting = self
                    .source
                    .get_env(&env)
                    .or_else(|| self.source.get_file(&format!("{path}.{key}")));
                if let Some(setting) = setting {
                    settings.insert(key.to_string(), setting);
                }
            }
            providers.push(RawProvider { name, settings });
        }

        Ok(RawSsoConfig {
            callback_url: s.get(ENV_SSO_CALLBACK_URL).map(|v| v.value),
            flow_ttl_secs,
            providers,
        })
    }
}

/// `AUTH_SSO_<NAME>_<SETTING>`, e.g. `AUTH_SSO_GOOGLE_CLAIMS_EMAIL`.
pub fn provider_env(name: &str, key: &str) -> String {
    format!(
        "{ENV_SSO_PROVIDER_PREFIX}{}_{}",
        name.to_ascii_uppercase(),
        key.replace('.', "_").to_ascii_uppercase()
    )
}

/// Provider names become variable names: `[a-z][a-z0-9_]*`.
fn check_name(name: &str) -> Result<(), ConfigError> {
    let valid = name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && name.len() <= 64;
    if valid {
        Ok(())
    } else {
        Err(ConfigError::Parse {
            key: format!("{PROVIDERS_PATH}.{name}"),
            reason: "provider names must match [a-z][a-z0-9_]* (at most 64 characters)".into(),
        })
    }
}

fn parse<T>(v: &Setting) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    v.value.trim().parse::<T>().map_err(|e| ConfigError::Parse {
        key: v.origin.clone(),
        reason: e.to_string(),
    })
}

// ── Validation ────────────────────────────────────────────────────────────────

impl RawSsoConfig {
    /// Validate and convert into [`SsoSettings`].
    pub fn build(self) -> Result<SsoSettings, ConfigError> {
        let callback_url = self
            .callback_url
            .ok_or_else(|| ConfigError::Missing(ENV_SSO_CALLBACK_URL.into()))?;
        let callback_url = secure_url(ENV_SSO_CALLBACK_URL, &callback_url)?;
        let flow_ttl = Duration::from_secs(self.flow_ttl_secs.unwrap_or(DEFAULT_FLOW_TTL_SECS));
        if flow_ttl.is_zero() {
            return Err(ConfigError::Parse {
                key: ENV_SSO_FLOW_TTL_SECS.into(),
                reason: "must be positive".into(),
            });
        }
        let mut seen = BTreeSet::new();
        let mut providers = Vec::new();
        for raw in self.providers {
            check_name(&raw.name)?;
            if !seen.insert(raw.name.clone()) {
                return Err(ConfigError::Parse {
                    key: format!("{PROVIDERS_PATH}.{}", raw.name),
                    reason: "configured twice".into(),
                });
            }
            providers.push(Provider(&raw).build()?);
        }
        Ok(SsoSettings {
            callback_url,
            flow_ttl,
            providers,
        })
    }
}

/// One raw provider being validated.
struct Provider<'a>(&'a RawProvider);

impl Provider<'_> {
    fn origin(&self, key: &str) -> String {
        format!("{PROVIDERS_PATH}.{}.{key}", self.0.name)
    }

    fn get(&self, key: &str) -> Option<&Setting> {
        self.0
            .settings
            .get(key)
            .filter(|s| !s.value.trim().is_empty())
    }

    fn string(&self, key: &str) -> Option<String> {
        self.get(key).map(|s| s.value.trim().to_string())
    }

    fn required(&self, key: &str) -> Result<String, ConfigError> {
        self.string(key)
            .ok_or_else(|| ConfigError::Missing(self.origin(key)))
    }

    fn parsed<T>(&self, key: &str) -> Result<Option<T>, ConfigError>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        self.get(key).map(parse).transpose()
    }

    fn bool(&self, key: &str) -> Result<Option<bool>, ConfigError> {
        match self.get(key) {
            None => Ok(None),
            Some(s) => match s.value.trim() {
                "true" => Ok(Some(true)),
                "false" => Ok(Some(false)),
                _ => Err(ConfigError::Parse {
                    key: s.origin.clone(),
                    reason: "expected true or false".into(),
                }),
            },
        }
    }

    fn url(&self, key: &str) -> Result<Option<String>, ConfigError> {
        self.get(key)
            .map(|s| secure_url(&s.origin, &s.value))
            .transpose()
    }

    fn url_or(&self, key: &str, default: &str) -> Result<String, ConfigError> {
        Ok(self.url(key)?.unwrap_or_else(|| default.to_string()))
    }

    fn required_url(&self, key: &str) -> Result<String, ConfigError> {
        self.url(key)?
            .ok_or_else(|| ConfigError::Missing(self.origin(key)))
    }

    /// Fails on a set setting that `kind` does not use.
    fn only(&self, kind: &str, extra: &[&str]) -> Result<(), ConfigError> {
        match self
            .0
            .settings
            .iter()
            .find(|(k, _)| !COMMON_KEYS.contains(&k.as_str()) && !extra.contains(&k.as_str()))
        {
            Some((_, s)) => Err(ConfigError::Parse {
                key: s.origin.clone(),
                reason: format!("not a setting of kind `{kind}`"),
            }),
            None => Ok(()),
        }
    }

    fn build(&self) -> Result<ProviderSettings, ConfigError> {
        let kind_name = self.required(P_KIND)?.to_ascii_lowercase();
        let kind = match kind_name.as_str() {
            "oidc" => {
                self.only("oidc", OIDC_KEYS)?;
                if !cfg!(feature = "oidc") {
                    return Err(feature_error(self, "oidc"));
                }
                ProviderKind::Oidc(OidcEndpoints {
                    issuer: self.required_url(P_ISSUER)?,
                    token_auth: self.parsed(P_TOKEN_AUTH)?,
                })
            }
            "oauth2" => {
                self.only("oauth2", OAUTH2_KEYS)?;
                ProviderKind::OAuth2(OAuth2Endpoints {
                    issuer: self.required(P_ISSUER)?,
                    authorize_url: self.required_url(P_AUTHORIZE_URL)?,
                    token_url: self.required_url(P_TOKEN_URL)?,
                    userinfo_url: self.required_url(P_USERINFO_URL)?,
                    token_auth: self.parsed(P_TOKEN_AUTH)?.unwrap_or(TokenAuth::Post),
                    pkce: self.bool(P_PKCE)?.unwrap_or(true),
                    claims: ClaimMap {
                        subject: self
                            .pointer(P_CLAIM_SUBJECT)?
                            .ok_or_else(|| ConfigError::Missing(self.origin(P_CLAIM_SUBJECT)))?,
                        email: self.pointer(P_CLAIM_EMAIL)?,
                        email_verified: self.pointer(P_CLAIM_EMAIL_VERIFIED)?,
                        username: self.pointer(P_CLAIM_USERNAME)?,
                        first_name: self.pointer(P_CLAIM_FIRST_NAME)?,
                        last_name: self.pointer(P_CLAIM_LAST_NAME)?,
                    },
                })
            }
            "github" => {
                self.only("github", GITHUB_KEYS)?;
                if !cfg!(feature = "github") {
                    return Err(feature_error(self, "github"));
                }
                ProviderKind::GitHub(GitHubEndpoints {
                    authorize_url: self.url_or(P_AUTHORIZE_URL, GITHUB_AUTHORIZE_URL)?,
                    token_url: self.url_or(P_TOKEN_URL, GITHUB_TOKEN_URL)?,
                    userinfo_url: self.url_or(P_USERINFO_URL, GITHUB_USERINFO_URL)?,
                    emails_url: self.url_or(P_EMAILS_URL, GITHUB_EMAILS_URL)?,
                })
            }
            other => {
                return Err(ConfigError::Parse {
                    key: self.origin(P_KIND),
                    reason: format!("unknown kind '{other}' (expected oidc, oauth2 or github)"),
                });
            }
        };

        let client_secret = self.string(P_CLIENT_SECRET);
        if matches!(kind, ProviderKind::GitHub(_)) && client_secret.is_none() {
            return Err(ConfigError::Missing(self.origin(P_CLIENT_SECRET)));
        }
        let mut scopes = match self.string(P_SCOPES) {
            Some(list) => list
                .split([',', ' '])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            None => match &kind {
                ProviderKind::Oidc(_) => OIDC_SCOPES.iter().map(|s| s.to_string()).collect(),
                ProviderKind::GitHub(_) => GITHUB_SCOPES.iter().map(|s| s.to_string()).collect(),
                ProviderKind::OAuth2(_) => Vec::new(),
            },
        };
        if matches!(kind, ProviderKind::Oidc(_)) && !scopes.iter().any(|s| s == "openid") {
            scopes.insert(0, "openid".into());
        }
        // GitHub's verified flag comes from its own API and can be relied on.
        let trust_email_default = matches!(kind, ProviderKind::GitHub(_));
        let policy = ProviderPolicy {
            link: self.parsed::<LinkPolicy>(P_LINK)?.unwrap_or_default(),
            provisioning: self
                .parsed::<Provisioning>(P_PROVISIONING)?
                .unwrap_or_default(),
            trust_email: self.bool(P_TRUST_EMAIL)?.unwrap_or(trust_email_default),
            max_links: self.parsed(P_MAX_LINKS)?.unwrap_or(1),
        };

        Ok(ProviderSettings {
            name: self.0.name.clone(),
            display_name: self
                .string(P_DISPLAY_NAME)
                .unwrap_or_else(|| self.0.name.clone()),
            client_id: self.required(P_CLIENT_ID)?,
            client_secret,
            scopes,
            policy,
            trust_amr: self.bool(P_TRUST_AMR)?.unwrap_or(false),
            kind,
        })
    }

    /// A JSON pointer: empty, or starting with `/`.
    fn pointer(&self, key: &str) -> Result<Option<String>, ConfigError> {
        match self.get(key) {
            None => Ok(None),
            Some(s) => {
                let v = s.value.trim();
                if v.starts_with('/') {
                    Ok(Some(v.to_string()))
                } else {
                    Err(ConfigError::Parse {
                        key: s.origin.clone(),
                        reason: "expected a JSON pointer such as /email".into(),
                    })
                }
            }
        }
    }
}

fn feature_error(p: &Provider<'_>, feature: &str) -> ConfigError {
    ConfigError::Parse {
        key: p.origin(P_KIND),
        reason: format!("kind `{feature}` needs z-auth-sso's `{feature}` feature"),
    }
}

/// An `https` URL, or `http` on the loopback interface (development).
pub(crate) fn secure_url(origin: &str, value: &str) -> Result<String, ConfigError> {
    let value = value.trim();
    let bad = |reason: &str| ConfigError::Parse {
        key: origin.to_string(),
        reason: reason.to_string(),
    };
    let url = reqwest::Url::parse(value).map_err(|e| bad(&format!("invalid URL: {e}")))?;
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    match url.scheme() {
        "https" => Ok(value.to_string()),
        "http" if loopback => Ok(value.to_string()),
        _ => Err(bad("must be an https URL (http only on localhost)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_variables_name_the_setting() {
        assert_eq!(
            provider_env("google", "client_secret"),
            "AUTH_SSO_GOOGLE_CLIENT_SECRET"
        );
        assert_eq!(
            provider_env("acme", "claims.email"),
            "AUTH_SSO_ACME_CLAIMS_EMAIL"
        );
    }

    #[test]
    fn urls_must_be_https_outside_localhost() {
        assert!(secure_url("k", "https://accounts.google.com").is_ok());
        assert!(secure_url("k", "http://127.0.0.1:8080/x").is_ok());
        assert!(secure_url("k", "http://localhost/x").is_ok());
        assert!(secure_url("k", "http://idp.example.com").is_err());
        assert!(secure_url("k", "ftp://idp.example.com").is_err());
        assert!(secure_url("k", "not a url").is_err());
    }

    #[test]
    fn names_are_variable_friendly() {
        assert!(check_name("google").is_ok());
        assert!(check_name("my_idp2").is_ok());
        assert!(check_name("Google").is_err());
        assert!(check_name("my-idp").is_err());
        assert!(check_name("2fa").is_err());
    }
}
