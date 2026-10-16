//! z-auth-sso constants: defaults, environment variables and their paths in
//! the configuration file.

use z_auth::conf::config::Key;

// ── Defaults ──────────────────────────────────────────────────────────────────

/// How long a redirect to an identity provider stays valid: 10 minutes.
pub const DEFAULT_FLOW_TTL_SECS: u64 = 600;

/// Timeout of each request to an identity provider.
pub const HTTP_TIMEOUT_SECS: u64 = 10;

/// `User-Agent` sent to identity providers (GitHub's API requires one).
pub const USER_AGENT: &str = concat!("z-auth-sso/", env!("CARGO_PKG_VERSION"));

/// Discovery documents and key sets are re-read after a day.
pub const METADATA_MAX_AGE_SECS: u64 = 86_400;

/// An ID token signed by an unknown key re-reads the key set at most this
/// often.
pub const JWKS_MIN_REFRESH_SECS: u64 = 60;

/// Clock-skew tolerance when checking an ID token's `exp`, `nbf` and `iat`.
pub const ID_TOKEN_LEEWAY_SECS: u64 = 60;

/// Random bytes in `state`, nonce, PKCE verifier and browser binding.
pub const SECRET_LEN: usize = 32;

/// Flow-state kind of a pending redirect.
pub const FLOW_SSO: &str = "sso";

/// Default scopes per kind.
pub const OIDC_SCOPES: &[&str] = &["openid", "email", "profile"];
pub const GITHUB_SCOPES: &[&str] = &["read:user", "user:email"];

/// GitHub's endpoints and the issuer its identities are recorded under.
pub const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
pub const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
pub const GITHUB_USERINFO_URL: &str = "https://api.github.com/user";
pub const GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";
pub const GITHUB_ISSUER: &str = "https://github.com";

// ── Environment variables and file paths ──────────────────────────────────────

/// The crate's top-level section in the configuration file.
pub const SECTION: &str = "sso";

/// Where providers are configured in the file, one mapping per provider.
pub const PROVIDERS_PATH: &str = "sso.providers";

pub const ENV_SSO_CALLBACK_URL: &str = "AUTH_SSO_CALLBACK_URL";
pub const ENV_SSO_FLOW_TTL_SECS: &str = "AUTH_SSO_FLOW_TTL_SECS";
/// Comma-separated provider names configured through the environment only
/// (each setting then comes from `AUTH_SSO_<NAME>_<SETTING>`).
pub const ENV_SSO_PROVIDERS: &str = "AUTH_SSO_PROVIDERS";

/// Prefix of a provider's variables: `AUTH_SSO_<NAME>_<SETTING>`, the
/// setting upper-cased with `.` as `_` (e.g. `AUTH_SSO_GOOGLE_CLIENT_SECRET`,
/// `AUTH_SSO_ACME_CLAIMS_EMAIL`).
pub const ENV_SSO_PROVIDER_PREFIX: &str = "AUTH_SSO_";

pub const KEYS: &[Key] = &[
    Key::new(ENV_SSO_CALLBACK_URL, "sso.callback_url"),
    Key::new(ENV_SSO_FLOW_TTL_SECS, "sso.flow_ttl_secs"),
];

// ── Provider settings (relative to `sso.providers.<name>`) ───────────────────

pub const P_KIND: &str = "kind";
pub const P_DISPLAY_NAME: &str = "display_name";
pub const P_CLIENT_ID: &str = "client_id";
pub const P_CLIENT_SECRET: &str = "client_secret";
pub const P_SCOPES: &str = "scopes";
pub const P_LINK: &str = "link";
pub const P_PROVISIONING: &str = "provisioning";
pub const P_TRUST_EMAIL: &str = "trust_email";
pub const P_TRUST_AMR: &str = "trust_amr";
pub const P_MAX_LINKS: &str = "max_links";
pub const P_ISSUER: &str = "issuer";
pub const P_AUTHORIZE_URL: &str = "authorize_url";
pub const P_TOKEN_URL: &str = "token_url";
pub const P_USERINFO_URL: &str = "userinfo_url";
pub const P_EMAILS_URL: &str = "emails_url";
pub const P_TOKEN_AUTH: &str = "token_auth";
pub const P_PKCE: &str = "pkce";
pub const P_CLAIM_SUBJECT: &str = "claims.subject";
pub const P_CLAIM_EMAIL: &str = "claims.email";
pub const P_CLAIM_EMAIL_VERIFIED: &str = "claims.email_verified";
pub const P_CLAIM_USERNAME: &str = "claims.username";
pub const P_CLAIM_FIRST_NAME: &str = "claims.first_name";
pub const P_CLAIM_LAST_NAME: &str = "claims.last_name";

/// Settings every kind accepts.
pub const COMMON_KEYS: &[&str] = &[
    P_KIND,
    P_DISPLAY_NAME,
    P_CLIENT_ID,
    P_CLIENT_SECRET,
    P_SCOPES,
    P_LINK,
    P_PROVISIONING,
    P_TRUST_EMAIL,
    P_TRUST_AMR,
    P_MAX_LINKS,
];

/// Settings of `kind: oidc` besides the common ones.
pub const OIDC_KEYS: &[&str] = &[P_ISSUER, P_TOKEN_AUTH];

/// Settings of `kind: oauth2` besides the common ones.
pub const OAUTH2_KEYS: &[&str] = &[
    P_ISSUER,
    P_AUTHORIZE_URL,
    P_TOKEN_URL,
    P_USERINFO_URL,
    P_TOKEN_AUTH,
    P_PKCE,
    P_CLAIM_SUBJECT,
    P_CLAIM_EMAIL,
    P_CLAIM_EMAIL_VERIFIED,
    P_CLAIM_USERNAME,
    P_CLAIM_FIRST_NAME,
    P_CLAIM_LAST_NAME,
];

/// Settings of `kind: github` besides the common ones (endpoint overrides,
/// e.g. for GitHub Enterprise Server).
pub const GITHUB_KEYS: &[&str] = &[P_AUTHORIZE_URL, P_TOKEN_URL, P_USERINFO_URL, P_EMAILS_URL];
