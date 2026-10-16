//! OpenID Connect providers (`kind: oidc`): Google, LinkedIn, Okta, Auth0,
//! Keycloak, GitLab, Entra ID (single tenant), …
//!
//! Endpoints come from the issuer's discovery document, whose `issuer` must
//! equal the configured one.  The ID token must be signed with an
//! asymmetric key from the provider's JWKS, name the configured issuer,
//! have this client among its audiences (and as `azp` when there are
//! several), be current, and carry the nonce of the redirect.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use z_auth::AuthError;
use z_auth::identity::external::{ExternalPrincipal, ProviderPolicy};

use crate::config::loaders::secure_url;
use crate::config::{ProviderKind, ProviderSettings, TokenAuth};
use crate::constants::{ID_TOKEN_LEEWAY_SECS, JWKS_MIN_REFRESH_SECS, METADATA_MAX_AGE_SECS};
use crate::http::{bool_at, exchange_code, failed, get_json, sha256_b64, text_at, unavailable};
use crate::provider::{AuthorizationRequest, IdentityProvider, with_query};

/// Signature algorithms accepted on ID tokens: asymmetric only, so a
/// token can never be "signed" with a public key used as an HMAC secret.
const ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// An OpenID Connect provider.
pub struct OidcProvider {
    settings: ProviderSettings,
    issuer: String,
    token_auth: Option<TokenAuth>,
    http: reqwest::Client,
    metadata: Mutex<Option<(Arc<Metadata>, Instant)>>,
    keys: Mutex<Option<(Arc<Vec<Jwk>>, Instant)>>,
}

/// The parts of the discovery document z-auth uses.
#[derive(Debug, Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Deserialize)]
struct IdClaims {
    sub: String,
    aud: Value,
    azp: Option<String>,
    nonce: Option<String>,
    #[serde(default)]
    amr: Vec<String>,
}

impl OidcProvider {
    /// # Panics
    /// If `settings.kind` is not `oidc`.
    pub fn new(settings: ProviderSettings, http: reqwest::Client) -> Self {
        let ProviderKind::Oidc(endpoints) = &settings.kind else {
            panic!("OidcProvider needs kind oidc");
        };
        Self {
            issuer: endpoints.issuer.clone(),
            token_auth: endpoints.token_auth,
            settings,
            http,
            metadata: Mutex::new(None),
            keys: Mutex::new(None),
        }
    }

    /// The discovery document, read again after a day.
    async fn metadata(&self) -> Result<Arc<Metadata>, AuthError> {
        if let Some((m, at)) = self.metadata.lock().unwrap().as_ref()
            && at.elapsed() < Duration::from_secs(METADATA_MAX_AGE_SECS)
        {
            return Ok(m.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| unavailable("discovery", e))?;
        if !response.status().is_success() {
            return Err(unavailable("discovery", response.status()));
        }
        let metadata: Metadata = response
            .json()
            .await
            .map_err(|e| unavailable("discovery", e))?;
        if metadata.issuer != self.issuer {
            return Err(AuthError::Config(format!(
                "provider {}: the discovery document names issuer {} instead of {}",
                self.settings.name, metadata.issuer, self.issuer
            )));
        }
        for endpoint in [
            &metadata.authorization_endpoint,
            &metadata.token_endpoint,
            &metadata.jwks_uri,
        ]
        .into_iter()
        .chain(&metadata.userinfo_endpoint)
        {
            secure_url("discovery", endpoint)
                .map_err(|e| AuthError::Config(format!("provider {}: {e}", self.settings.name)))?;
        }
        let metadata = Arc::new(metadata);
        *self.metadata.lock().unwrap() = Some((metadata.clone(), Instant::now()));
        Ok(metadata)
    }

    /// The provider's signing keys.  `refresh` re-reads them (an unknown
    /// `kid` after a key rotation), at most once a minute.
    async fn keys(&self, refresh: bool) -> Result<Arc<Vec<Jwk>>, AuthError> {
        if let Some((keys, at)) = self.keys.lock().unwrap().as_ref() {
            let age = at.elapsed();
            let stale = age >= Duration::from_secs(METADATA_MAX_AGE_SECS);
            let may_refresh = age >= Duration::from_secs(JWKS_MIN_REFRESH_SECS);
            if !stale && !(refresh && may_refresh) {
                return Ok(keys.clone());
            }
        }
        let metadata = self.metadata().await?;
        let response = self
            .http
            .get(&metadata.jwks_uri)
            .send()
            .await
            .map_err(|e| unavailable("key set", e))?;
        if !response.status().is_success() {
            return Err(unavailable("key set", response.status()));
        }
        let set: Value = response
            .json()
            .await
            .map_err(|e| unavailable("key set", e))?;
        // Keys this library cannot read (e.g. for encryption) are skipped,
        // not fatal.
        let keys: Vec<Jwk> = set
            .get("keys")
            .and_then(Value::as_array)
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| serde_json::from_value(k.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        let keys = Arc::new(keys);
        *self.keys.lock().unwrap() = Some((keys.clone(), Instant::now()));
        Ok(keys)
    }

    /// The signing key for `kid` (or the only one, when the token names
    /// none).
    async fn key_for(&self, kid: Option<&str>, alg: Algorithm) -> Result<Jwk, AuthError> {
        let pick = |keys: &[Jwk]| -> Option<Jwk> {
            let usable: Vec<&Jwk> = keys
                .iter()
                .filter(|k| {
                    !matches!(k.common.public_key_use, Some(ref u) if *u != PublicKeyUse::Signature)
                })
                .filter(|k| {
                    k.common
                        .key_algorithm
                        .is_none_or(|ka| format!("{ka:?}") == format!("{alg:?}"))
                })
                .collect();
            match kid {
                Some(kid) => usable
                    .into_iter()
                    .find(|k| k.common.key_id.as_deref() == Some(kid))
                    .cloned(),
                None if usable.len() == 1 => Some(usable[0].clone()),
                None => None,
            }
        };
        if let Some(key) = pick(&self.keys(false).await?) {
            return Ok(key);
        }
        pick(&self.keys(true).await?)
            .ok_or_else(|| failed("the ID token is signed with an unknown key"))
    }

    async fn verify_id_token(
        &self,
        id_token: &str,
        nonce: &str,
    ) -> Result<(IdClaims, Value), AuthError> {
        let header = decode_header(id_token).map_err(|e| failed(format!("bad ID token: {e}")))?;
        if !ALGORITHMS.contains(&header.alg) {
            return Err(failed(format!(
                "the ID token's algorithm {:?} is not accepted",
                header.alg
            )));
        }
        let jwk = self.key_for(header.kid.as_deref(), header.alg).await?;
        let key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| failed(format!("unusable signing key: {e}")))?;
        if key.family() != header.alg.family() {
            return Err(failed("the ID token's algorithm does not fit its key"));
        }
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.settings.client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = ID_TOKEN_LEEWAY_SECS;
        let raw = decode::<Value>(id_token, &key, &validation)
            .map_err(|e| failed(format!("the ID token was refused: {e}")))?
            .claims;
        let claims: IdClaims = serde_json::from_value(raw.clone())
            .map_err(|e| failed(format!("unexpected ID token claims: {e}")))?;

        if claims.nonce.as_deref() != Some(nonce) {
            return Err(failed("the ID token's nonce does not match"));
        }
        let audiences = match &claims.aud {
            Value::Array(a) => a.len(),
            _ => 1,
        };
        let azp_ok = match &claims.azp {
            Some(azp) => *azp == self.settings.client_id,
            None => audiences == 1,
        };
        if !azp_ok {
            return Err(failed("the ID token was issued to another client (azp)"));
        }
        if claims.sub.trim().is_empty() {
            return Err(failed("the ID token has no subject"));
        }
        Ok((claims, raw))
    }

    fn token_auth(&self, metadata: &Metadata) -> TokenAuth {
        self.token_auth.unwrap_or_else(|| {
            let methods = &metadata.token_endpoint_auth_methods_supported;
            // The spec's default is client_secret_basic.
            if methods.is_empty() || methods.iter().any(|m| m == "client_secret_basic") {
                TokenAuth::Basic
            } else {
                TokenAuth::Post
            }
        })
    }
}

#[async_trait]
impl IdentityProvider for OidcProvider {
    fn name(&self) -> &str {
        &self.settings.name
    }

    fn display_name(&self) -> &str {
        &self.settings.display_name
    }

    fn policy(&self) -> ProviderPolicy {
        self.settings.policy
    }

    async fn authorization_url(
        &self,
        request: AuthorizationRequest<'_>,
    ) -> Result<String, AuthError> {
        let metadata = self.metadata().await?;
        let scope = self.settings.scopes.join(" ");
        let challenge = sha256_b64(request.pkce_verifier);
        with_query(
            &metadata.authorization_endpoint,
            &[
                ("response_type", "code"),
                ("client_id", &self.settings.client_id),
                ("redirect_uri", request.redirect_uri),
                ("scope", &scope),
                ("state", request.state),
                ("nonce", request.nonce),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ],
        )
    }

    async fn exchange(
        &self,
        code: &str,
        request: AuthorizationRequest<'_>,
    ) -> Result<ExternalPrincipal, AuthError> {
        let metadata = self.metadata().await?;
        let tokens = exchange_code(
            &self.http,
            &metadata.token_endpoint,
            self.token_auth(&metadata),
            &self.settings.client_id,
            self.settings.client_secret.as_deref(),
            code,
            request.redirect_uri,
            Some(request.pkce_verifier),
        )
        .await?;
        let id_token = tokens
            .id_token
            .ok_or_else(|| failed("the provider returned no ID token"))?;
        let (claims, mut info) = self.verify_id_token(&id_token, request.nonce).await?;

        // The ID token may leave the profile to the user-info endpoint.
        if info.get("email").is_none()
            && let (Some(url), Some(access_token)) =
                (&metadata.userinfo_endpoint, &tokens.access_token)
        {
            let extra = get_json(&self.http, url, access_token, "user-info endpoint").await?;
            if text_at(&extra, "/sub").as_deref() != Some(claims.sub.as_str()) {
                return Err(failed("the user info belongs to another subject"));
            }
            if let (Value::Object(info), Value::Object(extra)) = (&mut info, extra) {
                for (k, v) in extra {
                    info.entry(k).or_insert(v);
                }
            }
        }

        let mut principal = ExternalPrincipal::new(&self.settings.name, &self.issuer, &claims.sub);
        if let Some(email) = text_at(&info, "/email") {
            principal = principal.with_email(email, bool_at(&info, "/email_verified"));
        }
        principal.username = text_at(&info, "/preferred_username");
        principal.first_name = text_at(&info, "/given_name");
        principal.last_name = text_at(&info, "/family_name");
        if self.settings.trust_amr {
            principal.amr = claims.amr;
        }
        Ok(principal)
    }
}
