//! Plain OAuth2 providers (`kind: oauth2`) and the GitHub preset
//! (`kind: github`): the access token reads a user-info endpoint, whose
//! fields are mapped to the principal.

use async_trait::async_trait;
use serde::Deserialize;
use z_auth::AuthError;
use z_auth::identity::external::{ExternalPrincipal, ProviderPolicy};

use crate::config::{ClaimMap, ProviderKind, ProviderSettings, TokenAuth};
use crate::constants::GITHUB_ISSUER;
use crate::http::{bool_at, exchange_code, failed, get_json, sha256_b64, text_at};
use crate::provider::{AuthorizationRequest, IdentityProvider, with_query};

/// A provider without ID tokens.  Its identities are recorded under the
/// configured `issuer` (GitHub: `https://github.com`).
pub struct OAuth2Provider {
    settings: ProviderSettings,
    endpoints: Endpoints,
    http: reqwest::Client,
}

struct Endpoints {
    issuer: String,
    authorize_url: String,
    token_url: String,
    userinfo_url: String,
    token_auth: TokenAuth,
    pkce: bool,
    claims: ClaimMap,
    /// GitHub: where the verified email addresses are listed.
    emails_url: Option<String>,
}

impl OAuth2Provider {
    /// # Panics
    /// If `settings.kind` is neither `oauth2` nor `github`.
    pub fn new(settings: ProviderSettings, http: reqwest::Client) -> Self {
        let endpoints = match &settings.kind {
            ProviderKind::OAuth2(e) => Endpoints {
                issuer: e.issuer.clone(),
                authorize_url: e.authorize_url.clone(),
                token_url: e.token_url.clone(),
                userinfo_url: e.userinfo_url.clone(),
                token_auth: e.token_auth,
                pkce: e.pkce,
                claims: e.claims.clone(),
                emails_url: None,
            },
            ProviderKind::GitHub(e) => Endpoints {
                issuer: GITHUB_ISSUER.into(),
                authorize_url: e.authorize_url.clone(),
                token_url: e.token_url.clone(),
                userinfo_url: e.userinfo_url.clone(),
                token_auth: TokenAuth::Post,
                // GitHub supports PKCE for OAuth apps.
                pkce: true,
                claims: ClaimMap {
                    subject: "/id".into(),
                    email: None,
                    email_verified: None,
                    username: Some("/login".into()),
                    first_name: None,
                    last_name: None,
                },
                emails_url: Some(e.emails_url.clone()),
            },
            ProviderKind::Oidc(_) => panic!("OAuth2Provider needs kind oauth2 or github"),
        };
        Self {
            settings,
            endpoints,
            http,
        }
    }

    /// GitHub: the primary address if verified, else any verified one.
    async fn github_email(
        &self,
        url: &str,
        access_token: &str,
    ) -> Result<Option<String>, AuthError> {
        #[derive(Deserialize)]
        struct Email {
            email: String,
            #[serde(default)]
            primary: bool,
            #[serde(default)]
            verified: bool,
        }
        let json = get_json(&self.http, url, access_token, "email endpoint").await?;
        let emails: Vec<Email> = serde_json::from_value(json)
            .map_err(|e| failed(format!("unexpected email list: {e}")))?;
        let verified = |e: &&Email| e.verified;
        Ok(emails
            .iter()
            .filter(verified)
            .find(|e| e.primary)
            .or_else(|| emails.iter().find(|e| e.verified))
            .map(|e| e.email.clone()))
    }
}

#[async_trait]
impl IdentityProvider for OAuth2Provider {
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
        let scope = self.settings.scopes.join(" ");
        let challenge = sha256_b64(request.pkce_verifier);
        let mut params = vec![
            ("response_type", "code"),
            ("client_id", self.settings.client_id.as_str()),
            ("redirect_uri", request.redirect_uri),
            ("state", request.state),
        ];
        if !scope.is_empty() {
            params.push(("scope", &scope));
        }
        if self.endpoints.pkce {
            params.push(("code_challenge", &challenge));
            params.push(("code_challenge_method", "S256"));
        }
        with_query(&self.endpoints.authorize_url, &params)
    }

    async fn exchange(
        &self,
        code: &str,
        request: AuthorizationRequest<'_>,
    ) -> Result<ExternalPrincipal, AuthError> {
        let e = &self.endpoints;
        let tokens = exchange_code(
            &self.http,
            &e.token_url,
            e.token_auth,
            &self.settings.client_id,
            self.settings.client_secret.as_deref(),
            code,
            request.redirect_uri,
            e.pkce.then_some(request.pkce_verifier),
        )
        .await?;
        let access_token = tokens
            .access_token
            .ok_or_else(|| failed("the provider returned no access token"))?;
        let info = get_json(
            &self.http,
            &e.userinfo_url,
            &access_token,
            "user-info endpoint",
        )
        .await?;

        let c = &e.claims;
        let subject = text_at(&info, &c.subject)
            .ok_or_else(|| failed("the provider's user info has no subject"))?;
        let mut principal = ExternalPrincipal::new(&self.settings.name, &e.issuer, subject);
        match &e.emails_url {
            Some(url) => {
                if let Some(email) = self.github_email(url, &access_token).await? {
                    principal = principal.with_email(email, true);
                }
            }
            None => {
                if let Some(email) = c.email.as_deref().and_then(|p| text_at(&info, p)) {
                    let verified = c
                        .email_verified
                        .as_deref()
                        .is_some_and(|p| bool_at(&info, p));
                    principal = principal.with_email(email, verified);
                }
            }
        }
        let field = |p: &Option<String>| p.as_deref().and_then(|p| text_at(&info, p));
        principal.username = field(&c.username);
        principal.first_name = field(&c.first_name);
        principal.last_name = field(&c.last_name);
        Ok(principal)
    }
}
