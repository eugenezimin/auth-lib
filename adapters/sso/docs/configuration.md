# Configuring z-auth-sso

z-auth-sso reads the `sso` section of the configuration file through `SsoSourceLoader`, the environment alone through `SsoEnvLoader`, or a `RawSsoConfig` filled in by code through `SsoDirectLoader`. As everywhere in z-auth, an environment variable wins over the file, so the file holds the structure and the environment holds secrets. `load_settings` validates everything at startup and names the offending path or variable in its error. The core's [configuration guide](../../../docs/configuration.md) explains `ConfigSource` and the file format.

## The section

| Variable | File path | Default | Meaning |
|---|---|---|---|
| `AUTH_SSO_CALLBACK_URL` | `sso.callback_url` | required | The callback route, registered with every provider as its redirect URI. Must be `https` (or `http` on localhost). |
| `AUTH_SSO_FLOW_TTL_SECS` | `sso.flow_ttl_secs` | `600` | How long a redirect to a provider stays valid. |
| `AUTH_SSO_BINDING_TRANSPORT` | `sso.binding.transport` | `cookie` | `cookie` or `header`, how the browser binding reaches the callback. It cannot be turned off. |
| `AUTH_SSO_BINDING_NAME` | `sso.binding.name` | by transport | The cookie or header name. `__Host-sso-binding` for a cookie on an https callback, `sso-binding` on a localhost http one, `X-SSO-Binding` for a header. |
| `AUTH_SSO_PROVIDERS` | none | none | Comma-separated names of providers configured in the environment alone. |

Providers are mappings under `sso.providers`, keyed by name. A name must match `[a-z][a-z0-9_]*`, because it becomes part of variable names, and it is recorded with every identity the provider links. Each setting of a provider is read from `AUTH_SSO_<NAME>_<SETTING>`, the setting in upper case with `.` written as `_`, before the file. `AUTH_SSO_GOOGLE_CLIENT_SECRET` is `sso.providers.google.client_secret`, and `AUTH_SSO_ACME_CLAIMS_EMAIL` is `sso.providers.acme.claims.email`. A key the provider's kind does not use, or that no kind uses, is rejected.

## The browser binding

The binding ties a callback to the browser that started the redirect. Why it exists and how each transport works is explained in the [README](../README.md#the-browser-binding). Loading the settings refuses every configuration that would weaken it. The transport must be `cookie` or `header`, and `off`, `none`, `query` and `body` are refused with an explanation. A cookie on an https callback must be named with the `__Host-` prefix, which pins it to your exact host, and a header must be a valid header name other than one the browser controls or the server reads for something else, such as `Authorization`, `Cookie`, `Origin` or any `Sec-` or `Proxy-` header.

```yaml
sso:
  callback_url: https://app.example.com/auth/sso/callback   # the server's route
  binding:
    transport: cookie
    name: __Host-sso-binding
```

```yaml
sso:
  callback_url: https://app.example.com/sso/callback        # the single-page app's route
  binding:
    transport: header
    name: X-SSO-Binding
```

With the header transport the callback URL is a page of the application, which forwards `state` and `code` to the API with the binding, and the API's CORS policy must list exact origins only.

## Settings of every provider

| Setting | Default | Meaning |
|---|---|---|
| `kind` | required | `oidc`, `oauth2` or `github`. |
| `display_name` | the name | Shown on sign-in pages through `Sso::providers`. |
| `client_id` | required | The client (application) id registered with the provider. |
| `client_secret` | none | The client secret. Required for `github`; an `oidc` or `oauth2` provider without one is used as a public client with PKCE. |
| `scopes` | by kind | A list, or a comma or space separated string. `oidc` defaults to `openid email profile` and always requests `openid`; `github` defaults to `read:user user:email`; `oauth2` has none. |
| `link` | `confirm_with_password` | `never`, `confirm_with_password` or `verified_email`. What a first sign-in does when an account with the provider's email exists. |
| `provisioning` | `deny` | `deny` or `create`. What a first sign-in does when no account has the provider's email. |
| `trust_email` | `false` (`github`: `true`) | Whether the provider's verified flag can be relied on. Leave it off for providers that let users enter unverified addresses. |
| `trust_amr` | `false` | Pass the provider's `amr` on to the session, so a provider-reported `mfa` satisfies z-auth's second factor. |
| `max_links` | `1` | How many identities of this provider one user may link; `0` lifts the limit. |

The meaning of `link`, `provisioning` and `trust_email` is explained in the [external identities guide](../../../docs/external-identities.md#signing-in). The defaults are the conservative ones, so a provider that should create accounts needs `provisioning: create`, and silent linking by email needs both `link: verified_email` and `trust_email: true`.

## kind oidc

| Setting | Default | Meaning |
|---|---|---|
| `issuer` | required | The issuer exactly as the provider's tokens carry it. The discovery document is read from `<issuer>/.well-known/openid-configuration` and must name the same issuer. |
| `token_auth` | from discovery | `basic` or `post`, how the client secret is sent to the token endpoint. Without it `client_secret_basic` is used unless the provider only lists `client_secret_post`. |

Google, LinkedIn, Okta, Auth0, Keycloak, GitLab and single-tenant Microsoft Entra ID are all of this kind.

```yaml
sso:
  callback_url: https://app.example.com/auth/sso/callback
  providers:
    google:
      kind: oidc
      issuer: https://accounts.google.com
      client_id: 1234.apps.googleusercontent.com
      link: verified_email
      provisioning: create
      trust_email: true
    linkedin:
      kind: oidc
      issuer: https://www.linkedin.com/oauth
      client_id: 86abc
    okta:
      kind: oidc
      issuer: https://acme.okta.com/oauth2/default
      client_id: 0oa1b2c3
      provisioning: create
      trust_amr: true          # the company's Okta enforces MFA
    entra:
      kind: oidc
      issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
      client_id: 00000000-0000-0000-0000-000000000000
```

Microsoft's multi-tenant endpoint (`/common` or `/organizations`) issues tokens whose issuer names each user's tenant, which a fixed issuer cannot match. Configure one provider per tenant, or add a host provider for the multi-tenant case.

## kind oauth2

| Setting | Default | Meaning |
|---|---|---|
| `issuer` | required | Any stable string, usually the provider's URL, recorded as the identities' issuer. |
| `authorize_url` | required | The authorization endpoint. |
| `token_url` | required | The token endpoint. |
| `userinfo_url` | required | Read with the access token; the claims below point into its JSON answer. |
| `token_auth` | `post` | `basic` or `post`. |
| `pkce` | `true` | Send a PKCE challenge. Providers that reject the parameters need `false`. |
| `claims.subject` | required | JSON pointer to the user's stable id, such as `/id`. Numbers are accepted. |
| `claims.email` | none | JSON pointer to the email address. |
| `claims.email_verified` | none | JSON pointer to a verified flag (`true` or `"true"`). Without it emails count as unverified. |
| `claims.username` | none | JSON pointer to a suggested username. |
| `claims.first_name` | none | JSON pointer to the first name. |
| `claims.last_name` | none | JSON pointer to the last name. |

```yaml
    facebook:
      kind: oauth2
      issuer: https://www.facebook.com
      authorize_url: https://www.facebook.com/v19.0/dialog/oauth
      token_url: https://graph.facebook.com/v19.0/oauth/access_token
      userinfo_url: https://graph.facebook.com/me?fields=id,email,first_name,last_name
      client_id: "1234567890"
      scopes: [email, public_profile]
      claims:
        subject: /id
        email: /email
        first_name: /first_name
        last_name: /last_name
```

## kind github

The preset needs only `client_id` and `client_secret` (feature `github`). The subject is GitHub's numeric user id, the username its login, and the email the primary verified address from `/user/emails`, or another verified one. A user with no verified address cannot be provisioned. `authorize_url`, `token_url`, `userinfo_url` and `emails_url` can be overridden for GitHub Enterprise Server.

```yaml
    github:
      kind: github
      client_id: Iv1.0123456789abcdef
      provisioning: create
```

## The environment alone

Without a file, `AUTH_SSO_PROVIDERS` names the providers and each setting comes from its variable.

```bash
AUTH_SSO_CALLBACK_URL=https://app.example.com/auth/sso/callback
AUTH_SSO_PROVIDERS=google,github
AUTH_SSO_GOOGLE_KIND=oidc
AUTH_SSO_GOOGLE_ISSUER=https://accounts.google.com
AUTH_SSO_GOOGLE_CLIENT_ID=1234.apps.googleusercontent.com
AUTH_SSO_GOOGLE_CLIENT_SECRET=...
AUTH_SSO_GITHUB_KIND=github
AUTH_SSO_GITHUB_CLIENT_ID=Iv1.0123456789abcdef
AUTH_SSO_GITHUB_CLIENT_SECRET=...
```

## In code

`RawSsoConfig` builds the same settings without a file, for tests or hosts with their own configuration system.

```rust
use z_auth_sso::config::{RawSsoConfig, SsoConfigLoader, SsoDirectLoader};

let settings = SsoDirectLoader::new(
    RawSsoConfig::default()
        .callback_url("https://app.example.com/auth/sso/callback")
        .provider("google", [
            ("kind", "oidc"),
            ("issuer", "https://accounts.google.com"),
            ("client_id", "1234.apps.googleusercontent.com"),
        ]),
)
.load_settings()?;
```

## Registering z-auth with a provider

Every provider asks for the redirect URI, which is `callback_url` exactly, and issues a client id and usually a secret. For `oidc` providers grant the `openid`, `email` and `profile` scopes, and for Google, Entra ID and Okta prefer a confidential web application client. The provider's console decides which accounts may sign in at all, such as one Google Workspace domain or one Entra tenant, and that restriction is the first line of defence for an internal application.
