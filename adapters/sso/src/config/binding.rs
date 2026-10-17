//! How the browser binding travels between the start of a redirect and its
//! callback.
//!
//! The binding ties a callback to the browser that started the redirect, so
//! that nobody can finish a sign-in (or a link) of their own in someone
//! else's browser.  It only works when the attacker cannot make the
//! victim's browser present a binding of the attacker's choosing, which
//! rules out every channel the attacker controls, such as the callback URL
//! itself.  Two transports keep that property, and the binding cannot be
//! turned off:
//!
//! - `cookie` — the host sets it with [`BindingSettings::set_cookie`]; on an
//!   `https` callback the name must carry the `__Host-` prefix, so no other
//!   subdomain can plant one;
//! - `header` — a page of the host's own origin reads the binding from its
//!   storage and sends it in this header when it forwards the callback
//!   parameters; the API must not allow cross-origin requests from other
//!   origins (no wildcard or reflected CORS origins).
//!
//! z-auth-sso never reads cookies or headers itself: the host takes the
//! value from where this setting says and passes it to
//! [`Sso::callback`](crate::Sso::callback).

use std::time::Duration;

use z_auth::conf::config::ConfigError;

use crate::constants::{
    DEFAULT_BINDING_COOKIE, DEFAULT_BINDING_COOKIE_INSECURE, DEFAULT_BINDING_HEADER,
    ENV_SSO_BINDING_NAME, ENV_SSO_BINDING_TRANSPORT,
};

/// Where the host keeps the binding between the redirect and the callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindingTransport {
    /// An HttpOnly cookie, sent with the provider's redirect back.
    #[default]
    Cookie,
    /// A request header, sent by the host's own page that forwards the
    /// callback parameters to the API.
    Header,
}

impl BindingTransport {
    pub fn name(self) -> &'static str {
        match self {
            Self::Cookie => "cookie",
            Self::Header => "header",
        }
    }
}

impl std::str::FromStr for BindingTransport {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cookie" => Ok(Self::Cookie),
            "header" => Ok(Self::Header),
            "off" | "none" | "disabled" | "false" => Err(
                "the browser binding cannot be turned off; without it anyone can finish a \
                 sign-in or link of their own in a victim's browser (expected cookie or header)"
                    .into(),
            ),
            "query" | "url" | "param" | "body" | "form" => Err(format!(
                "'{s}' would carry the binding in a request the attacker can craft, which \
                 defeats it (expected cookie or header)"
            )),
            other => Err(format!(
                "unknown binding transport '{other}' (expected cookie or header)"
            )),
        }
    }
}

/// The validated binding settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingSettings {
    pub transport: BindingTransport,
    /// The cookie or header name.
    pub name: String,
    /// The callback is `https`: cookies are `Secure`.
    pub secure: bool,
}

/// Headers a browser will not let a page set, or that mean something else
/// to the server; a binding sent in one of them never arrives intact.
const RESERVED_HEADERS: &[&str] = &[
    "accept",
    "authorization",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "host",
    "origin",
    "referer",
    "set-cookie",
    "te",
    "transfer-encoding",
    "upgrade",
    "user-agent",
];

impl BindingSettings {
    /// Validate the settings for a callback that is `https` (`secure`) or
    /// plain `http` on localhost.
    pub fn build(
        transport: Option<&str>,
        name: Option<&str>,
        secure: bool,
    ) -> Result<Self, ConfigError> {
        let transport = match transport.map(str::trim).filter(|t| !t.is_empty()) {
            None => BindingTransport::default(),
            Some(t) => t.parse().map_err(|reason| ConfigError::Parse {
                key: ENV_SSO_BINDING_TRANSPORT.into(),
                reason,
            })?,
        };
        let name = match name.map(str::trim).filter(|n| !n.is_empty()) {
            Some(n) => n.to_string(),
            None => match transport {
                BindingTransport::Cookie if secure => DEFAULT_BINDING_COOKIE.into(),
                BindingTransport::Cookie => DEFAULT_BINDING_COOKIE_INSECURE.into(),
                BindingTransport::Header => DEFAULT_BINDING_HEADER.into(),
            },
        };
        let bad = |reason: String| ConfigError::Parse {
            key: ENV_SSO_BINDING_NAME.into(),
            reason,
        };
        if name.len() > 64 || !name.bytes().all(is_token_char) {
            return Err(bad(format!(
                "'{name}' is not a valid {} name (letters, digits and !#$%&'*+-.^_`|~, at most 64)",
                transport.name()
            )));
        }
        match transport {
            BindingTransport::Cookie => {
                if secure && !name.starts_with("__Host-") {
                    return Err(bad(format!(
                        "on an https callback the cookie name must start with __Host- \
                         (e.g. {DEFAULT_BINDING_COOKIE}), so no other subdomain can set it"
                    )));
                }
            }
            BindingTransport::Header => {
                let lower = name.to_ascii_lowercase();
                if RESERVED_HEADERS.contains(&lower.as_str())
                    || lower.starts_with("sec-")
                    || lower.starts_with("proxy-")
                {
                    return Err(bad(format!(
                        "'{name}' is reserved; browsers will not send a binding in it \
                         (e.g. {DEFAULT_BINDING_HEADER})"
                    )));
                }
            }
        }
        Ok(Self {
            transport,
            name,
            secure,
        })
    }

    /// The `Set-Cookie` value that stores `binding` for `max_age` (the
    /// redirect's lifetime): HttpOnly, `SameSite=Lax` (sent with the
    /// provider's top-level redirect back, not with cross-site
    /// sub-requests), `Path=/` and `Secure` on https.  `None` with the
    /// header transport.
    pub fn set_cookie(&self, binding: &str, max_age: Duration) -> Option<String> {
        (self.transport == BindingTransport::Cookie).then(|| {
            format!(
                "{}={binding}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{}",
                self.name,
                max_age.as_secs(),
                if self.secure { "; Secure" } else { "" }
            )
        })
    }

    /// The `Set-Cookie` value that deletes the cookie after the callback.
    /// `None` with the header transport.
    pub fn clear_cookie(&self) -> Option<String> {
        self.set_cookie("", Duration::ZERO)
    }

    /// "the cookie `__Host-sso-binding`", for messages.
    pub fn describe(&self) -> String {
        format!("the {} `{}`", self.transport.name(), self.name)
    }
}

/// An RFC 9110 `tchar`.
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(t: Option<&str>, n: Option<&str>, secure: bool) -> Result<BindingSettings, String> {
        BindingSettings::build(t, n, secure).map_err(|e| e.to_string())
    }

    #[test]
    fn defaults_follow_the_callback_scheme() {
        let https = build(None, None, true).unwrap();
        assert_eq!(https.transport, BindingTransport::Cookie);
        assert_eq!(https.name, "__Host-sso-binding");
        assert_eq!(build(None, None, false).unwrap().name, "sso-binding");
        assert_eq!(
            build(Some("header"), None, true).unwrap().name,
            "X-SSO-Binding"
        );
    }

    #[test]
    fn the_binding_cannot_be_turned_off_or_moved_into_the_request() {
        for t in ["off", "none", "query", "body", "magic"] {
            let e = build(Some(t), None, true).unwrap_err();
            assert!(e.contains("expected cookie or header"), "{t}: {e}");
        }
        assert!(
            build(Some("off"), None, true)
                .unwrap_err()
                .contains("cannot be turned off")
        );
    }

    #[test]
    fn https_cookies_need_the_host_prefix() {
        let e = build(Some("cookie"), Some("sso"), true).unwrap_err();
        assert!(e.contains("__Host-"), "{e}");
        assert!(build(Some("cookie"), Some("__Secure-sso"), true).is_err());
        assert!(build(Some("cookie"), Some("__Host-mine"), true).is_ok());
        // Plain http is for localhost development only.
        assert!(build(Some("cookie"), Some("sso"), false).is_ok());
    }

    #[test]
    fn header_names_must_be_usable() {
        assert!(build(Some("header"), Some("X-Login-Binding"), true).is_ok());
        for name in [
            "Authorization",
            "cookie",
            "Sec-Fetch-Site",
            "Proxy-Foo",
            "X Bad",
            "X:Y",
        ] {
            assert!(build(Some("header"), Some(name), true).is_err(), "{name}");
        }
    }

    #[test]
    fn cookies_are_http_only_lax_and_secure_on_https() {
        let s = build(None, None, true).unwrap();
        assert_eq!(
            s.set_cookie("abc", Duration::from_secs(600)).unwrap(),
            "__Host-sso-binding=abc; Path=/; Max-Age=600; HttpOnly; SameSite=Lax; Secure"
        );
        assert_eq!(
            s.clear_cookie().unwrap(),
            "__Host-sso-binding=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure"
        );
        let local = build(None, None, false).unwrap();
        assert!(
            !local
                .set_cookie("abc", Duration::from_secs(1))
                .unwrap()
                .contains("Secure")
        );
        let header = build(Some("header"), None, true).unwrap();
        assert_eq!(header.set_cookie("abc", Duration::from_secs(1)), None);
        assert_eq!(header.clear_cookie(), None);
    }
}
