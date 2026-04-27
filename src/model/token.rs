/// JWT claims and token type models.

#[derive(Debug, Clone, PartialEq)]
pub enum TokenType {
    Access,
    Refresh,
}

/// Claims encoded into every JWT issued by this library.
#[derive(Debug, Clone)]
pub struct Claims {
    /// Subject — the `user_id` as a string.
    pub sub: String,
    /// Issuer — from `JwtConfig::issuer`.
    pub iss: String,
    /// JWT ID — unique per token, used for blocklist lookups.
    pub jti: String,
    /// Issued-at (Unix seconds).
    pub iat: usize,
    /// Expiry (Unix seconds).
    pub exp: usize,
    /// Discriminates access tokens from refresh tokens.
    pub token_type: TokenType,
}
