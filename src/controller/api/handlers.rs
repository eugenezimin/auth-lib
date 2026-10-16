//! Framework-agnostic endpoint handlers.
//!
//! Each handler takes a service trait object plus a request DTO and returns a
//! response DTO or an [`ApiError`].  The host application wraps them in its
//! own web framework and supplies the [`ClientContext`] (real client IP,
//! user agent):
//!
//! ```rust,ignore
//! // axum example (host application code)
//! async fn refresh(
//!     State(auth): State<Arc<ZAuth>>,
//!     ConnectInfo(addr): ConnectInfo<SocketAddr>,
//!     Json(req): Json<RefreshRequest>,
//! ) -> Result<Json<TokenPairResponse>, MyError> {
//!     let ctx = ClientContext::new(addr.ip());
//!     Ok(Json(handlers::refresh(auth.authentication(), req, ctx).await?))
//! }
//! ```

use crate::controller::api::dto::{
    CompleteLoginRequest, LoginRequest, LoginResponse, PermissionCatalogResponse, RefreshRequest,
    RegisterRequest, RevokeRequest, RevokeResponse, TokenPairResponse, UserResponse,
};
use crate::controller::api::error::ApiError;
use crate::identity::user::service::UserService;
use crate::security::authentication::model::ClientContext;
use crate::security::authentication::service::AuthenticationService;
use crate::security::authorization::service::PermissionService;
use crate::security::token::service::TokenRevocationService;

/// `POST /register`
pub async fn register(
    users: &dyn UserService,
    req: RegisterRequest,
) -> Result<UserResponse, ApiError> {
    Ok(users.register(req.into()).await?.into())
}

/// `POST /login` — tokens, or a challenge when a second factor is needed.
pub async fn login(
    auth: &dyn AuthenticationService,
    req: LoginRequest,
    ctx: ClientContext,
) -> Result<LoginResponse, ApiError> {
    Ok(auth.login(req.into(), ctx).await?.into())
}

/// `POST /login/second-factor` — complete a login with the challenge token
/// and a code.
pub async fn complete_login(
    auth: &dyn AuthenticationService,
    req: CompleteLoginRequest,
    ctx: ClientContext,
) -> Result<TokenPairResponse, ApiError> {
    Ok(auth.complete_login(req.into(), ctx).await?.into())
}

/// `POST /refresh` — the only endpoint that touches session storage.
pub async fn refresh(
    auth: &dyn AuthenticationService,
    req: RefreshRequest,
    ctx: ClientContext,
) -> Result<TokenPairResponse, ApiError> {
    Ok(auth
        .refresh(&req.access_token, &req.refresh_token, ctx)
        .await?
        .into())
}

/// `POST /logout` with the bearer access token (may be expired).
/// Returns `true` if a session was closed.
pub async fn logout(auth: &dyn AuthenticationService, bearer: &str) -> Result<bool, ApiError> {
    Ok(auth.logout(bearer).await?)
}

/// `POST /logout/all` with a valid bearer access token.  Returns the number
/// of sessions closed.
pub async fn logout_all(auth: &dyn AuthenticationService, bearer: &str) -> Result<u64, ApiError> {
    let claims = auth.verify_access_token(bearer).await?;
    Ok(auth.logout_all(claims.sub).await?)
}

/// `POST /revocations` — accept revoked tokens / sessions / users.
pub async fn revoke(
    revocation: &dyn TokenRevocationService,
    req: RevokeRequest,
) -> Result<RevokeResponse, ApiError> {
    let targets = req.targets.into_iter().map(Into::into).collect();
    let sessions_ended = revocation.revoke_many(targets, req.reason).await?;
    Ok(RevokeResponse { sessions_ended })
}

/// `GET /permissions/catalog` — served from memory; UIs fetch it once and
/// again only when a token's `pv` is newer than their copy.
pub fn permission_catalog(
    permissions: &dyn PermissionService,
) -> Result<PermissionCatalogResponse, ApiError> {
    Ok(PermissionCatalogResponse::from(
        permissions.catalog()?.as_ref(),
    ))
}
