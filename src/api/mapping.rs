//! Conversions between API DTOs and domain models.

use crate::api::dto::{
    LoginRequest, PermissionCatalogResponse, PermissionDto, PermissionOptionDto, RegisterRequest,
    RevokeTargetDto, TokenPairResponse, UserResponse,
};
use crate::authentication::model::{Credentials, TokenPair};
use crate::authorization::model::{Permission, PermissionCatalog, PermissionKind};
use crate::token::model::RevokeTarget;
use crate::user::model::{RegisterUser, User};

impl From<RegisterRequest> for RegisterUser {
    fn from(r: RegisterRequest) -> Self {
        Self {
            email: r.email,
            password: r.password,
            username: r.username,
            first_name: r.first_name,
            last_name: r.last_name,
        }
    }
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            username: u.username,
            first_name: u.first_name,
            last_name: u.last_name,
            avatar_url: u.avatar_url,
            is_active: u.is_active,
            is_verified: u.is_verified,
            created_at: u.created_at,
        }
    }
}

impl From<LoginRequest> for Credentials {
    fn from(r: LoginRequest) -> Self {
        Self {
            email: r.email,
            password: r.password,
        }
    }
}

impl From<TokenPair> for TokenPairResponse {
    fn from(p: TokenPair) -> Self {
        Self {
            session_id: p.session_id,
            access_token: p.access_token,
            access_expires_at: p.access_expires_at,
            refresh_token: p.refresh_token,
            refresh_expires_at: p.refresh_expires_at,
        }
    }
}

impl From<RevokeTargetDto> for RevokeTarget {
    fn from(t: RevokeTargetDto) -> Self {
        match t {
            RevokeTargetDto::AccessToken(token) => Self::AccessToken(token),
            RevokeTargetDto::RefreshToken(token) => Self::RefreshToken(token),
            RevokeTargetDto::Session(id) => Self::Session(id),
            RevokeTargetDto::User(id) => Self::User(id),
        }
    }
}

impl From<&PermissionCatalog> for PermissionCatalogResponse {
    fn from(c: &PermissionCatalog) -> Self {
        Self {
            version: c.version,
            permissions: c.permissions.iter().map(Into::into).collect(),
        }
    }
}

impl From<&Permission> for PermissionDto {
    fn from(p: &Permission) -> Self {
        let (kind, max_length) = match p.kind {
            PermissionKind::Bool => ("bool", None),
            PermissionKind::Single => ("single", None),
            PermissionKind::Multi => ("multi", None),
            PermissionKind::Text { max_length } => ("text", Some(max_length)),
        };
        Self {
            code: p.code.clone(),
            kind: kind.into(),
            description: p.description.clone(),
            position: p.position,
            max_length,
            options: p
                .options
                .iter()
                .map(|o| PermissionOptionDto {
                    code: o.code.clone(),
                    position: o.position,
                })
                .collect(),
        }
    }
}
