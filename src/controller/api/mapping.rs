//! Conversions between API DTOs and domain models.

use crate::controller::api::dto::{
    ChallengeDeliveryDto, CompleteLoginRequest, LoginChallengeResponse, LoginRequest,
    LoginResponse, PermissionCatalogResponse, PermissionDto, PermissionOptionDto, RegisterRequest,
    RevokeTargetDto, TokenPairResponse, UserResponse,
};
use crate::identity::user::model::{RegisterUser, User};
use crate::security::authentication::model::{
    ChallengeDelivery, Credentials, LoginChallenge, LoginOutcome, SecondFactorProof, TokenPair,
};
use crate::security::authorization::model::{Permission, PermissionCatalog, PermissionKind};
use crate::security::token::model::RevokeTarget;

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

impl From<LoginOutcome> for LoginResponse {
    fn from(o: LoginOutcome) -> Self {
        match o {
            LoginOutcome::Tokens(pair) => Self::Authenticated(pair.into()),
            LoginOutcome::SecondFactor(challenge) => Self::SecondFactorRequired(challenge.into()),
        }
    }
}

impl From<LoginChallenge> for LoginChallengeResponse {
    fn from(c: LoginChallenge) -> Self {
        Self {
            challenge_token: c.challenge_token,
            expires_at: c.expires_at,
            methods: c.methods,
            delivery: c.delivery.map(Into::into),
        }
    }
}

impl From<ChallengeDelivery> for ChallengeDeliveryDto {
    fn from(d: ChallengeDelivery) -> Self {
        Self {
            method: d.method,
            destination_hint: d.destination_hint,
            expires_at: d.expires_at,
        }
    }
}

impl From<CompleteLoginRequest> for SecondFactorProof {
    fn from(r: CompleteLoginRequest) -> Self {
        Self {
            challenge_token: r.challenge_token,
            method: r.method,
            code: r.code,
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
