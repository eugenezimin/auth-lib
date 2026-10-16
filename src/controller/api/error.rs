//! Transport-agnostic API error.
//!
//! Carries an HTTP status as a plain `u16` so the library does not depend on
//! any HTTP crate; the host maps it into its framework's response type.

use crate::conf::constants::*;
use crate::controller::api::dto::ErrorBody;
use crate::utils::error::AuthError;

#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP status code.
    pub status: u16,
    /// Stable, machine-readable error code (e.g. `"email_already_taken"`).
    pub code: &'static str,
    /// Human-readable message.  Generic for 5xx errors.
    pub message: String,
}

impl ApiError {
    /// Convert into a serializable body.
    pub fn body(&self) -> ErrorBody {
        ErrorBody {
            code: self.code.to_string(),
            message: self.message.clone(),
        }
    }

    fn client(status: u16, code: &'static str, err: &AuthError) -> Self {
        Self {
            status,
            code,
            message: err.to_string(),
        }
    }

    fn internal(code: &'static str) -> Self {
        Self {
            status: HTTP_INTERNAL_SERVER_ERROR,
            code,
            message: INTERNAL_ERROR_MESSAGE.to_string(),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        use AuthError::*;
        match &err {
            EmailAlreadyTaken => Self::client(HTTP_CONFLICT, "email_already_taken", &err),
            UsernameAlreadyTaken => Self::client(HTTP_CONFLICT, "username_already_taken", &err),
            RoleAlreadyExists => Self::client(HTTP_CONFLICT, "role_already_exists", &err),
            RoleAlreadyAssigned => Self::client(HTTP_CONFLICT, "role_already_assigned", &err),
            RoleNotAssigned => Self::client(HTTP_CONFLICT, "role_not_assigned", &err),
            InvalidEmail(_) => Self::client(HTTP_UNPROCESSABLE_ENTITY, "invalid_email", &err),
            WeakPassword(_) => Self::client(HTTP_UNPROCESSABLE_ENTITY, "weak_password", &err),
            AccountDisabled => Self::client(HTTP_FORBIDDEN, "account_disabled", &err),
            AccountNotVerified => Self::client(HTTP_FORBIDDEN, "account_not_verified", &err),
            UserNotFound => Self::client(HTTP_NOT_FOUND, "user_not_found", &err),
            InvalidCredentials => Self::client(HTTP_UNAUTHORIZED, "invalid_credentials", &err),
            InvalidToken(_) => Self::client(HTTP_UNAUTHORIZED, "invalid_token", &err),
            TokenRevoked => Self::client(HTTP_UNAUTHORIZED, "token_revoked", &err),
            SessionExpired => Self::client(HTTP_UNAUTHORIZED, "session_expired", &err),
            SessionCompromised => Self::client(HTTP_UNAUTHORIZED, "session_compromised", &err),
            AuthzModeDisabled(_) => Self::client(HTTP_CONFLICT, "authz_mode_disabled", &err),
            RoleNotFound => Self::client(HTTP_NOT_FOUND, "role_not_found", &err),
            PermissionNotFound => Self::client(HTTP_NOT_FOUND, "permission_not_found", &err),
            PermissionAlreadyExists => {
                Self::client(HTTP_CONFLICT, "permission_already_exists", &err)
            }
            InvalidCode(_) => Self::client(HTTP_UNPROCESSABLE_ENTITY, "invalid_code", &err),
            InvalidPermissionValue(_) => {
                Self::client(HTTP_UNPROCESSABLE_ENTITY, "invalid_permission_value", &err)
            }
            SecondFactorRequired => Self::client(HTTP_FORBIDDEN, "second_factor_required", &err),
            InvalidSecondFactor => Self::client(HTTP_UNAUTHORIZED, "invalid_second_factor", &err),
            SecondFactorLocked => {
                Self::client(HTTP_TOO_MANY_REQUESTS, "second_factor_locked", &err)
            }
            ChallengeExpired => Self::client(HTTP_UNAUTHORIZED, "challenge_expired", &err),
            SecondFactorNotEnrolled => {
                Self::client(HTTP_FORBIDDEN, "second_factor_not_enrolled", &err)
            }
            SecondFactorAlreadyEnrolled => {
                Self::client(HTTP_CONFLICT, "second_factor_already_enrolled", &err)
            }
            SecondFactorNotFound => Self::client(HTTP_NOT_FOUND, "second_factor_not_found", &err),
            UnsupportedSecondFactor(_) => {
                Self::client(HTTP_UNPROCESSABLE_ENTITY, "unsupported_second_factor", &err)
            }
            InvalidDestination(_) => {
                Self::client(HTTP_UNPROCESSABLE_ENTITY, "invalid_destination", &err)
            }
            CodeResendTooSoon => Self::client(HTTP_TOO_MANY_REQUESTS, "code_resend_too_soon", &err),
            CodeDeliveryFailed(_) => Self {
                status: HTTP_SERVICE_UNAVAILABLE,
                code: "code_delivery_failed",
                message: "the code could not be delivered; retry later".into(),
            },
            ClusterMessageRejected(_) => {
                Self::client(HTTP_UNAUTHORIZED, "cluster_message_rejected", &err)
            }
            ClusterUnreachable(_) => Self::internal("cluster_unreachable"),
            NotAuthority { .. } => Self::client(HTTP_MISDIRECTED_REQUEST, "not_authority", &err),
            ReplicaStale => Self::client(HTTP_SERVICE_UNAVAILABLE, "replica_stale", &err),
            ReplicaBehind => Self::client(HTTP_SERVICE_UNAVAILABLE, "replica_behind", &err),
            NodeFenced => Self::client(HTTP_SERVICE_UNAVAILABLE, "node_fenced", &err),
            HashingError(_) => Self::internal("hashing_error"),
            Storage(_) => Self::internal("storage_error"),
            Config(_) => Self::internal("config_error"),
            TokenCreationError(_) => Self::internal("token_creation_error"),
            Internal(_) => Self::internal("internal_error"),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.message)
    }
}

impl std::error::Error for ApiError {}
