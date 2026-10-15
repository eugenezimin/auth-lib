//! Convenience re-exports: `use z_auth::prelude::*;`

pub use crate::conf::config::{
    AuthConfig, AuthzMode, ConfigLoader, DirectLoader, EnvLoader, RawConfig,
};
pub use crate::controller::api::ApiError;
pub use crate::controller::extension::{Extension, ExtensionReport};
pub use crate::controller::facade::{
    ZAuth, ZAuthBuilder, Repositories, StartReport, TickReport,
};
pub use crate::eventing::{DomainEvent, EventPublisher};
pub use crate::identity::access::{
    NewRole, Role, RoleRepository, RoleService, RoleUpdate, UserRole, UserRoleRepository,
};
pub use crate::identity::credentials::PasswordHasher;
pub use crate::identity::user::{
    NewUser, RegisterUser, UpdateUser, User, UserPage, UserQuery, UserRepository, UserService,
    UserUpdate, UserWithRoles,
};
pub use crate::security::authentication::{
    AuthenticationService, ClientContext, Credentials, TokenPair,
};
pub use crate::security::authorization::{
    Authorizer, EffectivePermissions, GrantView, NewPermission, Permission, PermissionCatalog,
    PermissionKind, PermissionRepository, PermissionService, PermissionValue,
};
pub use crate::security::session::RevocationReason;
pub use crate::security::session::{
    NewSession, RefreshSnapshot, RotateOutcome, Session, SessionGeneration, SessionLifetimes,
    SessionRepository, SessionStatus,
};
#[cfg(feature = "crypto")]
pub use crate::security::token::KeyService;
pub use crate::security::token::{
    Claims, Denylist, KeyRepository, KeyRing, NewRevocation, NewVerifyingKey, Revocation,
    RevocationRepository, RevocationScope, RevocationStatus, RevokeTarget, TokenRevocationService,
    TokenVerifier, VerifyingKeyRecord,
};
pub use crate::utils::clock::{Clock, SystemClock};
pub use crate::utils::error::AuthError;
