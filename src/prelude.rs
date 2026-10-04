//! Convenience re-exports: `use auth_lib::prelude::*;`

pub use crate::access::{NewRole, Role, RoleRepository, RoleService, UserRole, UserRoleRepository};
pub use crate::api::ApiError;
pub use crate::authentication::{
    AuthenticationService, ClientContext, Credentials, NewSession, RefreshSnapshot, RotateOutcome,
    Session, SessionGeneration, SessionLifetimes, SessionRepository, SessionStatus, TokenPair,
};
pub use crate::authorization::{
    Authorizer, EffectivePermissions, NewPermission, Permission, PermissionCatalog, PermissionKind,
    PermissionRepository, PermissionService, PermissionValue,
};
pub use crate::clock::{Clock, SystemClock};
#[cfg(feature = "cluster")]
pub use crate::cluster::{
    ClusterEnvelope, ClusterService, ClusterTransport, HeartbeatStatus, NodeInfo, NodeRecord,
    NodeRepository, NodeState, NodeTransition, PeerState,
};
pub use crate::config::{AuthConfig, AuthzMode, ConfigLoader, DirectLoader, EnvLoader, RawConfig};
pub use crate::credentials::PasswordHasher;
pub use crate::error::AuthError;
pub use crate::events::{DomainEvent, EventPublisher};
pub use crate::facade::{AuthLib, AuthLibBuilder, Repositories, StartReport, TickReport};
#[cfg(feature = "crypto")]
pub use crate::token::KeyService;
pub use crate::token::{
    Claims, Denylist, KeyRepository, KeyRing, NewRevocation, NewVerifyingKey, Revocation,
    RevocationReason, RevocationRepository, RevocationScope, RevocationStatus, RevokeTarget,
    TokenRevocationService, TokenVerifier, VerifyingKeyRecord,
};
pub use crate::user::{
    NewUser, RegisterUser, UpdateUser, User, UserRepository, UserService, UserUpdate, UserWithRoles,
};
