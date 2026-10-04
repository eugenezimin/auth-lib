//! Access-control context — roles and user → role assignments (RBAC).

pub mod model;
pub mod repository;
pub mod service;
pub mod service_impl;

pub use model::{NewRole, Role, UserRole};
pub use repository::{RoleRepository, UserRoleRepository};
pub use service::RoleService;
pub use service_impl::RoleServiceImpl;
