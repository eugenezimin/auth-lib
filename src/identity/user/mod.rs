//! Identity context — user accounts.

pub mod model;
pub mod repository;
pub mod service;
pub mod service_impl;
pub mod sessions;
pub mod validation;

pub use model::{
    DEFAULT_USER_PAGE, MAX_USER_PAGE, NewUser, RegisterUser, UpdateUser, User, UserPage, UserQuery,
    UserUpdate, UserWithRoles,
};
pub use repository::UserRepository;
pub use service::UserService;
pub use service_impl::UserServiceImpl;
pub use sessions::{AccountChange, AccountSessions};
pub use validation::{normalize_email, validate_email};
