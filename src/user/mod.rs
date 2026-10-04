//! Identity context — user accounts.

pub mod model;
pub mod repository;
pub mod service;
pub mod service_impl;
pub mod validation;

pub use model::{NewUser, RegisterUser, UpdateUser, User, UserUpdate, UserWithRoles};
pub use repository::UserRepository;
pub use service::UserService;
pub use service_impl::UserServiceImpl;
pub use validation::normalize_email;
