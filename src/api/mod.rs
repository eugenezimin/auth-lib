//! Framework-agnostic API layer — DTOs, error mapping and endpoint handlers.
//!
//! No HTTP crate is used: handlers are plain async functions and errors carry
//! the status code as a `u16`.

pub mod dto;
pub mod error;
pub mod handlers;
pub mod mapping;

pub use error::ApiError;
