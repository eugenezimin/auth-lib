//! Identity contexts — [`user`] accounts, their [`credentials`] (password
//! hashing and policy), [`access`] (roles and grants) and [`external`]
//! identities linked to them.

pub mod access;
pub mod credentials;
pub mod external;
pub mod user;
