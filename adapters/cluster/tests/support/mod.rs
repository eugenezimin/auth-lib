//! Shared helpers for the cluster test suite: `z-auth-testkit` plus an
//! in-memory cluster network ([`cluster`]) and a federation world
//! ([`federation`]).
//!
//! Import with:
//!   mod support;
//!   use support::*;
#![allow(dead_code, unused_imports)] // each test binary uses a different subset

pub mod cluster;
pub mod federation;

pub use z_auth_testkit::*;
