pub(crate) mod config; // pub(crate) — Config is accessed via pub methods, not re-exported internals
pub mod errors; // pub — AuthError is pub
pub(crate) mod helpers; // pub(crate) — internal utilities
