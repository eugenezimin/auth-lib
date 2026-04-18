pub mod interfaces; // pub — the entire public API
pub mod model; // pub — types used in trait signatures
pub mod utils; // pub — AuthError is pub, so the path must be pub

pub mod auth; // internal: AuthServiceImpl is pub(crate)
pub(crate) mod storage; // internal: concrete repos, pool, factory
