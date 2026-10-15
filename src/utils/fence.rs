//! A serving fence: a shared flag an extension raises when this instance
//! must stop serving (e.g. it lost its cluster).  Once raised, the token
//! verifier, [`ZAuth::tick`](crate::ZAuth::tick) and any wrapper that
//! checks it refuse with [`AuthError::NodeFenced`].  It never comes down;
//! the host restarts the process.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::utils::error::AuthError;

#[derive(Debug, Clone, Default)]
pub struct ServingFence(Arc<AtomicBool>);

impl ServingFence {
    pub fn new() -> Self {
        Self::default()
    }

    /// Raise the fence.  Returns `true` the first time.
    pub fn fence(&self) -> bool {
        !self.0.swap(true, Ordering::SeqCst)
    }

    pub fn is_fenced(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// [`AuthError::NodeFenced`] once fenced.
    pub fn check(&self) -> Result<(), AuthError> {
        if self.is_fenced() {
            Err(AuthError::NodeFenced)
        } else {
            Ok(())
        }
    }
}
