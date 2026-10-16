//! What z-auth-mfa reports from `ZAuth::tick`; read it with
//! `tick_report.extension::<MfaTickReport>()`.

/// A tick that purged (ticks between purges report nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MfaTickReport {
    /// Expired challenges, enrollments and lockout rows deleted.
    pub purged: u64,
}
