//! Circuit breaker for one link target.  Pure; time comes from the caller.
//!
//! ```text
//! closed ──`threshold` consecutive failed requests──► open
//!   ▲                                                  │ cooldown elapsed
//!   │                                                  ▼
//!   └─────────── probe succeeded ─────────────── half-open ──probe failed──► open
//! ```

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default)]
pub(crate) struct Breaker {
    failures: u32,
    opened_at: Option<DateTime<Utc>>,
}

impl Breaker {
    /// Whether a request may be sent: closed, or open long enough to probe.
    pub fn allows(&self, now: DateTime<Utc>, cooldown: chrono::Duration) -> bool {
        self.opened_at.is_none_or(|at| now - at >= cooldown)
    }

    /// Open and still cooling down.
    pub fn is_open(&self, now: DateTime<Utc>, cooldown: chrono::Duration) -> bool {
        !self.allows(now, cooldown)
    }

    pub fn success(&mut self) {
        self.failures = 0;
        self.opened_at = None;
    }

    /// A request failed (after its retries).
    pub fn failure(&mut self, now: DateTime<Utc>, threshold: u32) {
        if self.opened_at.is_some() {
            // The half-open probe failed: cool down again.
            self.opened_at = Some(now);
            return;
        }
        self.failures += 1;
        if self.failures >= threshold {
            self.opened_at = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_after_threshold_and_half_opens_after_cooldown() {
        let t0 = Utc::now();
        let cooldown = chrono::Duration::seconds(30);
        let mut b = Breaker::default();
        assert!(b.allows(t0, cooldown));

        b.failure(t0, 3);
        b.failure(t0, 3);
        assert!(b.allows(t0, cooldown), "still closed below the threshold");
        b.failure(t0, 3);
        assert!(b.is_open(t0, cooldown));
        assert!(b.is_open(t0 + chrono::Duration::seconds(29), cooldown));

        let probe_at = t0 + cooldown;
        assert!(b.allows(probe_at, cooldown), "half-open: one probe");
        b.failure(probe_at, 3);
        assert!(
            b.is_open(probe_at + chrono::Duration::seconds(1), cooldown),
            "reopened"
        );

        let probe_at = probe_at + cooldown;
        assert!(b.allows(probe_at, cooldown));
        b.success();
        assert!(b.allows(probe_at, cooldown));
        b.failure(probe_at, 3);
        assert!(b.allows(probe_at, cooldown), "counter was reset");
    }
}
