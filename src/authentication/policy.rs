//! Refresh decision policy — a pure function, no I/O.
//!
//! Evaluated after the access token's signature has been verified (expiry
//! ignored), the refresh token parsed, both tokens confirmed to reference the
//! same session, and the denylist consulted.
//!
//! | condition (in order)                                          | decision                   |
//! |---------------------------------------------------------------|----------------------------|
//! | session not active                                            | reject `TokenRevoked`      |
//! | past idle or absolute expiry                                  | reject `SessionExpired`    |
//! | refresh MAC invalid                                           | reject `InvalidToken`      |
//! | generation no longer in history                               | reject `InvalidToken`      |
//! | generation's `access_jti` ≠ access token `jti`                | compromise `TokenReuse`    |
//! | IP binding on and request IP ≠ session's creating IP          | compromise `IpMismatch`    |
//! | generation = current                                          | rotate                     |
//! | generation = current − 1, within grace, IP = current's IP     | return the current pair    |
//! | any other generation in history                               | compromise `TokenReuse`    |

use chrono::{DateTime, Utc};

use crate::authentication::model::{ClientContext, Session, SessionGeneration, SessionStatus};
use crate::config::SessionConfig;
use crate::error::AuthError;
use crate::token::model::{Claims, RevocationReason};

#[derive(Debug)]
pub enum RefreshDecision {
    /// Issue generation `current + 1`.
    Rotate,
    /// Hand out the current generation's pair again (concurrent refresh).
    ReturnCurrent,
    /// End the session as compromised and require login.
    Compromise(RevocationReason),
    /// Refuse without side effects.
    Reject(AuthError),
}

pub struct RefreshInput<'a> {
    pub claims: &'a Claims,
    pub session: &'a Session,
    /// Whether the refresh token's MAC verified against the session secret.
    pub mac_valid: bool,
    /// The generation the presented tokens belong to, if still in history.
    pub presented: Option<&'a SessionGeneration>,
    /// The session's current generation, if different from `presented`.
    pub current: Option<&'a SessionGeneration>,
    pub ctx: &'a ClientContext,
    pub now: DateTime<Utc>,
    pub config: &'a SessionConfig,
}

pub fn evaluate_refresh(input: &RefreshInput<'_>) -> RefreshDecision {
    let RefreshInput {
        claims,
        session,
        mac_valid,
        presented,
        current,
        ctx,
        now,
        config,
    } = *input;

    if session.status != SessionStatus::Active {
        return RefreshDecision::Reject(AuthError::TokenRevoked);
    }
    if now >= session.idle_expires_at || now >= session.absolute_expires_at {
        return RefreshDecision::Reject(AuthError::SessionExpired);
    }
    if !mac_valid {
        return RefreshDecision::Reject(AuthError::InvalidToken("bad refresh token".into()));
    }
    let Some(presented) = presented else {
        return RefreshDecision::Reject(AuthError::InvalidToken("unknown token generation".into()));
    };
    if presented.access_jti != claims.jti || presented.generation != claims.generation {
        return RefreshDecision::Compromise(RevocationReason::TokenReuse);
    }
    if config.ip_binding && ctx.ip != session.created_ip {
        return RefreshDecision::Compromise(RevocationReason::IpMismatch);
    }

    if presented.generation == session.current_generation {
        return RefreshDecision::Rotate;
    }

    let within_grace = presented.generation + 1 == session.current_generation
        && presented.superseded_at.is_some_and(|at| {
            now.signed_duration_since(at)
                .to_std()
                .map(|elapsed| elapsed < config.refresh_grace)
                .unwrap_or(true) // superseded "in the future" — clock skew; treat as fresh
        })
        && current.is_some_and(|c| c.issued_ip == ctx.ip);
    if within_grace {
        return RefreshDecision::ReturnCurrent;
    }

    RefreshDecision::Compromise(RevocationReason::TokenReuse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use uuid::Uuid;

    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    fn config(ip_binding: bool) -> SessionConfig {
        SessionConfig {
            refresh_secret: None,
            idle_timeout: Duration::from_secs(1800),
            absolute_timeout: Duration::from_secs(28_800),
            history_size: 10,
            refresh_grace: Duration::from_secs(30),
            ip_binding,
            max_sessions_per_user: 5,
        }
    }

    struct Fixture {
        now: DateTime<Utc>,
        session: Session,
        generations: Vec<SessionGeneration>,
    }

    /// A session at generation 3; generation 2 was superseded 10 s ago.
    fn fixture() -> Fixture {
        let now = Utc::now();
        let sid = Uuid::new_v4();
        let generations = (1..=3)
            .map(|g| SessionGeneration {
                session_id: sid,
                generation: g,
                access_jti: Uuid::new_v4(),
                issued_ip: IP_A,
                issued_at: now,
                access_expires_at: now,
                superseded_at: (g < 3).then(|| now - chrono::Duration::seconds(10)),
            })
            .collect();
        Fixture {
            now,
            session: Session {
                id: sid,
                user_id: Uuid::new_v4(),
                secret: vec![],
                status: SessionStatus::Active,
                end_reason: None,
                created_ip: IP_A,
                user_agent: None,
                current_generation: 3,
                created_at: now,
                idle_expires_at: now + chrono::Duration::minutes(30),
                absolute_expires_at: now + chrono::Duration::hours(8),
                ended_at: None,
            },
            generations,
        }
    }

    fn claims_for(f: &Fixture, g: &SessionGeneration) -> Claims {
        Claims {
            sub: f.session.user_id,
            sid: f.session.id,
            jti: g.access_jti,
            generation: g.generation,
            iss: "t".into(),
            iat: 0,
            exp: 0,
            authz: None,
        }
    }

    fn decide(f: &Fixture, presented_gen: u32, ip: IpAddr, cfg: &SessionConfig) -> RefreshDecision {
        let presented = f.generations.iter().find(|g| g.generation == presented_gen);
        let claims = claims_for(f, presented.unwrap_or(&f.generations[0]));
        let current = f.generations.last();
        let ctx = ClientContext {
            ip,
            user_agent: None,
        };
        evaluate_refresh(&RefreshInput {
            claims: &claims,
            session: &f.session,
            mac_valid: true,
            presented,
            current,
            ctx: &ctx,
            now: f.now,
            config: cfg,
        })
    }

    #[test]
    fn current_generation_rotates() {
        assert!(matches!(
            decide(&fixture(), 3, IP_A, &config(false)),
            RefreshDecision::Rotate
        ));
    }

    #[test]
    fn previous_generation_within_grace_returns_current() {
        assert!(matches!(
            decide(&fixture(), 2, IP_A, &config(false)),
            RefreshDecision::ReturnCurrent
        ));
    }

    #[test]
    fn previous_generation_from_other_ip_is_reuse() {
        assert!(matches!(
            decide(&fixture(), 2, IP_B, &config(false)),
            RefreshDecision::Compromise(RevocationReason::TokenReuse)
        ));
    }

    #[test]
    fn previous_generation_after_grace_is_reuse() {
        let mut f = fixture();
        f.generations[1].superseded_at = Some(f.now - chrono::Duration::seconds(31));
        assert!(matches!(
            decide(&f, 2, IP_A, &config(false)),
            RefreshDecision::Compromise(RevocationReason::TokenReuse)
        ));
    }

    #[test]
    fn older_generation_is_reuse() {
        assert!(matches!(
            decide(&fixture(), 1, IP_A, &config(false)),
            RefreshDecision::Compromise(RevocationReason::TokenReuse)
        ));
    }

    #[test]
    fn generation_outside_history_is_rejected_without_side_effects() {
        assert!(matches!(
            decide(&fixture(), 42, IP_A, &config(false)),
            RefreshDecision::Reject(AuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn mixed_pair_is_reuse() {
        let f = fixture();
        let mut claims = claims_for(&f, &f.generations[2]);
        claims.jti = Uuid::new_v4();
        let ctx = ClientContext {
            ip: IP_A,
            user_agent: None,
        };
        let decision = evaluate_refresh(&RefreshInput {
            claims: &claims,
            session: &f.session,
            mac_valid: true,
            presented: Some(&f.generations[2]),
            current: None,
            ctx: &ctx,
            now: f.now,
            config: &config(false),
        });
        assert!(matches!(
            decision,
            RefreshDecision::Compromise(RevocationReason::TokenReuse)
        ));
    }

    #[test]
    fn ip_binding_toggle() {
        assert!(matches!(
            decide(&fixture(), 3, IP_B, &config(false)),
            RefreshDecision::Rotate
        ));
        assert!(matches!(
            decide(&fixture(), 3, IP_B, &config(true)),
            RefreshDecision::Compromise(RevocationReason::IpMismatch)
        ));
    }

    #[test]
    fn inactive_expired_and_bad_mac_are_rejected() {
        let mut f = fixture();
        f.session.status = SessionStatus::Compromised;
        assert!(matches!(
            decide(&f, 3, IP_A, &config(false)),
            RefreshDecision::Reject(AuthError::TokenRevoked)
        ));

        let mut f = fixture();
        f.session.idle_expires_at = f.now;
        assert!(matches!(
            decide(&f, 3, IP_A, &config(false)),
            RefreshDecision::Reject(AuthError::SessionExpired)
        ));

        let mut f = fixture();
        f.session.absolute_expires_at = f.now - chrono::Duration::seconds(1);
        assert!(matches!(
            decide(&f, 3, IP_A, &config(false)),
            RefreshDecision::Reject(AuthError::SessionExpired)
        ));

        let f = fixture();
        let claims = claims_for(&f, &f.generations[2]);
        let ctx = ClientContext {
            ip: IP_A,
            user_agent: None,
        };
        let decision = evaluate_refresh(&RefreshInput {
            claims: &claims,
            session: &f.session,
            mac_valid: false,
            presented: Some(&f.generations[2]),
            current: None,
            ctx: &ctx,
            now: f.now,
            config: &config(false),
        });
        assert!(matches!(
            decision,
            RefreshDecision::Reject(AuthError::InvalidToken(_))
        ));
    }
}
