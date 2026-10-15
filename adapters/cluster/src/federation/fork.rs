//! Refresh forks: two clusters rotated the same generation.  Pure and
//! deterministic — every cluster reaches the same verdict from the same
//! variants.
//!
//! | rule | compromise when |
//! |------|-----------------|
//! | linkage | a variant's `parent_jti` is not a variant of the generation before it (a continuation of a token this cluster never saw — e.g. one hidden by history trimming) |
//! | same parent | the variants of one generation were obtained with different access tokens (both branches kept refreshing) |
//! | same client | two variants fail `AUTH_REFRESH_RETRY_MATCH` |
//! | window | their issue times are further apart than `AUTH_FORK_WINDOW_MS` + max skew |
//! | budget | more than `AUTH_FORK_MAX_BENIGN` benign forks within `AUTH_FORK_BUDGET_WINDOW_SECS` |
//!
//! A benign fork keeps the lowest `access_jti` as winner; the others become
//! aliases.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::sync::{GenerationVariant, GenerationVariants};
use z_auth::conf::config::RetryMatch;
use z_auth::security::session::RequestTraits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkParams {
    pub retry_match: RetryMatch,
    /// Fork window plus the allowed clock skew.
    pub window: chrono::Duration,
    pub max_benign: u32,
    pub budget_window: chrono::Duration,
}

/// A fork judged benign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenignFork {
    pub generation: u32,
    pub winner: Uuid,
    pub losers: Vec<Uuid>,
    /// Latest issue time among the variants.
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerdict {
    Clean {
        benign: Vec<BenignFork>,
    },
    /// The earliest violation, by time.
    Compromised {
        at: DateTime<Utc>,
    },
}

fn traits(v: &GenerationVariant) -> RequestTraits<'_> {
    RequestTraits {
        ip: v.issued_ip,
        user_agent: v.issued_user_agent.as_deref(),
        fingerprint_hash: v.fingerprint_hash.as_ref(),
    }
}

fn latest(variants: &[GenerationVariant]) -> DateTime<Utc> {
    variants
        .iter()
        .map(|v| v.issued_at)
        .max()
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

/// Judge every generation of a session (sorted by generation, variants
/// sorted by jti).
pub fn evaluate_chain(generations: &[GenerationVariants], p: &ForkParams) -> ChainVerdict {
    let mut violations: Vec<DateTime<Utc>> = Vec::new();
    let mut benign: Vec<BenignFork> = Vec::new();

    for (i, g) in generations.iter().enumerate() {
        // Linkage with the generation before, when we have it.
        if let Some(prev) = i
            .checked_sub(1)
            .map(|j| &generations[j])
            .filter(|prev| prev.generation + 1 == g.generation)
        {
            for v in &g.variants {
                if let Some(parent) = v.parent_jti
                    && !prev.variants.iter().any(|pv| pv.access_jti == parent)
                {
                    violations.push(v.issued_at);
                }
            }
        }

        let [first, rest @ ..] = g.variants.as_slice() else {
            continue;
        };
        if rest.is_empty() {
            continue;
        }
        let same_parent = rest.iter().all(|v| v.parent_jti == first.parent_jti);
        let same_client = g.variants.iter().all(|a| {
            g.variants
                .iter()
                .all(|b| traits(a).same_client(&traits(b), &p.retry_match))
        });
        let earliest = g
            .variants
            .iter()
            .map(|v| v.issued_at)
            .min()
            .unwrap_or(first.issued_at);
        let at = latest(&g.variants);
        let within_window = at - earliest <= p.window;
        if same_parent && same_client && within_window {
            benign.push(BenignFork {
                generation: g.generation,
                winner: first.access_jti,
                losers: rest.iter().map(|v| v.access_jti).collect(),
                at,
            });
        } else {
            violations.push(at);
        }
    }

    // Budget: too many benign forks within one window.
    let mut times: Vec<DateTime<Utc>> = benign.iter().map(|f| f.at).collect();
    times.sort();
    let allowed = p.max_benign as usize;
    for (i, t) in times.iter().enumerate() {
        if i >= allowed && *t - times[i - allowed] <= p.budget_window {
            violations.push(*t);
            break;
        }
    }

    match violations.into_iter().min() {
        Some(at) => ChainVerdict::Compromised { at },
        None => ChainVerdict::Clean { benign },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::IpAddr;

    pub fn params() -> ForkParams {
        ForkParams {
            retry_match: RetryMatch::default(),
            window: chrono::Duration::seconds(5),
            max_benign: 1,
            budget_window: chrono::Duration::hours(1),
        }
    }

    pub fn variant(jti: u128, parent: Option<u128>, ip: &str, at_secs: i64) -> GenerationVariant {
        let t0 = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        GenerationVariant {
            access_jti: Uuid::from_u128(jti),
            parent_jti: parent.map(Uuid::from_u128),
            issued_ip: ip.parse::<IpAddr>().unwrap(),
            issued_user_agent: None,
            fingerprint_hash: None,
            issued_at: t0 + chrono::Duration::seconds(at_secs),
            access_expires_at: t0 + chrono::Duration::seconds(at_secs + 300),
            superseded_at: None,
        }
    }

    pub fn gen_of(generation: u32, mut variants: Vec<GenerationVariant>) -> GenerationVariants {
        variants.sort_by_key(|v| v.access_jti);
        GenerationVariants {
            generation,
            variants,
        }
    }

    #[test]
    fn single_chain_is_clean() {
        let chain = vec![
            gen_of(1, vec![variant(10, None, "10.0.0.1", 0)]),
            gen_of(2, vec![variant(20, Some(10), "10.0.0.1", 300)]),
            gen_of(3, vec![variant(30, Some(20), "10.0.0.2", 600)]),
        ];
        assert_eq!(
            evaluate_chain(&chain, &params()),
            ChainVerdict::Clean { benign: vec![] }
        );
    }

    #[test]
    fn retry_at_two_clusters_is_benign_and_lowest_jti_wins() {
        let chain = vec![
            gen_of(1, vec![variant(10, None, "10.0.0.1", 0)]),
            gen_of(
                2,
                vec![
                    variant(22, Some(10), "10.0.0.1", 300),
                    variant(21, Some(10), "10.0.0.1", 302),
                ],
            ),
        ];
        let ChainVerdict::Clean { benign } = evaluate_chain(&chain, &params()) else {
            panic!("benign");
        };
        assert_eq!(benign.len(), 1);
        assert_eq!(benign[0].winner, Uuid::from_u128(21));
        assert_eq!(benign[0].losers, vec![Uuid::from_u128(22)]);
    }

    #[test]
    fn different_client_window_or_parent_compromises() {
        let base = |b: GenerationVariant| {
            vec![
                gen_of(
                    1,
                    vec![
                        variant(10, None, "10.0.0.1", 0),
                        variant(11, None, "10.0.0.1", 0),
                    ],
                ),
                gen_of(2, vec![variant(21, Some(10), "10.0.0.1", 300), b]),
            ]
        };
        for (other, why) in [
            (variant(22, Some(10), "10.9.9.9", 301), "other IP"),
            (variant(22, Some(10), "10.0.0.1", 306), "outside the window"),
            (variant(22, Some(11), "10.0.0.1", 301), "different parent"),
        ] {
            let chain = base(other);
            // Generation 1 is a benign fork itself here; keep the budget out
            // of the way.
            let mut p = params();
            p.max_benign = 5;
            assert!(
                matches!(evaluate_chain(&chain, &p), ChainVerdict::Compromised { .. }),
                "{why}"
            );
        }
    }

    #[test]
    fn double_continuation_compromises() {
        // Benign fork at 2, then each branch refreshed.
        let chain = vec![
            gen_of(1, vec![variant(10, None, "10.0.0.1", 0)]),
            gen_of(
                2,
                vec![
                    variant(21, Some(10), "10.0.0.1", 300),
                    variant(22, Some(10), "10.0.0.1", 301),
                ],
            ),
            gen_of(
                3,
                vec![
                    variant(31, Some(21), "10.0.0.1", 600),
                    variant(32, Some(22), "10.0.0.1", 601),
                ],
            ),
        ];
        let mut p = params();
        p.max_benign = 5;
        assert!(matches!(
            evaluate_chain(&chain, &p),
            ChainVerdict::Compromised { .. }
        ));
    }

    #[test]
    fn continuation_of_an_unknown_token_compromises() {
        let chain = vec![
            gen_of(4, vec![variant(40, Some(30), "10.0.0.1", 0)]),
            gen_of(5, vec![variant(50, Some(99), "10.0.0.1", 300)]),
        ];
        assert!(matches!(
            evaluate_chain(&chain, &params()),
            ChainVerdict::Compromised { .. }
        ));
    }

    #[test]
    fn the_benign_budget_is_enforced() {
        let mut chain = vec![gen_of(1, vec![variant(10, None, "10.0.0.1", 0)])];
        for g in 2..=3u32 {
            let parent = u128::from(g - 1) * 10;
            let t = i64::from(g) * 300;
            chain.push(gen_of(
                g,
                vec![
                    variant(u128::from(g) * 10, Some(parent), "10.0.0.1", t),
                    variant(u128::from(g) * 10 + 1, Some(parent), "10.0.0.1", t + 1),
                ],
            ));
        }
        assert!(
            matches!(
                evaluate_chain(&chain, &params()),
                ChainVerdict::Compromised { .. }
            ),
            "two benign forks within an hour, one allowed"
        );
        let mut p = params();
        p.budget_window = chrono::Duration::seconds(100);
        assert!(matches!(
            evaluate_chain(&chain, &p),
            ChainVerdict::Clean { .. }
        ));
        p.max_benign = 0;
        assert!(matches!(
            evaluate_chain(&chain, &p),
            ChainVerdict::Compromised { .. }
        ));
    }

    #[test]
    fn fingerprint_criterion_needs_both_fingerprints() {
        let mut p = params();
        p.retry_match = RetryMatch {
            ip: false,
            user_agent: false,
            fingerprint: true,
        };
        let mut a = variant(21, Some(10), "10.0.0.1", 300);
        let mut b = variant(22, Some(10), "10.0.0.2", 301);
        let chain = |a: &GenerationVariant, b: &GenerationVariant| {
            vec![
                gen_of(1, vec![variant(10, None, "10.0.0.1", 0)]),
                gen_of(2, vec![a.clone(), b.clone()]),
            ]
        };
        assert!(matches!(
            evaluate_chain(&chain(&a, &b), &p),
            ChainVerdict::Compromised { .. }
        ));
        a.fingerprint_hash = Some([1; 32]);
        b.fingerprint_hash = Some([1; 32]);
        assert!(matches!(
            evaluate_chain(&chain(&a, &b), &p),
            ChainVerdict::Clean { .. }
        ));
    }
}
