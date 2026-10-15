//! Merge rules for synced records — lattice joins: commutative, associative
//! and idempotent, so clusters converge whatever order (or how many times)
//! records arrive in.
//!
//! | record | rule |
//! |--------|------|
//! | session status | `active < revoked < compromised`; `ended_at` = earliest end; `end_reason` from the earliest end of the winning status |
//! | session expiry | `idle_expires_at` = latest; `current_generation` = highest |
//! | generations | union of variants per generation; forks judged by [`evaluate_chain`]; a compromising fork ends the session; trimmed to `history_size` |
//! | revocation | `enforced` wins; earliest `enforced_at` (and its `enforced_by`); earliest `revoked_at`; latest `expires_at` |
//! | verifying key | `revoked` wins; earliest `revoked_at` |
//! | account / catalog snapshot | higher `version` wins |

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::federation::fork::{BenignFork, ChainVerdict, ForkParams, evaluate_chain};
use crate::sync::{
    AccountSnapshot, CatalogSnapshot, GenerationVariant, GenerationVariants, SessionAggregate,
    SyncSession,
};
use z_auth::security::session::RevocationReason;
use z_auth::security::session::SessionStatus;
use z_auth::security::token::model::{KeyStatus, Revocation, RevocationStatus, VerifyingKeyRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeParams {
    pub fork: ForkParams,
    pub history_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMerge {
    pub merged: SessionAggregate,
    /// Differs from the local state.
    pub changed: bool,
    /// Active locally (or unknown), ended now.
    pub newly_ended: bool,
    /// Benign forks the local state did not know about.
    pub new_benign_forks: Vec<BenignFork>,
}

fn status_rank(s: SessionStatus) -> u8 {
    match s {
        SessionStatus::Active => 0,
        SessionStatus::Revoked => 1,
        SessionStatus::Compromised => 2,
    }
}

/// A fixed order for tie-breaks.
fn reason_rank(r: RevocationReason) -> u8 {
    use RevocationReason::*;
    match r {
        Logout => 0,
        LogoutAll => 1,
        Evicted => 2,
        TokenReuse => 3,
        IpMismatch => 4,
        Compromised => 5,
        Administrative => 6,
        PasswordChanged => 7,
        AccountDisabled => 8,
        AccountDeleted => 9,
        RevokedTokenUsed => 10,
        ConcurrentRefresh => 11,
    }
}

fn min_opt<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// How a session ended, as one candidate among several.
#[derive(Clone, Copy)]
struct End {
    status: SessionStatus,
    at: Option<DateTime<Utc>>,
    reason: Option<RevocationReason>,
}

fn end_of(s: &SyncSession) -> End {
    End {
        status: s.status,
        at: s.ended_at,
        reason: s.end_reason,
    }
}

/// Union of two generation lists (variants by jti; `superseded_at` the
/// earliest), then each generation's `superseded_at` normalised.
fn union_generations(
    a: &[GenerationVariants],
    b: &[GenerationVariants],
) -> Vec<GenerationVariants> {
    let mut by_gen: BTreeMap<u32, BTreeMap<uuid::Uuid, GenerationVariant>> = BTreeMap::new();
    for g in a.iter().chain(b) {
        let slot = by_gen.entry(g.generation).or_default();
        for v in &g.variants {
            slot.entry(v.access_jti)
                .and_modify(|existing| {
                    existing.superseded_at = min_opt(existing.superseded_at, v.superseded_at);
                })
                .or_insert_with(|| v.clone());
        }
    }
    let mut out: Vec<GenerationVariants> = by_gen
        .into_iter()
        .map(|(generation, variants)| GenerationVariants {
            generation,
            variants: variants.into_values().collect(),
        })
        .collect();
    // A generation is superseded once the next one exists: at the earliest
    // of what was recorded and when the next one was issued.
    for i in 0..out.len() {
        let next_issued = out
            .get(i + 1)
            .filter(|n| n.generation == out[i].generation + 1)
            .and_then(|n| n.variants.iter().map(|v| v.issued_at).min());
        let recorded = out[i].variants.iter().filter_map(|v| v.superseded_at).min();
        let superseded = min_opt(recorded, next_issued);
        for v in &mut out[i].variants {
            v.superseded_at = superseded;
        }
    }
    out
}

fn benign_of(generations: &[GenerationVariants], p: &ForkParams) -> Vec<BenignFork> {
    match evaluate_chain(generations, p) {
        ChainVerdict::Clean { benign } => benign,
        ChainVerdict::Compromised { .. } => Vec::new(),
    }
}

/// Merge `incoming` into `local` (either order gives the same result).
pub fn merge_session(
    local: Option<&SessionAggregate>,
    incoming: &SessionAggregate,
    p: &MergeParams,
) -> SessionMerge {
    let base = local.unwrap_or(incoming);
    let generations = union_generations(
        local.map(|l| l.generations.as_slice()).unwrap_or_default(),
        &incoming.generations,
    );

    let mut ends = vec![end_of(&incoming.session)];
    ends.extend(local.map(|l| end_of(&l.session)));
    let verdict = evaluate_chain(&generations, &p.fork);
    if let ChainVerdict::Compromised { at } = verdict {
        ends.push(End {
            status: SessionStatus::Compromised,
            at: Some(at),
            reason: Some(RevocationReason::TokenReuse),
        });
    }
    let status = ends
        .iter()
        .map(|e| e.status)
        .max_by_key(|s| status_rank(*s))
        .unwrap_or(SessionStatus::Active);
    let ended_at = ends.iter().fold(None, |acc, e| min_opt(acc, e.at));
    let end_reason = ends
        .iter()
        .filter(|e| e.status == status && e.reason.is_some())
        .min_by_key(|e| {
            (
                e.at.unwrap_or(DateTime::<Utc>::MAX_UTC),
                e.reason.map(reason_rank),
            )
        })
        .and_then(|e| e.reason);

    let current_generation = generations
        .last()
        .map(|g| g.generation)
        .unwrap_or(0)
        .max(base.session.current_generation)
        .max(incoming.session.current_generation);
    let keep_from = current_generation.saturating_sub(p.history_size);
    let generations: Vec<GenerationVariants> = generations
        .into_iter()
        .filter(|g| g.generation > keep_from)
        .collect();

    let s = &base.session;
    let merged = SessionAggregate {
        session: SyncSession {
            id: s.id,
            user_id: s.user_id,
            secret: s.secret.clone(),
            status,
            end_reason: if status == SessionStatus::Active {
                None
            } else {
                end_reason
            },
            created_ip: s.created_ip,
            user_agent: s.user_agent.clone(),
            current_generation,
            created_at: s.created_at.min(incoming.session.created_at),
            idle_expires_at: s.idle_expires_at.max(incoming.session.idle_expires_at),
            absolute_expires_at: s
                .absolute_expires_at
                .min(incoming.session.absolute_expires_at),
            ended_at: if status == SessionStatus::Active {
                None
            } else {
                ended_at
            },
        },
        generations,
    };

    let known = local
        .map(|l| benign_of(&l.generations, &p.fork))
        .unwrap_or_default();
    let new_benign_forks = match verdict {
        ChainVerdict::Clean { benign } => {
            benign.into_iter().filter(|f| !known.contains(f)).collect()
        }
        ChainVerdict::Compromised { .. } => Vec::new(),
    };
    let was_active = local.is_none_or(|l| l.session.status == SessionStatus::Active);
    SessionMerge {
        changed: local != Some(&merged),
        newly_ended: was_active && merged.session.status != SessionStatus::Active,
        new_benign_forks,
        merged,
    }
}

/// Merge two copies of the same revocation.
pub fn merge_revocation(a: &Revocation, b: &Revocation) -> Revocation {
    let status = a.status.max(b.status);
    let enforcement = [a, b]
        .into_iter()
        .filter(|r| r.status == RevocationStatus::Enforced)
        .filter_map(|r| r.enforced_at.map(|at| (at, r.enforced_by)))
        .min();
    Revocation {
        id: a.id,
        scope: a.scope,
        reason: if reason_rank(a.reason) <= reason_rank(b.reason) {
            a.reason
        } else {
            b.reason
        },
        status,
        origin_node: a.origin_node.min(b.origin_node),
        revoked_at: a.revoked_at.min(b.revoked_at),
        expires_at: a.expires_at.max(b.expires_at),
        enforced_at: enforcement.map(|(at, _)| at),
        enforced_by: enforcement.and_then(|(_, by)| by),
    }
}

/// Merge two copies of the same verifying key.
pub fn merge_key(a: &VerifyingKeyRecord, b: &VerifyingKeyRecord) -> VerifyingKeyRecord {
    let status = a.status.max(b.status);
    VerifyingKeyRecord {
        kid: a.kid.clone(),
        public_key: a.public_key,
        status,
        published_by: min_opt(a.published_by, b.published_by),
        created_at: a.created_at.min(b.created_at),
        revoked_at: if status == KeyStatus::Revoked {
            min_opt(a.revoked_at, b.revoked_at)
        } else {
            None
        },
    }
}

/// The newer account snapshot.
pub fn merge_account(a: &AccountSnapshot, b: &AccountSnapshot) -> AccountSnapshot {
    if b.version > a.version {
        b.clone()
    } else {
        a.clone()
    }
}

/// The newer catalog snapshot.
pub fn merge_catalog(a: &CatalogSnapshot, b: &CatalogSnapshot) -> CatalogSnapshot {
    if b.version > a.version {
        b.clone()
    } else {
        a.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::fork::tests::{gen_of, params, variant};
    use uuid::Uuid;

    fn p(history: u32) -> MergeParams {
        let mut fork = params();
        fork.max_benign = 10;
        MergeParams {
            fork,
            history_size: history,
        }
    }

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    fn session(generations: Vec<GenerationVariants>) -> SessionAggregate {
        SessionAggregate {
            session: SyncSession {
                id: Uuid::from_u128(1),
                user_id: Uuid::from_u128(2),
                secret: vec![9; 32],
                status: SessionStatus::Active,
                end_reason: None,
                created_ip: "10.0.0.1".parse().unwrap(),
                user_agent: None,
                current_generation: generations.last().map(|g| g.generation).unwrap_or(1),
                created_at: t(0),
                idle_expires_at: t(1800),
                absolute_expires_at: t(28_800),
                ended_at: None,
            },
            generations,
        }
    }

    fn base_chain(upto: u32) -> Vec<GenerationVariants> {
        (1..=upto)
            .map(|g| {
                let parent = (g > 1).then(|| u128::from(g - 1) * 10);
                gen_of(
                    g,
                    vec![variant(
                        u128::from(g) * 10,
                        parent,
                        "10.0.0.1",
                        i64::from(g) * 300,
                    )],
                )
            })
            .collect()
    }

    fn merge(a: &SessionAggregate, b: &SessionAggregate, prm: &MergeParams) -> SessionAggregate {
        merge_session(Some(a), b, prm).merged
    }

    /// A family of replicas of one session: rotations at different
    /// clusters, a benign fork, ends of different kinds and times.
    fn replicas() -> Vec<SessionAggregate> {
        let mut out = Vec::new();
        // Plain progress at two speeds.
        out.push(session(base_chain(2)));
        out.push(session(base_chain(4)));
        // A benign retry fork at generation 3 (same parent, IP, 1 s apart).
        let mut forked = base_chain(2);
        forked.push(gen_of(3, vec![variant(31, Some(20), "10.0.0.1", 901)]));
        let mut f = session(forked);
        f.session.idle_expires_at = t(2700);
        out.push(f);
        // Logged out at one cluster.
        let mut revoked = session(base_chain(3));
        revoked.session.status = SessionStatus::Revoked;
        revoked.session.end_reason = Some(RevocationReason::Logout);
        revoked.session.ended_at = Some(t(1000));
        out.push(revoked);
        // Compromised elsewhere, later.
        let mut compromised = session(base_chain(2));
        compromised.session.status = SessionStatus::Compromised;
        compromised.session.end_reason = Some(RevocationReason::IpMismatch);
        compromised.session.ended_at = Some(t(1200));
        out.push(compromised);
        out
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let prm = p(50);
        let all = replicas();
        for a in &all {
            assert_eq!(merge(a, a, &prm), merge(a, a, &prm));
            let aa = merge(a, a, &prm);
            assert_eq!(merge(&aa, a, &prm), aa, "idempotent");
            for b in &all {
                assert_eq!(merge(a, b, &prm), merge(b, a, &prm), "commutative");
                for c in &all {
                    assert_eq!(
                        merge(&merge(a, b, &prm), c, &prm),
                        merge(a, &merge(b, c, &prm), &prm),
                        "associative"
                    );
                }
            }
        }
    }

    #[test]
    fn every_delivery_order_converges() {
        let prm = p(50);
        let all = replicas();
        let mut results = Vec::new();
        // All permutations of the five replicas.
        let mut idx: Vec<usize> = (0..all.len()).collect();
        permute(&mut idx, 0, &mut |order| {
            let mut acc = all[order[0]].clone();
            for &i in &order[1..] {
                acc = merge(&acc, &all[i], &prm);
            }
            results.push(acc);
        });
        assert!(results.windows(2).all(|w| w[0] == w[1]));
        let final_state = &results[0];
        assert_eq!(final_state.session.status, SessionStatus::Compromised);
        assert_eq!(
            final_state.session.end_reason,
            Some(RevocationReason::IpMismatch)
        );
        assert_eq!(final_state.session.ended_at, Some(t(1000)), "earliest end");
        assert_eq!(final_state.session.current_generation, 4);
        assert_eq!(final_state.session.idle_expires_at, t(2700));
        let g3 = final_state
            .generations
            .iter()
            .find(|g| g.generation == 3)
            .unwrap();
        assert_eq!(g3.variants.len(), 2, "both variants of the fork kept");
        assert_eq!(
            g3.variants[0].access_jti,
            Uuid::from_u128(30),
            "lowest jti wins"
        );
    }

    fn permute(idx: &mut Vec<usize>, k: usize, f: &mut impl FnMut(&[usize])) {
        if k == idx.len() {
            f(idx);
            return;
        }
        for i in k..idx.len() {
            idx.swap(k, i);
            permute(idx, k + 1, f);
            idx.swap(k, i);
        }
    }

    #[test]
    fn a_benign_fork_is_reported_once() {
        let prm = p(50);
        let a = session(base_chain(3));
        let mut forked = base_chain(2);
        forked.push(gen_of(3, vec![variant(31, Some(20), "10.0.0.1", 901)]));
        let b = session(forked);
        let first = merge_session(Some(&a), &b, &prm);
        assert!(first.changed);
        assert!(!first.newly_ended);
        assert_eq!(first.new_benign_forks.len(), 1);
        assert_eq!(first.new_benign_forks[0].losers, vec![Uuid::from_u128(31)]);
        let again = merge_session(Some(&first.merged), &b, &prm);
        assert!(!again.changed, "nothing new: no write, no ping-pong");
        assert!(again.new_benign_forks.is_empty());
    }

    #[test]
    fn a_malicious_fork_ends_the_session_everywhere() {
        let prm = p(50);
        let a = session(base_chain(3));
        let mut forked = base_chain(2);
        forked.push(gen_of(3, vec![variant(31, Some(20), "10.9.9.9", 901)]));
        let b = session(forked);
        let m = merge_session(Some(&a), &b, &prm);
        assert!(m.newly_ended);
        assert_eq!(m.merged.session.status, SessionStatus::Compromised);
        assert_eq!(
            m.merged.session.end_reason,
            Some(RevocationReason::TokenReuse)
        );
        assert_eq!(m.merged, merge(&b, &a, &prm));
    }

    #[test]
    fn history_is_trimmed_and_superseded_times_filled_in() {
        let prm = p(3);
        let m = merge(&session(base_chain(2)), &session(base_chain(6)), &prm);
        let gens: Vec<u32> = m.generations.iter().map(|g| g.generation).collect();
        assert_eq!(gens, vec![4, 5, 6]);
        assert_eq!(m.generations[0].variants[0].superseded_at, Some(t(1500)));
        assert_eq!(m.generations[2].variants[0].superseded_at, None);
    }

    #[test]
    fn revocations_and_keys_merge_monotonically() {
        let pending = Revocation {
            id: Uuid::from_u128(5),
            scope: z_auth::security::token::model::RevocationScope::Session(Uuid::from_u128(1)),
            reason: RevocationReason::Logout,
            status: RevocationStatus::Pending,
            origin_node: Uuid::from_u128(7),
            revoked_at: t(10),
            expires_at: t(400),
            enforced_at: None,
            enforced_by: None,
        };
        let enforced_late = Revocation {
            status: RevocationStatus::Enforced,
            enforced_at: Some(t(30)),
            enforced_by: Some(Uuid::from_u128(9)),
            ..pending.clone()
        };
        let enforced_early = Revocation {
            status: RevocationStatus::Enforced,
            enforced_at: Some(t(20)),
            enforced_by: Some(Uuid::from_u128(8)),
            expires_at: t(500),
            ..pending.clone()
        };
        let m = merge_revocation(&merge_revocation(&pending, &enforced_late), &enforced_early);
        assert_eq!(
            m,
            merge_revocation(&enforced_early, &merge_revocation(&enforced_late, &pending))
        );
        assert_eq!(m.status, RevocationStatus::Enforced);
        assert_eq!(m.enforced_at, Some(t(20)));
        assert_eq!(m.enforced_by, Some(Uuid::from_u128(8)));
        assert_eq!(m.expires_at, t(500));

        let active = VerifyingKeyRecord {
            kid: "k".into(),
            public_key: [1; 32],
            status: KeyStatus::Active,
            published_by: None,
            created_at: t(0),
            revoked_at: None,
        };
        let revoked = VerifyingKeyRecord {
            status: KeyStatus::Revoked,
            revoked_at: Some(t(50)),
            published_by: Some(Uuid::from_u128(3)),
            ..active.clone()
        };
        let k = merge_key(&active, &revoked);
        assert_eq!(k, merge_key(&revoked, &active));
        assert_eq!(k.status, KeyStatus::Revoked);
        assert_eq!(k.published_by, Some(Uuid::from_u128(3)));
    }
}
