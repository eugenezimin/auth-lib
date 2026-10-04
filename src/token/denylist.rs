//! In-memory denylist consulted on every access-token verification.
//!
//! Pure `std`: read-mostly maps with O(1) lookups and no I/O.  Entries only
//! need to live as long as an access token (see [`Revocation::expires_at`]),
//! so memory stays bounded.  Filled locally by
//! [`TokenRevocationService`](crate::token::TokenRevocationService), at
//! startup from the store, and by revocations pushed from other instances.
//!
//! A token covered by a **pending** revocation is rejected *and* recorded as
//! an [`EnforcementHit`]; the revocation service later enforces it (marks the
//! revocation enforced and the session compromised).

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, RwLock};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::AuthError;
use crate::token::model::{Claims, EnforcementHit, Revocation, RevocationScope, RevocationStatus};

#[derive(Default)]
struct Inner {
    /// revocation id → revocation (the source for snapshots and digests)
    all: HashMap<Uuid, Revocation>,
    /// session id → revocation ids
    sessions: HashMap<Uuid, Vec<Uuid>>,
    /// user id → revocation ids
    users: HashMap<Uuid, Vec<Uuid>>,
}

#[derive(Default)]
struct Hits {
    queue: Vec<EnforcementHit>,
    /// Revocations already queued once — enforce each at most once.
    recorded: HashSet<Uuid>,
}

#[derive(Default)]
pub struct Denylist {
    inner: RwLock<Inner>,
    hits: Mutex<Hits>,
}

impl Denylist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a revocation, or merge it into the one with the same id
    /// (`Enforced` wins over `Pending`).  Idempotent; returns `true` if the
    /// denylist changed.
    pub fn apply(&self, revocation: &Revocation) -> bool {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = inner.all.get_mut(&revocation.id) {
            if revocation.status > existing.status {
                existing.status = revocation.status;
                existing.enforced_at = revocation.enforced_at;
                existing.enforced_by = revocation.enforced_by;
                return true;
            }
            return false;
        }
        let index = match revocation.scope {
            RevocationScope::Session(sid) => inner.sessions.entry(sid).or_default(),
            RevocationScope::User(uid) => inner.users.entry(uid).or_default(),
        };
        index.push(revocation.id);
        inner.all.insert(revocation.id, revocation.clone());
        true
    }

    /// Reject tokens whose session is revoked, or whose user was revoked at
    /// or after the token's `iat`.  A hit on a pending revocation is
    /// recorded for enforcement.
    pub fn check(&self, claims: &Claims, now: DateTime<Utc>) -> Result<(), AuthError> {
        let hit = {
            let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
            let live = |id: &Uuid| inner.all.get(id).filter(|r| r.expires_at > now);
            let by_session = inner
                .sessions
                .get(&claims.sid)
                .into_iter()
                .flatten()
                .filter_map(live);
            let by_user = inner
                .users
                .get(&claims.sub)
                .into_iter()
                .flatten()
                .filter_map(live)
                .filter(|r| claims.iat <= r.revoked_at.timestamp());
            let mut matched = by_session.chain(by_user).peekable();
            if matched.peek().is_none() {
                return Ok(());
            }
            matched
                .find(|r| r.status == RevocationStatus::Pending)
                .map(|r| EnforcementHit {
                    revocation_id: r.id,
                    session_id: claims.sid,
                })
        };
        if let Some(hit) = hit {
            let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
            if hits.recorded.insert(hit.revocation_id) {
                hits.queue.push(hit);
            }
        }
        Err(AuthError::TokenRevoked)
    }

    /// Take the recorded enforcement hits.
    pub fn drain_hits(&self) -> Vec<EnforcementHit> {
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut hits.queue)
    }

    /// Every live revocation, sorted by id — for snapshots and digests.
    pub fn entries(&self, now: DateTime<Utc>) -> Vec<Revocation> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut live: Vec<Revocation> = inner
            .all
            .values()
            .filter(|r| r.expires_at > now)
            .cloned()
            .collect();
        live.sort_by_key(|r| r.id);
        live
    }

    /// Drop entries that have expired.  Returns how many were removed.
    pub fn prune(&self, now: DateTime<Utc>) -> usize {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let expired: Vec<Uuid> = inner
            .all
            .values()
            .filter(|r| r.expires_at <= now)
            .map(|r| r.id)
            .collect();
        for id in &expired {
            inner.all.remove(id);
        }
        let Inner {
            all,
            sessions,
            users,
        } = &mut *inner;
        sessions.retain(|_, ids| {
            ids.retain(|id| all.contains_key(id));
            !ids.is_empty()
        });
        users.retain(|_, ids| {
            ids.retain(|id| all.contains_key(id));
            !ids.is_empty()
        });
        drop(inner);
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        for id in &expired {
            hits.recorded.remove(id);
        }
        expired.len()
    }

    /// Number of entries (live or not yet pruned).
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .all
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::model::RevocationReason;
    use std::time::Duration;

    fn revocation(scope: RevocationScope, now: DateTime<Utc>) -> Revocation {
        Revocation {
            id: Uuid::new_v4(),
            scope,
            reason: RevocationReason::Logout,
            status: RevocationStatus::Pending,
            origin_node: Uuid::new_v4(),
            revoked_at: now,
            expires_at: now + Duration::from_secs(300),
            enforced_at: None,
            enforced_by: None,
        }
    }

    fn claims(sub: Uuid, sid: Uuid, iat: i64) -> Claims {
        Claims {
            sub,
            sid,
            jti: Uuid::new_v4(),
            generation: 1,
            iss: "t".into(),
            iat,
            exp: iat + 300,
            authz: None,
        }
    }

    #[test]
    fn pending_hits_are_recorded_once_and_enforced_wins() {
        let now = Utc::now();
        let list = Denylist::new();
        let sid = Uuid::new_v4();
        let mut r = revocation(RevocationScope::Session(sid), now);
        assert!(list.apply(&r));
        assert!(!list.apply(&r), "idempotent");

        let c = claims(Uuid::new_v4(), sid, now.timestamp());
        assert!(list.check(&c, now).is_err());
        assert!(list.check(&c, now).is_err());
        let hits = list.drain_hits();
        assert_eq!(hits.len(), 1, "one hit per revocation");
        assert_eq!(hits[0].session_id, sid);

        r.status = RevocationStatus::Enforced;
        r.enforced_at = Some(now);
        assert!(list.apply(&r), "enforced wins");
        r.status = RevocationStatus::Pending;
        assert!(!list.apply(&r), "never back to pending");
        assert!(list.check(&c, now).is_err(), "still rejected");
        assert!(list.drain_hits().is_empty(), "enforced: nothing to record");
    }

    #[test]
    fn user_cutoff_and_expiry() {
        let now = Utc::now();
        let list = Denylist::new();
        let uid = Uuid::new_v4();
        list.apply(&revocation(RevocationScope::User(uid), now));
        assert!(
            list.check(&claims(uid, Uuid::new_v4(), now.timestamp()), now)
                .is_err()
        );
        let later = now.timestamp() + 1;
        assert!(
            list.check(&claims(uid, Uuid::new_v4(), later), now).is_ok(),
            "issued after"
        );

        let after = now + Duration::from_secs(301);
        assert!(
            list.check(&claims(uid, Uuid::new_v4(), now.timestamp()), after)
                .is_ok()
        );
        assert_eq!(list.prune(after), 1);
        assert!(list.is_empty());
    }
}
