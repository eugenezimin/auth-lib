//! In-memory implementations of every z-auth repository port.
//!
//! **Test-only** — lets the core test suite run without a database.  A single
//! [`InMemoryDb`] implements all ports over shared state so cross-port
//! behaviour (user → roles joins, delete cascades) matches a relational store.
//! Like a real database it owns the clock: every timestamp comes from the
//! injected [`Clock`], so tests can time-travel by advancing it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use z_auth::prelude::*;
use z_auth::security::authorization::{
    EffectiveGrants, PermissionAssignment, PermissionGrant, PermissionOption,
};
use z_auth::security::session::IssueContext;
use z_auth::security::token::KeyStatus;
#[cfg(feature = "shared")]
use z_auth_cluster::prelude::*;

#[derive(Default)]
struct State {
    users: HashMap<Uuid, User>,
    roles: HashMap<Uuid, Role>,
    user_roles: Vec<UserRole>,
    sessions: HashMap<Uuid, Session>,
    /// session ID → generations, oldest first
    generations: HashMap<Uuid, Vec<SessionGeneration>>,
    revocations: Vec<Revocation>,
    permissions: HashMap<Uuid, Permission>,
    /// Last position handed out (positions start at 1, never reused).
    last_position: u32,
    user_grants: Vec<GrantRow>,
    role_grants: Vec<GrantRow>,
    keys: HashMap<String, VerifyingKeyRecord>,
    #[cfg(feature = "shared")]
    nodes: HashMap<Uuid, NodeRecord>,
    #[cfg(feature = "shared")]
    node_writes: usize,
    #[cfg(feature = "shared")]
    node_reads: usize,
    /// node id → when it was retired (federation mode)
    #[cfg(feature = "shared")]
    retired_at: HashMap<Uuid, DateTime<Utc>>,

    // ── sync (federation mode) ──────────────────────────────────────────
    /// (kind, key) → seq of the record's latest change
    feed: HashMap<(&'static str, String), u64>,
    seq: u64,
    site_id: Option<Uuid>,
    /// session id → revision, bumped by every session write
    session_revs: HashMap<Uuid, u64>,
    /// session id → losing fork variants: (generation, variant)
    #[cfg(feature = "federation")]
    alias_variants: HashMap<Uuid, Vec<(u32, z_auth_cluster::federation::GenerationVariant)>>,
    #[cfg(feature = "federation")]
    accounts: HashMap<Uuid, z_auth_cluster::federation::AccountSnapshot>,
    #[cfg(feature = "federation")]
    catalog_snapshot: Option<z_auth_cluster::federation::CatalogSnapshot>,
    #[cfg(feature = "federation")]
    cursors:
        HashMap<z_auth_cluster::federation::SiteId, z_auth_cluster::federation::FeedCursor>,
    caught_up: HashMap<String, DateTime<Utc>>,
    versions: u64,
    /// Records applied from other clusters (for "no ping-pong" checks).
    applied: usize,
}

const FEED_SESSION: &str = "session";
const FEED_REVOCATION: &str = "revocation";
const FEED_KEY: &str = "verifying_key";
#[cfg(feature = "federation")]
const FEED_ACCOUNT: &str = "account";
#[cfg(feature = "federation")]
const FEED_CATALOG: &str = "catalog";

impl State {
    /// Record a change in the feed, as the Postgres triggers do.
    fn touch(&mut self, kind: &'static str, key: impl Into<String>) {
        self.seq += 1;
        let key = key.into();
        if kind == FEED_SESSION
            && let Ok(id) = key.parse::<Uuid>()
        {
            *self.session_revs.entry(id).or_default() += 1;
        }
        self.feed.insert((kind, key), self.seq);
    }
}

/// One stored grant row: a `bool` (no option, no text), one chosen option,
/// or a `text` value.  `owner` is a user or a role id.
#[derive(Clone)]
struct GrantRow {
    owner: Uuid,
    permission_id: Uuid,
    option_id: Option<Uuid>,
    text: Option<String>,
}

pub struct InMemoryDb {
    state: Mutex<State>,
    calls: AtomicUsize,
    clock: Arc<dyn Clock>,
}

impl InMemoryDb {
    /// A store whose "database time" is `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Mutex::default(),
            calls: AtomicUsize::new(0),
            clock,
        }
    }

    fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.state.lock().expect("in-memory state poisoned")
    }

    /// Number of repository calls made so far (any port).
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Stored generation numbers of a session, oldest first.
    pub fn generation_numbers(&self, session_id: Uuid) -> Vec<u32> {
        self.lock()
            .generations
            .get(&session_id)
            .map(|g| g.iter().map(|g| g.generation).collect())
            .unwrap_or_default()
    }

    /// Persisted revocations (for assertions).
    pub fn revocations(&self) -> Vec<Revocation> {
        self.lock().revocations.clone()
    }
}

impl State {
    fn with_roles(&self, user: &User) -> UserWithRoles {
        let roles = self
            .user_roles
            .iter()
            .filter(|ur| ur.user_id == user.id && ur.revoked_at.is_none())
            .filter_map(|ur| self.roles.get(&ur.role_id).cloned())
            .collect();
        UserWithRoles {
            user: user.clone(),
            roles,
        }
    }

    fn user_by<F: Fn(&User) -> bool>(&self, pred: F) -> Option<&User> {
        self.users.values().find(|u| pred(u))
    }
}

/// Usernames match case-insensitively (see the `UserRepository` contract).
fn same_username(user: &User, username: &str) -> bool {
    user.username
        .as_deref()
        .is_some_and(|u| u.to_lowercase() == username.to_lowercase())
}

// ── UserRepository ────────────────────────────────────────────────────────────

#[async_trait]
impl UserRepository for InMemoryDb {
    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, AuthError> {
        Ok(self.lock().users.get(&user_id).cloned())
    }
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        Ok(self.lock().user_by(|u| u.email == email).cloned())
    }
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError> {
        Ok(self.lock().user_by(|u| same_username(u, username)).cloned())
    }
    async fn find_with_roles_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        let s = self.lock();
        Ok(s.users.get(&user_id).map(|u| s.with_roles(u)))
    }
    async fn find_with_roles_by_email(
        &self,
        email: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        let s = self.lock();
        Ok(s.user_by(|u| u.email == email).map(|u| s.with_roles(u)))
    }
    async fn list(&self, query: &UserQuery) -> Result<UserPage, AuthError> {
        let needle = query.search.as_deref().map(str::to_lowercase);
        let s = self.lock();
        let mut matching: Vec<&User> = s
            .users
            .values()
            .filter(|u| match &needle {
                None => true,
                Some(n) => {
                    u.email.to_lowercase().contains(n)
                        || u.username
                            .as_deref()
                            .is_some_and(|name| name.to_lowercase().contains(n))
                }
            })
            .collect();
        matching.sort_by_key(|u| std::cmp::Reverse((u.created_at, u.id)));
        Ok(UserPage {
            total: matching.len() as u64,
            items: matching
                .into_iter()
                .skip(query.offset as usize)
                .take(query.limit as usize)
                .cloned()
                .collect(),
        })
    }
    async fn find_with_roles_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        let s = self.lock();
        Ok(s.user_by(|u| same_username(u, username))
            .map(|u| s.with_roles(u)))
    }
    async fn exists_by_email(&self, email: &str) -> Result<bool, AuthError> {
        Ok(self.lock().user_by(|u| u.email == email).is_some())
    }
    async fn exists_by_username(&self, username: &str) -> Result<bool, AuthError> {
        Ok(self
            .lock()
            .user_by(|u| same_username(u, username))
            .is_some())
    }
    async fn create(&self, new_user: NewUser) -> Result<User, AuthError> {
        let mut s = self.lock();
        if s.user_by(|u| u.email == new_user.email).is_some() {
            return Err(AuthError::EmailAlreadyTaken);
        }
        if let Some(ref username) = new_user.username
            && s.user_by(|u| same_username(u, username)).is_some()
        {
            return Err(AuthError::UsernameAlreadyTaken);
        }
        let now = self.now();
        let user = User {
            id: Uuid::new_v4(),
            email: new_user.email,
            password_hash: Some(new_user.password_hash),
            username: new_user.username,
            first_name: new_user.first_name,
            last_name: new_user.last_name,
            avatar_url: None,
            is_active: true,
            is_verified: false,
            created_at: now,
            updated_at: now,
        };
        s.users.insert(user.id, user.clone());
        Ok(user)
    }
    async fn update(&self, user_id: Uuid, update: UserUpdate) -> Result<Option<User>, AuthError> {
        let mut s = self.lock();
        if let Some(ref email) = update.email
            && s.user_by(|u| u.id != user_id && &u.email == email)
                .is_some()
        {
            return Err(AuthError::EmailAlreadyTaken);
        }
        if let Some(ref username) = update.username
            && s.user_by(|u| u.id != user_id && same_username(u, username))
                .is_some()
        {
            return Err(AuthError::UsernameAlreadyTaken);
        }
        let Some(user) = s.users.get_mut(&user_id) else {
            return Ok(None);
        };
        if let Some(v) = update.email {
            user.email = v;
        }
        if let Some(v) = update.password_hash {
            user.password_hash = Some(v);
        }
        if let Some(v) = update.username {
            user.username = Some(v);
        }
        if let Some(v) = update.first_name {
            user.first_name = Some(v);
        }
        if let Some(v) = update.last_name {
            user.last_name = Some(v);
        }
        if let Some(v) = update.avatar_url {
            user.avatar_url = Some(v);
        }
        user.updated_at = self.now();
        Ok(Some(user.clone()))
    }
    async fn delete(&self, user_id: Uuid) -> Result<Option<Uuid>, AuthError> {
        let mut s = self.lock();
        if s.users.remove(&user_id).is_none() {
            return Ok(None);
        }
        s.user_roles.retain(|ur| ur.user_id != user_id);
        s.user_grants.retain(|g| g.owner != user_id);
        let owned: Vec<Uuid> = s
            .sessions
            .values()
            .filter(|sess| sess.user_id == user_id)
            .map(|sess| sess.id)
            .collect();
        for id in owned {
            s.sessions.remove(&id);
            s.generations.remove(&id);
        }
        Ok(Some(user_id))
    }
    async fn activate(&self, user_id: Uuid) -> Result<bool, AuthError> {
        Ok(self
            .lock()
            .users
            .get_mut(&user_id)
            .map(|u| u.is_active = true)
            .is_some())
    }
    async fn deactivate(&self, user_id: Uuid) -> Result<bool, AuthError> {
        Ok(self
            .lock()
            .users
            .get_mut(&user_id)
            .map(|u| u.is_active = false)
            .is_some())
    }
    async fn is_active(&self, user_id: Uuid) -> Result<Option<bool>, AuthError> {
        Ok(self.lock().users.get(&user_id).map(|u| u.is_active))
    }
    async fn is_verified(&self, user_id: Uuid) -> Result<Option<bool>, AuthError> {
        Ok(self.lock().users.get(&user_id).map(|u| u.is_verified))
    }
}

// ── RoleRepository ────────────────────────────────────────────────────────────

#[async_trait]
impl RoleRepository for InMemoryDb {
    async fn create(&self, new_role: &NewRole) -> Result<Role, AuthError> {
        let mut s = self.lock();
        if s.roles
            .values()
            .any(|r| r.name == new_role.name || r.code == new_role.code)
        {
            return Err(AuthError::RoleAlreadyExists);
        }
        let role = Role {
            id: Uuid::new_v4(),
            code: new_role.code.clone(),
            name: new_role.name.clone(),
            description: new_role.description.clone(),
            created_at: self.now(),
        };
        s.roles.insert(role.id, role.clone());
        Ok(role)
    }
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Role>, AuthError> {
        Ok(self.lock().roles.get(&id).cloned())
    }
    async fn find_by_name(&self, name: &str) -> Result<Option<Role>, AuthError> {
        Ok(self.lock().roles.values().find(|r| r.name == name).cloned())
    }
    async fn find_by_code(&self, code: &str) -> Result<Option<Role>, AuthError> {
        Ok(self.lock().roles.values().find(|r| r.code == code).cloned())
    }
    async fn update(&self, id: Uuid, update: &RoleUpdate) -> Result<Option<Role>, AuthError> {
        let mut s = self.lock();
        if let Some(ref name) = update.name
            && s.roles.values().any(|r| r.id != id && &r.name == name)
        {
            return Err(AuthError::RoleAlreadyExists);
        }
        let Some(role) = s.roles.get_mut(&id) else {
            return Ok(None);
        };
        if let Some(ref name) = update.name {
            role.name = name.clone();
        }
        if let Some(ref description) = update.description {
            role.description = description.clone();
        }
        Ok(Some(role.clone()))
    }
    async fn list_all(&self) -> Result<Vec<Role>, AuthError> {
        let mut roles: Vec<Role> = self.lock().roles.values().cloned().collect();
        roles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(roles)
    }
    async fn delete(&self, id: Uuid) -> Result<Option<Uuid>, AuthError> {
        let mut s = self.lock();
        if s.roles.remove(&id).is_none() {
            return Ok(None);
        }
        s.user_roles.retain(|ur| ur.role_id != id);
        s.role_grants.retain(|g| g.owner != id);
        Ok(Some(id))
    }
    async fn exists_by_name(&self, name: &str) -> Result<bool, AuthError> {
        Ok(self.lock().roles.values().any(|r| r.name == name))
    }
}

// ── UserRoleRepository ────────────────────────────────────────────────────────

#[async_trait]
impl UserRoleRepository for InMemoryDb {
    async fn assign(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        let mut s = self.lock();
        let active = s
            .user_roles
            .iter()
            .any(|ur| ur.user_id == user_id && ur.role_id == role_id && ur.revoked_at.is_none());
        if active {
            return Ok(false);
        }
        s.user_roles.push(UserRole {
            id: Uuid::new_v4(),
            user_id,
            role_id,
            assigned_at: self.now(),
            revoked_at: None,
        });
        Ok(true)
    }
    async fn revoke(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        let mut s = self.lock();
        match s
            .user_roles
            .iter_mut()
            .find(|ur| ur.user_id == user_id && ur.role_id == role_id && ur.revoked_at.is_none())
        {
            Some(ur) => {
                ur.revoked_at = Some(self.now());
                Ok(true)
            }
            None => Ok(false),
        }
    }
    async fn is_role_active(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        Ok(self
            .lock()
            .user_roles
            .iter()
            .any(|ur| ur.user_id == user_id && ur.role_id == role_id && ur.revoked_at.is_none()))
    }
    async fn list_active_for_user(&self, user_id: Uuid) -> Result<Vec<UserRole>, AuthError> {
        let mut v: Vec<UserRole> = self
            .lock()
            .user_roles
            .iter()
            .filter(|ur| ur.user_id == user_id && ur.revoked_at.is_none())
            .cloned()
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.assigned_at));
        Ok(v)
    }
    async fn list_all_for_user(&self, user_id: Uuid) -> Result<Vec<UserRole>, AuthError> {
        let mut v: Vec<UserRole> = self
            .lock()
            .user_roles
            .iter()
            .filter(|ur| ur.user_id == user_id)
            .cloned()
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.assigned_at));
        Ok(v)
    }
    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64, AuthError> {
        let now = self.now();
        let mut count = 0;
        for ur in self
            .lock()
            .user_roles
            .iter_mut()
            .filter(|ur| ur.user_id == user_id && ur.revoked_at.is_none())
        {
            ur.revoked_at = Some(now);
            count += 1;
        }
        Ok(count)
    }

    async fn list_active_holders(&self, role_id: Uuid) -> Result<Vec<Uuid>, AuthError> {
        let mut ids: Vec<Uuid> = self
            .lock()
            .user_roles
            .iter()
            .filter(|ur| ur.role_id == role_id && ur.revoked_at.is_none())
            .map(|ur| ur.user_id)
            .collect();
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
}

// ── SessionRepository ─────────────────────────────────────────────────────────

fn is_live(s: &Session, now: DateTime<Utc>) -> bool {
    s.status == SessionStatus::Active && s.idle_expires_at > now && s.absolute_expires_at > now
}

fn new_generation(
    session_id: Uuid,
    generation: u32,
    issued: &IssueContext,
    now: DateTime<Utc>,
    lifetimes: &SessionLifetimes,
) -> SessionGeneration {
    SessionGeneration {
        session_id,
        generation,
        access_jti: Uuid::new_v4(),
        issued_ip: issued.ip,
        issued_at: now,
        access_expires_at: now + lifetimes.access_ttl,
        superseded_at: None,
        parent_jti: issued.parent_jti,
        issued_user_agent: issued.user_agent.clone(),
        fingerprint_hash: issued.fingerprint_hash,
        aliases: Vec::new(),
    }
}

impl State {
    fn generation(&self, session_id: Uuid, generation: u32) -> Option<SessionGeneration> {
        self.generations
            .get(&session_id)
            .and_then(|gens| gens.iter().find(|g| g.generation == generation).cloned())
    }
}

#[async_trait]
impl SessionRepository for InMemoryDb {
    async fn create(
        &self,
        new: NewSession,
        lifetimes: &SessionLifetimes,
    ) -> Result<(Session, SessionGeneration), AuthError> {
        let now = self.now();
        let session = Session {
            id: Uuid::new_v4(),
            user_id: new.user_id,
            secret: new.secret.clone(),
            status: SessionStatus::Active,
            end_reason: None,
            created_ip: new.created_ip,
            user_agent: new.user_agent.clone(),
            current_generation: 1,
            created_at: now,
            idle_expires_at: now + lifetimes.idle_timeout,
            absolute_expires_at: now + lifetimes.absolute_timeout,
            ended_at: None,
        };
        let first = new_generation(
            session.id,
            1,
            &IssueContext {
                ip: session.created_ip,
                user_agent: session.user_agent.clone(),
                fingerprint_hash: new.fingerprint_hash,
                parent_jti: None,
            },
            now,
            lifetimes,
        );
        let mut s = self.lock();
        s.generations.insert(session.id, vec![first.clone()]);
        s.sessions.insert(session.id, session.clone());
        s.touch(FEED_SESSION, session.id.to_string());
        Ok((session, first))
    }

    async fn find(&self, session_id: Uuid) -> Result<Option<Session>, AuthError> {
        Ok(self.lock().sessions.get(&session_id).cloned())
    }

    async fn find_generation(
        &self,
        session_id: Uuid,
        generation: u32,
    ) -> Result<Option<SessionGeneration>, AuthError> {
        Ok(self.lock().generation(session_id, generation))
    }

    async fn load_for_refresh(
        &self,
        session_id: Uuid,
        generation: u32,
    ) -> Result<Option<RefreshSnapshot>, AuthError> {
        let now = self.now();
        let s = self.lock();
        Ok(s.sessions.get(&session_id).map(|session| RefreshSnapshot {
            presented: s.generation(session_id, generation),
            current: s.generation(session_id, session.current_generation),
            session: session.clone(),
            now,
        }))
    }

    async fn rotate(
        &self,
        session_id: Uuid,
        expected_generation: u32,
        issued: &IssueContext,
        lifetimes: &SessionLifetimes,
    ) -> Result<RotateOutcome, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        let Some(session) = s.sessions.get_mut(&session_id) else {
            return Ok(RotateOutcome::Conflict);
        };
        if session.status != SessionStatus::Active
            || session.current_generation != expected_generation
        {
            return Ok(RotateOutcome::Conflict);
        }
        let newest = expected_generation + 1;
        session.current_generation = newest;
        session.idle_expires_at = now + lifetimes.idle_timeout;
        let session = session.clone();

        let generation = new_generation(session_id, newest, issued, now, lifetimes);
        let gens = s.generations.entry(session_id).or_default();
        if let Some(prev) = gens
            .iter_mut()
            .find(|g| g.generation == expected_generation)
        {
            prev.superseded_at = Some(now);
        }
        gens.push(generation.clone());
        gens.retain(|g| g.generation + lifetimes.history_size > newest);
        #[cfg(feature = "federation")]
        if let Some(aliases) = s.alias_variants.get_mut(&session_id) {
            aliases.retain(|(g, _)| g + lifetimes.history_size > newest);
        }
        s.touch(FEED_SESSION, session_id.to_string());
        Ok(RotateOutcome::Rotated {
            session,
            generation,
        })
    }

    async fn end(
        &self,
        session_id: Uuid,
        status: SessionStatus,
        reason: RevocationReason,
    ) -> Result<bool, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        match s.sessions.get_mut(&session_id) {
            Some(session) if session.status == SessionStatus::Active => {
                session.status = status;
                session.end_reason = Some(reason);
                session.ended_at = Some(now);
                s.touch(FEED_SESSION, session_id.to_string());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn end_all_for_user(
        &self,
        user_id: Uuid,
        status: SessionStatus,
        reason: RevocationReason,
    ) -> Result<Vec<Uuid>, AuthError> {
        let now = self.now();
        let mut ended = Vec::new();
        let mut s = self.lock();
        for session in s.sessions.values_mut() {
            if session.user_id == user_id && session.status == SessionStatus::Active {
                session.status = status;
                session.end_reason = Some(reason);
                session.ended_at = Some(now);
                ended.push(session.id);
            }
        }
        for id in &ended {
            s.touch(FEED_SESSION, id.to_string());
        }
        Ok(ended)
    }

    async fn mark_compromised(
        &self,
        session_id: Uuid,
        reason: RevocationReason,
    ) -> Result<bool, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        match s.sessions.get_mut(&session_id) {
            Some(session) => {
                session.status = SessionStatus::Compromised;
                session.end_reason = Some(reason);
                session.ended_at.get_or_insert(now);
                s.touch(FEED_SESSION, session_id.to_string());
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn list_active_for_user(&self, user_id: Uuid) -> Result<Vec<Session>, AuthError> {
        let now = self.now();
        let mut active: Vec<Session> = self
            .lock()
            .sessions
            .values()
            .filter(|s| s.user_id == user_id && is_live(s, now))
            .cloned()
            .collect();
        active.sort_by_key(|s| s.created_at);
        Ok(active)
    }

    async fn purge(&self, retention: Duration) -> Result<u64, AuthError> {
        let before = self.now() - retention;
        let mut s = self.lock();
        let dead: Vec<Uuid> = s
            .sessions
            .values()
            .filter(|sess| {
                sess.ended_at.is_some_and(|at| at < before)
                    || sess.idle_expires_at < before
                    || sess.absolute_expires_at < before
            })
            .map(|sess| sess.id)
            .collect();
        for id in &dead {
            s.sessions.remove(id);
            s.generations.remove(id);
        }
        Ok(dead.len() as u64)
    }
}

// ── RevocationRepository ──────────────────────────────────────────────────────

#[async_trait]
impl RevocationRepository for InMemoryDb {
    async fn insert(&self, new: &NewRevocation) -> Result<Revocation, AuthError> {
        let now = self.now();
        let revocation = Revocation {
            id: Uuid::new_v4(),
            scope: new.scope,
            reason: new.reason,
            status: RevocationStatus::Pending,
            origin_node: new.origin_node,
            revoked_at: now,
            expires_at: now + new.ttl,
            enforced_at: None,
            enforced_by: None,
        };
        let mut s = self.lock();
        s.revocations.push(revocation.clone());
        s.touch(FEED_REVOCATION, revocation.id.to_string());
        Ok(revocation)
    }

    async fn mark_enforced(&self, id: Uuid, by: Uuid) -> Result<Option<Revocation>, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        let enforced = s
            .revocations
            .iter_mut()
            .find(|r| r.id == id && r.status == RevocationStatus::Pending)
            .map(|r| {
                r.status = RevocationStatus::Enforced;
                r.enforced_at = Some(now);
                r.enforced_by = Some(by);
                r.clone()
            });
        if enforced.is_some() {
            s.touch(FEED_REVOCATION, id.to_string());
        }
        Ok(enforced)
    }

    async fn list_active(&self) -> Result<Vec<Revocation>, AuthError> {
        let now = self.now();
        Ok(self
            .lock()
            .revocations
            .iter()
            .filter(|r| r.expires_at > now)
            .cloned()
            .collect())
    }

    async fn purge_expired(&self) -> Result<u64, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        let before = s.revocations.len();
        s.revocations.retain(|r| r.expires_at > now);
        Ok((before - s.revocations.len()) as u64)
    }
}

// ── KeyRepository ─────────────────────────────────────────────────────────────

#[async_trait]
impl KeyRepository for InMemoryDb {
    async fn publish(&self, key: &NewVerifyingKey) -> Result<VerifyingKeyRecord, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        if let Some(existing) = s.keys.get(&key.kid) {
            return Ok(existing.clone());
        }
        let record = VerifyingKeyRecord {
            kid: key.kid.clone(),
            public_key: key.public_key,
            status: KeyStatus::Active,
            published_by: Some(key.published_by),
            created_at: now,
            revoked_at: None,
        };
        s.keys.insert(key.kid.clone(), record.clone());
        s.touch(FEED_KEY, key.kid.clone());
        Ok(record)
    }

    async fn revoke(&self, kid: &str) -> Result<Option<VerifyingKeyRecord>, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        let mut changed = false;
        let record = s.keys.get_mut(kid).map(|k| {
            if k.status == KeyStatus::Active {
                k.status = KeyStatus::Revoked;
                k.revoked_at = Some(now);
                changed = true;
            }
            k.clone()
        });
        if changed {
            s.touch(FEED_KEY, kid.to_string());
        }
        Ok(record)
    }

    async fn list(&self) -> Result<Vec<VerifyingKeyRecord>, AuthError> {
        Ok(self.lock().keys.values().cloned().collect())
    }
}

// ── NodeRepository ────────────────────────────────────────────────────────────

#[cfg(feature = "shared")]
impl InMemoryDb {
    /// A node's registry row (for assertions).
    pub fn node(&self, node_id: Uuid) -> Option<NodeRecord> {
        self.lock().nodes.get(&node_id).cloned()
    }

    /// Remove a node from the registry (simulates a node the others only
    /// learn about through gossip).
    pub fn drop_node(&self, node_id: Uuid) {
        self.lock().nodes.remove(&node_id);
    }

    /// Registry writes so far (inserts, updates, deletes that changed a row).
    pub fn node_writes(&self) -> usize {
        self.lock().node_writes
    }

    /// Registry reads (`list`) so far.
    pub fn node_reads(&self) -> usize {
        self.lock().node_reads
    }

    /// Every registry row (for assertions).
    pub fn nodes(&self) -> Vec<NodeRecord> {
        self.lock().nodes.values().cloned().collect()
    }
}

#[cfg(feature = "shared")]
#[async_trait]
impl NodeRepository for InMemoryDb {
    async fn register(&self, node: &NodeInfo) -> Result<(), AuthError> {
        let now = self.now();
        let mut s = self.lock();
        s.node_writes += 1;
        s.nodes.insert(
            node.node_id,
            NodeRecord {
                info: node.clone(),
                state: NodeState::Joining,
                heartbeat: HeartbeatStatus::Online,
                state_changed_at: now,
                heartbeat_changed_at: now,
            },
        );
        Ok(())
    }

    async fn restore(&self, node: &NodeInfo, state: NodeState) -> Result<bool, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        let changed = match s.nodes.get_mut(&node.node_id) {
            Some(n) if n.heartbeat == HeartbeatStatus::Online => false,
            Some(n) => {
                n.heartbeat = HeartbeatStatus::Online;
                n.heartbeat_changed_at = now;
                true
            }
            None => {
                s.nodes.insert(
                    node.node_id,
                    NodeRecord {
                        info: node.clone(),
                        state,
                        heartbeat: HeartbeatStatus::Online,
                        state_changed_at: now,
                        heartbeat_changed_at: now,
                    },
                );
                true
            }
        };
        s.node_writes += usize::from(changed);
        Ok(changed)
    }

    async fn transition(&self, node_id: Uuid, t: NodeTransition) -> Result<bool, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        let Some(n) = s.nodes.get_mut(&node_id) else {
            return Ok(false);
        };
        let (st, hb) = (n.state, n.heartbeat);
        let changed = match t {
            NodeTransition::Activate if st == NodeState::Joining => {
                n.state = NodeState::Active;
                n.state_changed_at = now;
                true
            }
            NodeTransition::BeginLeave if st != NodeState::Leaving => {
                n.state = NodeState::Leaving;
                n.state_changed_at = now;
                true
            }
            NodeTransition::MarkOffline if hb == HeartbeatStatus::Online => {
                n.heartbeat = HeartbeatStatus::Offline;
                n.heartbeat_changed_at = now;
                true
            }
            NodeTransition::MarkOnline if hb == HeartbeatStatus::Offline => {
                n.heartbeat = HeartbeatStatus::Online;
                n.heartbeat_changed_at = now;
                true
            }
            NodeTransition::Remove if st == NodeState::Leaving => {
                s.nodes.remove(&node_id);
                true
            }
            NodeTransition::Expire if hb == HeartbeatStatus::Offline => {
                s.nodes.remove(&node_id);
                true
            }
            _ => false,
        };
        s.node_writes += usize::from(changed);
        Ok(changed)
    }

    async fn list(&self) -> Result<Vec<NodeRecord>, AuthError> {
        let mut s = self.lock();
        s.node_reads += 1;
        Ok(s.nodes.values().cloned().collect())
    }

    async fn evict(&self, target: Uuid, observer: Uuid) -> Result<EvictOutcome, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        let status = |s: &State, id| s.nodes.get(&id).map(|n| n.heartbeat);
        let outcome = match (status(&s, observer), status(&s, target)) {
            (None | Some(HeartbeatStatus::Missing), _) => EvictOutcome::ObserverMissing,
            (_, None | Some(HeartbeatStatus::Missing)) => EvictOutcome::AlreadyMissing,
            _ => {
                let n = s.nodes.get_mut(&target).expect("checked above");
                n.heartbeat = HeartbeatStatus::Missing;
                n.heartbeat_changed_at = now;
                s.retired_at.insert(target, now);
                s.node_writes += 1;
                EvictOutcome::Evicted
            }
        };
        Ok(outcome)
    }

    async fn update_address(&self, node: &NodeInfo) -> Result<bool, AuthError> {
        let mut s = self.lock();
        let changed = match s.nodes.get_mut(&node.node_id) {
            Some(n) if n.heartbeat != HeartbeatStatus::Missing && n.info != *node => {
                n.info = node.clone();
                true
            }
            _ => false,
        };
        s.node_writes += usize::from(changed);
        Ok(changed)
    }

    async fn purge_retired(&self, older_than: Duration) -> Result<u64, AuthError> {
        let now = self.now();
        let horizon = chrono::Duration::from_std(older_than).unwrap_or(chrono::Duration::MAX);
        let mut s = self.lock();
        let expired: Vec<Uuid> = s
            .retired_at
            .iter()
            .filter(|(_, at)| now - **at > horizon)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            s.retired_at.remove(id);
            s.nodes.remove(id);
        }
        s.node_writes += expired.len();
        Ok(expired.len() as u64)
    }
}

impl InMemoryDb {
    /// A stored revocation (for assertions).
    pub fn revocation(&self, id: Uuid) -> Option<Revocation> {
        self.lock().revocations.iter().find(|r| r.id == id).cloned()
    }
}

// ── PermissionRepository ──────────────────────────────────────────────────────

impl State {
    fn next_position(&mut self) -> u32 {
        self.last_position += 1;
        self.last_position
    }

    fn catalog_version(&self) -> u64 {
        self.permissions
            .values()
            .flat_map(|p| {
                p.position
                    .into_iter()
                    .chain(p.options.iter().map(|o| o.position))
            })
            .max()
            .unwrap_or(0) as u64
    }

    fn replace_grant(rows: &mut Vec<GrantRow>, owner: Uuid, a: &PermissionAssignment) {
        rows.retain(|g| !(g.owner == owner && g.permission_id == a.permission_id));
        let row = |option_id, text| GrantRow {
            owner,
            permission_id: a.permission_id,
            option_id,
            text,
        };
        if a.option_ids.is_empty() {
            rows.push(row(None, a.text.clone()));
        } else {
            rows.extend(a.option_ids.iter().map(|&o| row(Some(o), None)));
        }
    }

    fn clear_grant(rows: &mut Vec<GrantRow>, owner: Uuid, permission_id: Uuid) -> bool {
        let before = rows.len();
        rows.retain(|g| !(g.owner == owner && g.permission_id == permission_id));
        rows.len() != before
    }

    /// The owner's rows folded into one assignment per permission, ordered
    /// by permission id with sorted option ids (as the Postgres adapter).
    fn list_grants(rows: &[GrantRow], owner: Uuid) -> Vec<PermissionAssignment> {
        let mut by_permission: std::collections::BTreeMap<Uuid, PermissionAssignment> =
            std::collections::BTreeMap::new();
        for g in rows.iter().filter(|g| g.owner == owner) {
            let a = by_permission
                .entry(g.permission_id)
                .or_insert_with(|| PermissionAssignment {
                    permission_id: g.permission_id,
                    option_ids: Vec::new(),
                    text: g.text.clone(),
                });
            a.option_ids.extend(g.option_id);
        }
        by_permission
            .into_values()
            .map(|mut a| {
                a.option_ids.sort();
                a
            })
            .collect()
    }
}

#[async_trait]
impl PermissionRepository for InMemoryDb {
    async fn create(&self, new: &NewPermission) -> Result<Permission, AuthError> {
        let now = self.now();
        let mut s = self.lock();
        if s.permissions.values().any(|p| p.code == new.code) {
            return Err(AuthError::PermissionAlreadyExists);
        }
        let position = match new.kind {
            PermissionKind::Bool | PermissionKind::Text { .. } => Some(s.next_position()),
            PermissionKind::Single | PermissionKind::Multi => None,
        };
        let options = new
            .options
            .iter()
            .map(|code| PermissionOption {
                id: Uuid::new_v4(),
                code: code.clone(),
                position: s.next_position(),
            })
            .collect();
        let permission = Permission {
            id: Uuid::new_v4(),
            code: new.code.clone(),
            kind: new.kind,
            description: new.description.clone(),
            position,
            options,
            created_at: now,
        };
        s.permissions.insert(permission.id, permission.clone());
        Ok(permission)
    }

    async fn add_option(
        &self,
        permission_id: Uuid,
        option_code: &str,
    ) -> Result<Permission, AuthError> {
        let mut s = self.lock();
        let position = s.next_position();
        let permission = s
            .permissions
            .get_mut(&permission_id)
            .ok_or(AuthError::PermissionNotFound)?;
        permission.options.push(PermissionOption {
            id: Uuid::new_v4(),
            code: option_code.into(),
            position,
        });
        Ok(permission.clone())
    }

    async fn delete(&self, permission_id: Uuid) -> Result<bool, AuthError> {
        let mut s = self.lock();
        s.user_grants.retain(|g| g.permission_id != permission_id);
        s.role_grants.retain(|g| g.permission_id != permission_id);
        Ok(s.permissions.remove(&permission_id).is_some())
    }

    async fn find_by_code(&self, code: &str) -> Result<Option<Permission>, AuthError> {
        Ok(self
            .lock()
            .permissions
            .values()
            .find(|p| p.code == code)
            .cloned())
    }

    async fn load_catalog(&self) -> Result<PermissionCatalog, AuthError> {
        let s = self.lock();
        let mut permissions: Vec<Permission> = s.permissions.values().cloned().collect();
        permissions.sort_by(|a, b| a.code.cmp(&b.code));
        Ok(PermissionCatalog {
            version: s.catalog_version(),
            permissions,
        })
    }

    async fn replace_user_grant(
        &self,
        user_id: Uuid,
        assignment: &PermissionAssignment,
    ) -> Result<(), AuthError> {
        State::replace_grant(&mut self.lock().user_grants, user_id, assignment);
        Ok(())
    }

    async fn clear_user_grant(
        &self,
        user_id: Uuid,
        permission_id: Uuid,
    ) -> Result<bool, AuthError> {
        Ok(State::clear_grant(
            &mut self.lock().user_grants,
            user_id,
            permission_id,
        ))
    }

    async fn replace_role_grant(
        &self,
        role_id: Uuid,
        assignment: &PermissionAssignment,
    ) -> Result<(), AuthError> {
        State::replace_grant(&mut self.lock().role_grants, role_id, assignment);
        Ok(())
    }

    async fn list_user_grants(&self, user_id: Uuid) -> Result<Vec<PermissionAssignment>, AuthError> {
        Ok(State::list_grants(&self.lock().user_grants, user_id))
    }

    async fn list_role_grants(&self, role_id: Uuid) -> Result<Vec<PermissionAssignment>, AuthError> {
        Ok(State::list_grants(&self.lock().role_grants, role_id))
    }

    async fn clear_role_grant(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> Result<bool, AuthError> {
        Ok(State::clear_grant(
            &mut self.lock().role_grants,
            role_id,
            permission_id,
        ))
    }

    /// Same merge rules as the Postgres adapter: `bool` OR, `multi` union,
    /// `single` / `text` → direct grant, else the role with the lowest code.
    async fn effective_grants(
        &self,
        user_id: Uuid,
        include_role_grants: bool,
    ) -> Result<EffectiveGrants, AuthError> {
        let s = self.lock();
        // (rank, role code, row): direct grants rank 0, role grants rank 1.
        let mut sources: Vec<(u8, String, &GrantRow)> = s
            .user_grants
            .iter()
            .filter(|g| g.owner == user_id)
            .map(|g| (0, String::new(), g))
            .collect();
        if include_role_grants {
            for ur in s
                .user_roles
                .iter()
                .filter(|ur| ur.user_id == user_id && ur.revoked_at.is_none())
            {
                let code = s
                    .roles
                    .get(&ur.role_id)
                    .map(|r| r.code.clone())
                    .unwrap_or_default();
                sources.extend(
                    s.role_grants
                        .iter()
                        .filter(|g| g.owner == ur.role_id)
                        .map(|g| (1, code.clone(), g)),
                );
            }
        }

        let mut grants = Vec::new();
        for permission in s.permissions.values() {
            let mut rows: Vec<&(u8, String, &GrantRow)> = sources
                .iter()
                .filter(|(_, _, g)| g.permission_id == permission.id)
                .collect();
            rows.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
            let option_position = |id: Option<Uuid>| {
                permission
                    .options
                    .iter()
                    .find(|o| Some(o.id) == id)
                    .map(|o| o.position)
            };
            let grant = |position| PermissionGrant {
                position,
                text: None,
            };
            match permission.kind {
                PermissionKind::Bool => {
                    if !rows.is_empty() {
                        grants.extend(permission.position.map(grant));
                    }
                }
                PermissionKind::Multi => {
                    let mut positions: Vec<u32> = rows
                        .iter()
                        .filter_map(|r| option_position(r.2.option_id))
                        .collect();
                    positions.sort();
                    positions.dedup();
                    grants.extend(positions.into_iter().map(grant));
                }
                PermissionKind::Single => {
                    if let Some(first) = rows.first() {
                        grants.extend(option_position(first.2.option_id).map(grant));
                    }
                }
                PermissionKind::Text { .. } => {
                    if let (Some(first), Some(position)) = (rows.first(), permission.position) {
                        grants.push(PermissionGrant {
                            position,
                            text: first.2.text.clone(),
                        });
                    }
                }
            }
        }
        grants.sort_by_key(|g| g.position);
        Ok(EffectiveGrants {
            catalog_version: s.catalog_version(),
            grants,
        })
    }
}

// ── SyncStore (federation mode) ───────────────────────────────────────────────

#[cfg(feature = "federation")]
mod sync_store {
    use super::*;
    use z_auth_cluster::federation::{
        AccountSnapshot, ApplyOutcome, CatalogSnapshot, ChangePage, FeedCursor, GenerationVariant,
        SessionAggregate, SiteId, SyncRecord, SyncStore, merge_key, merge_revocation,
    };

    impl State {
        fn aggregate(&self, id: Uuid) -> Option<SessionAggregate> {
            let session = self.sessions.get(&id)?;
            let aliases = self.alias_variants.get(&id);
            let gens: Vec<(SessionGeneration, Vec<GenerationVariant>)> = self
                .generations
                .get(&id)
                .map(|gens| {
                    gens.iter()
                        .map(|g| {
                            let variants = aliases
                                .map(|a| {
                                    a.iter()
                                        .filter(|(n, _)| *n == g.generation)
                                        .map(|(_, v)| v.clone())
                                        .collect()
                                })
                                .unwrap_or_default();
                            (g.clone(), variants)
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(SessionAggregate::from_parts(session, &gens))
        }

        fn record(&self, kind: &str, key: &str) -> Option<SyncRecord> {
            match kind {
                FEED_SESSION => self
                    .aggregate(key.parse().ok()?)
                    .map(|a| SyncRecord::Session(Box::new(a))),
                FEED_REVOCATION => {
                    let id: Uuid = key.parse().ok()?;
                    self.revocations
                        .iter()
                        .find(|r| r.id == id)
                        .cloned()
                        .map(SyncRecord::Revocation)
                }
                FEED_KEY => self.keys.get(key).cloned().map(SyncRecord::VerifyingKey),
                FEED_ACCOUNT => self
                    .accounts
                    .get(&key.parse().ok()?)
                    .cloned()
                    .map(SyncRecord::Account),
                FEED_CATALOG => self
                    .catalog_snapshot
                    .clone()
                    .map(|c| SyncRecord::Catalog(Box::new(c))),
                _ => None,
            }
        }
    }

    impl InMemoryDb {
        /// Records this database applied from other clusters.
        pub fn applied(&self) -> usize {
            self.lock().applied
        }

        /// Feed entries (any origin) — "did anything new get written?"
        pub fn feed_seq(&self) -> u64 {
            self.lock().seq
        }

        /// Every session aggregate, sorted (for convergence checks).
        pub fn session_aggregates(&self) -> Vec<SessionAggregate> {
            let s = self.lock();
            let mut ids: Vec<Uuid> = s.sessions.keys().copied().collect();
            ids.sort();
            ids.into_iter().filter_map(|id| s.aggregate(id)).collect()
        }

        /// Stored account snapshot (for assertions).
        pub fn account(&self, user_id: Uuid) -> Option<AccountSnapshot> {
            self.lock().accounts.get(&user_id).cloned()
        }

        /// Number of stored users (session stores have none).
        pub fn user_count(&self) -> usize {
            self.lock().users.len()
        }

        pub fn has_session(&self, id: Uuid) -> bool {
            self.lock().sessions.contains_key(&id)
        }
    }

    #[async_trait]
    impl SyncStore for InMemoryDb {
        async fn site_id(&self) -> Result<SiteId, AuthError> {
            let mut s = self.lock();
            Ok(SiteId(*s.site_id.get_or_insert_with(Uuid::new_v4)))
        }

        async fn head(&self) -> Result<FeedCursor, AuthError> {
            Ok(FeedCursor {
                txid: 0,
                seq: self.lock().seq,
            })
        }

        async fn changes_since(
            &self,
            after: FeedCursor,
            limit: u32,
        ) -> Result<ChangePage, AuthError> {
            let site = self.site_id().await?;
            let s = self.lock();
            let mut entries: Vec<(u64, &(&'static str, String))> = s
                .feed
                .iter()
                .filter(|(_, seq)| **seq > after.seq)
                .map(|(k, seq)| (*seq, k))
                .collect();
            entries.sort_by_key(|(seq, _)| *seq);
            let more = entries.len() > limit as usize;
            entries.truncate(limit as usize);
            let next = entries
                .last()
                .map(|(seq, _)| FeedCursor { txid: 0, seq: *seq })
                .unwrap_or(after);
            let records = entries
                .iter()
                .filter_map(|(_, (kind, key))| s.record(kind, key))
                .collect();
            Ok(ChangePage {
                site,
                records,
                next,
                more,
            })
        }

        async fn load_session(
            &self,
            id: Uuid,
        ) -> Result<Option<(SessionAggregate, u64)>, AuthError> {
            let s = self.lock();
            Ok(s.aggregate(id)
                .map(|a| (a, s.session_revs.get(&id).copied().unwrap_or(0))))
        }

        async fn store_session(
            &self,
            merged: &SessionAggregate,
            expected: Option<u64>,
        ) -> Result<ApplyOutcome, AuthError> {
            let id = merged.session.id;
            let mut s = self.lock();
            let current = s
                .sessions
                .contains_key(&id)
                .then(|| s.session_revs.get(&id).copied().unwrap_or(0));
            if current != expected {
                return Ok(ApplyOutcome::Conflict);
            }
            if s.aggregate(id).as_ref() == Some(merged) {
                return Ok(ApplyOutcome::Unchanged);
            }
            let stored = merged.stored_generations();
            s.sessions.insert(id, merged.to_session());
            s.generations
                .insert(id, stored.iter().map(|(g, _)| g.clone()).collect());
            s.alias_variants.insert(
                id,
                stored
                    .iter()
                    .flat_map(|(g, aliases)| aliases.iter().map(|v| (g.generation, v.clone())))
                    .collect(),
            );
            s.applied += 1;
            s.touch(FEED_SESSION, id.to_string());
            Ok(ApplyOutcome::Applied)
        }

        async fn active_session_ids(&self, user_id: Uuid) -> Result<Vec<Uuid>, AuthError> {
            let s = self.lock();
            let mut ids: Vec<Uuid> = s
                .sessions
                .values()
                .filter(|x| x.user_id == user_id && x.status == SessionStatus::Active)
                .map(|x| x.id)
                .collect();
            ids.sort();
            Ok(ids)
        }

        async fn merge_revocation(&self, r: &Revocation) -> Result<ApplyOutcome, AuthError> {
            let mut s = self.lock();
            match s.revocations.iter().position(|x| x.id == r.id) {
                Some(i) => {
                    let merged = merge_revocation(&s.revocations[i], r);
                    if merged == s.revocations[i] {
                        return Ok(ApplyOutcome::Unchanged);
                    }
                    s.revocations[i] = merged;
                }
                None => s.revocations.push(r.clone()),
            }
            s.applied += 1;
            s.touch(FEED_REVOCATION, r.id.to_string());
            Ok(ApplyOutcome::Applied)
        }

        async fn merge_key(&self, k: &VerifyingKeyRecord) -> Result<ApplyOutcome, AuthError> {
            let mut s = self.lock();
            let merged = match s.keys.get(&k.kid) {
                Some(existing) => {
                    let merged = merge_key(existing, k);
                    if &merged == existing {
                        return Ok(ApplyOutcome::Unchanged);
                    }
                    merged
                }
                None => k.clone(),
            };
            s.keys.insert(k.kid.clone(), merged);
            s.applied += 1;
            s.touch(FEED_KEY, k.kid.clone());
            Ok(ApplyOutcome::Applied)
        }

        async fn apply_account(&self, a: &AccountSnapshot) -> Result<ApplyOutcome, AuthError> {
            let mut s = self.lock();
            if s.accounts
                .get(&a.user_id)
                .is_some_and(|x| x.version >= a.version)
            {
                return Ok(ApplyOutcome::Unchanged);
            }
            s.accounts.insert(a.user_id, a.clone());
            s.applied += 1;
            s.touch(FEED_ACCOUNT, a.user_id.to_string());
            Ok(ApplyOutcome::Applied)
        }

        async fn load_account(&self, user_id: Uuid) -> Result<Option<AccountSnapshot>, AuthError> {
            Ok(self.lock().accounts.get(&user_id).cloned())
        }

        async fn apply_catalog(&self, c: &CatalogSnapshot) -> Result<ApplyOutcome, AuthError> {
            let mut s = self.lock();
            if s.catalog_snapshot
                .as_ref()
                .is_some_and(|x| x.version >= c.version)
            {
                return Ok(ApplyOutcome::Unchanged);
            }
            s.catalog_snapshot = Some(c.clone());
            s.applied += 1;
            s.touch(FEED_CATALOG, "catalog");
            Ok(ApplyOutcome::Applied)
        }

        async fn load_catalog(&self) -> Result<Option<CatalogSnapshot>, AuthError> {
            Ok(self.lock().catalog_snapshot.clone())
        }

        async fn cursor(&self, site: SiteId) -> Result<FeedCursor, AuthError> {
            Ok(self.lock().cursors.get(&site).copied().unwrap_or_default())
        }

        async fn advance_cursor(&self, site: SiteId, to: FeedCursor) -> Result<(), AuthError> {
            let mut s = self.lock();
            let c = s.cursors.entry(site).or_default();
            *c = (*c).max(to);
            Ok(())
        }

        async fn reset_cursor(&self, site: SiteId) -> Result<(), AuthError> {
            self.lock().cursors.remove(&site);
            Ok(())
        }

        async fn next_version(&self) -> Result<u64, AuthError> {
            let mut s = self.lock();
            s.versions += 1;
            Ok(s.versions)
        }

        async fn record_caught_up(
            &self,
            service: &str,
            at: DateTime<Utc>,
        ) -> Result<(), AuthError> {
            let mut s = self.lock();
            let slot = s.caught_up.entry(service.to_string()).or_insert(at);
            *slot = (*slot).max(at);
            Ok(())
        }

        async fn caught_up_at(&self, service: &str) -> Result<Option<DateTime<Utc>>, AuthError> {
            Ok(self.lock().caught_up.get(service).copied())
        }
    }
}
