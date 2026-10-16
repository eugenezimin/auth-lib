//! Federation-mode data: what is synced between clusters, and how a
//! cluster's database feed is paged.  It sits below both
//! [`shared`](crate::shared) (whose wire format carries
//! [`SyncMessage`]) and [`federation`](crate::federation) (which
//! produces and merges it).
//!
//! Only state a refresh needs crosses clusters: sessions (with every
//! variant of every generation), revocations, verifying keys, and the
//! authority's account and catalog snapshots.  Users, roles and grants
//! stay in the authority's database.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use z_auth::security::authorization::model::PermissionCatalog;
use z_auth::security::session::RevocationReason;
use z_auth::security::session::{Session, SessionGeneration, SessionStatus};
use z_auth::security::token::model::{AuthzClaims, Revocation, VerifyingKeyRecord};

/// Identity of a cluster's database (created once, shared by its
/// instances).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct SiteId(pub Uuid);

/// Position in a database's change feed.  Postgres: `(txid, seq)`; an
/// in-memory store may use `(0, seq)`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct FeedCursor {
    pub txid: u64,
    pub seq: u64,
}

/// The kinds of record in the feed.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Session,
    Revocation,
    VerifyingKey,
    Account,
    Catalog,
}

/// A session as synced: everything except the generations.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SyncSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret: Vec<u8>,
    pub status: SessionStatus,
    pub end_reason: Option<RevocationReason>,
    pub created_ip: IpAddr,
    pub user_agent: Option<String>,
    /// Authentication methods the session was opened with (`amr`).
    #[serde(default)]
    pub amr: Vec<String>,
    pub current_generation: u32,
    pub created_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for SyncSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncSession")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("secret", &"<redacted>")
            .field("status", &self.status)
            .field("end_reason", &self.end_reason)
            .field("amr", &self.amr)
            .field("current_generation", &self.current_generation)
            .field("idle_expires_at", &self.idle_expires_at)
            .field("ended_at", &self.ended_at)
            .finish_non_exhaustive()
    }
}

/// One rotation of a generation.  Several exist when two clusters rotated
/// the same generation (a fork).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenerationVariant {
    pub access_jti: Uuid,
    pub parent_jti: Option<Uuid>,
    pub issued_ip: IpAddr,
    pub issued_user_agent: Option<String>,
    pub fingerprint_hash: Option<[u8; 32]>,
    pub issued_at: DateTime<Utc>,
    pub access_expires_at: DateTime<Utc>,
    pub superseded_at: Option<DateTime<Utc>>,
}

/// Every known variant of one generation, sorted by `access_jti`: the
/// first is the winner, the rest are aliases.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenerationVariants {
    pub generation: u32,
    pub variants: Vec<GenerationVariant>,
}

/// A session with all its generations — the unit merged between clusters.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionAggregate {
    pub session: SyncSession,
    /// Sorted by generation.
    pub generations: Vec<GenerationVariants>,
}

impl SessionAggregate {
    /// From a stored session and its generations (each with its aliases'
    /// full variants in `alias_variants`).
    pub fn from_parts(
        session: &Session,
        generations: &[(SessionGeneration, Vec<GenerationVariant>)],
    ) -> Self {
        let mut gens: Vec<GenerationVariants> = generations
            .iter()
            .map(|(g, aliases)| {
                let mut variants = vec![GenerationVariant {
                    access_jti: g.access_jti,
                    parent_jti: g.parent_jti,
                    issued_ip: g.issued_ip,
                    issued_user_agent: g.issued_user_agent.clone(),
                    fingerprint_hash: g.fingerprint_hash,
                    issued_at: g.issued_at,
                    access_expires_at: g.access_expires_at,
                    superseded_at: g.superseded_at,
                }];
                variants.extend(aliases.iter().cloned());
                variants.sort_by_key(|v| v.access_jti);
                variants.dedup_by_key(|v| v.access_jti);
                GenerationVariants {
                    generation: g.generation,
                    variants,
                }
            })
            .collect();
        gens.sort_by_key(|g| g.generation);
        Self {
            session: SyncSession {
                id: session.id,
                user_id: session.user_id,
                secret: session.secret.clone(),
                status: session.status,
                end_reason: session.end_reason,
                created_ip: session.created_ip,
                user_agent: session.user_agent.clone(),
                amr: session.amr.clone(),
                current_generation: session.current_generation,
                created_at: session.created_at,
                idle_expires_at: session.idle_expires_at,
                absolute_expires_at: session.absolute_expires_at,
                ended_at: session.ended_at,
            },
            generations: gens,
        }
    }

    pub fn to_session(&self) -> Session {
        let s = &self.session;
        Session {
            id: s.id,
            user_id: s.user_id,
            secret: s.secret.clone(),
            status: s.status,
            end_reason: s.end_reason,
            created_ip: s.created_ip,
            user_agent: s.user_agent.clone(),
            amr: s.amr.clone(),
            current_generation: s.current_generation,
            created_at: s.created_at,
            idle_expires_at: s.idle_expires_at,
            absolute_expires_at: s.absolute_expires_at,
            ended_at: s.ended_at,
        }
    }

    /// Stored form of each generation: the winner (lowest jti) with the
    /// others as aliases, plus the aliases' full variants.
    pub fn stored_generations(&self) -> Vec<(SessionGeneration, Vec<GenerationVariant>)> {
        self.generations
            .iter()
            .filter_map(|g| {
                let (winner, rest) = g.variants.split_first()?;
                Some((
                    SessionGeneration {
                        session_id: self.session.id,
                        generation: g.generation,
                        access_jti: winner.access_jti,
                        issued_ip: winner.issued_ip,
                        issued_at: winner.issued_at,
                        access_expires_at: winner.access_expires_at,
                        superseded_at: winner.superseded_at,
                        parent_jti: winner.parent_jti,
                        issued_user_agent: winner.issued_user_agent.clone(),
                        fingerprint_hash: winner.fingerprint_hash,
                        aliases: rest.iter().map(|v| v.access_jti).collect(),
                    },
                    rest.to_vec(),
                ))
            })
            .collect()
    }
}

/// What a refresh at a non-authority service needs to know about a user,
/// as last computed by the authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountSnapshot {
    pub user_id: Uuid,
    /// Monotonic per user; the newer snapshot wins.
    pub version: u64,
    pub is_active: bool,
    pub deleted: bool,
    pub authz: Option<AuthzClaims>,
}

/// The permission catalog as last published by the authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CatalogSnapshot {
    pub version: u64,
    pub catalog: PermissionCatalog,
}

/// One synced record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum SyncRecord {
    Session(Box<SessionAggregate>),
    Revocation(Revocation),
    VerifyingKey(VerifyingKeyRecord),
    Account(AccountSnapshot),
    Catalog(Box<CatalogSnapshot>),
}

impl SyncRecord {
    pub fn kind(&self) -> RecordKind {
        match self {
            Self::Session(_) => RecordKind::Session,
            Self::Revocation(_) => RecordKind::Revocation,
            Self::VerifyingKey(_) => RecordKind::VerifyingKey,
            Self::Account(_) => RecordKind::Account,
            Self::Catalog(_) => RecordKind::Catalog,
        }
    }

    /// The record's key within its kind.
    pub fn key(&self) -> String {
        match self {
            Self::Session(a) => a.session.id.to_string(),
            Self::Revocation(r) => r.id.to_string(),
            Self::VerifyingKey(k) => k.kid.clone(),
            Self::Account(a) => a.user_id.to_string(),
            Self::Catalog(_) => "catalog".into(),
        }
    }
}

/// One page of a database's change feed: the current state of each record
/// that changed after `after`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChangePage {
    pub site: SiteId,
    pub records: Vec<SyncRecord>,
    /// Pass back as `after` for the next page.
    pub next: FeedCursor,
    pub more: bool,
}

/// Result of applying one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The local state changed.
    Applied,
    /// Nothing new.
    Unchanged,
    /// Not stored: expired, purgeable, or (on-demand) not held here.
    Dropped,
    /// A concurrent local write won the compare-and-swap; retry.
    Conflict,
}

/// Federation messages between clusters (inside a cluster envelope).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SyncMessage {
    /// Read the receiver's feed after `after`; the reply is a `Page`.
    Pull {
        after: FeedCursor,
        limit: u32,
    },
    Page(ChangePage),
    /// A refresh met a session (or a user) this cluster does not have yet;
    /// the reply is a `SessionState`.
    FetchSession {
        session_id: Uuid,
        user_id: Uuid,
    },
    SessionState {
        session: Option<Box<SessionAggregate>>,
        account: Option<AccountSnapshot>,
    },
}
