//! Federation mode (database per service): what is synced between
//! clusters and how it merges.  Feature `federation`.
//!
//! The authority service (UMS) owns identity — users, roles, grants, the
//! catalog — and publishes what a refresh needs as account and catalog
//! snapshots.  Every other service keeps a session store.  Sessions,
//! revocations and verifying keys are written anywhere and merged with
//! lattice rules ([`merge`]); refresh forks are judged by [`fork`].
//! Protocol: `docs/replication.md`.

pub mod engine;
pub mod extension;
pub mod fork;
pub mod guard;
pub mod membership;
pub mod merge;
pub mod producer;
pub mod store;

pub use crate::sync::{
    AccountSnapshot, ApplyOutcome, CatalogSnapshot, ChangePage, FeedCursor, GenerationVariant,
    GenerationVariants, RecordKind, SessionAggregate, SiteId, SyncMessage, SyncRecord, SyncSession,
};
pub use engine::{FederationEngine, FederationReport, config_fingerprint};
pub use extension::{Federation, SessionRepositories};
pub use fork::{BenignFork, ChainVerdict, ForkParams, evaluate_chain};
pub use merge::{
    MergeParams, SessionMerge, merge_account, merge_catalog, merge_key, merge_revocation,
    merge_session,
};
pub use store::SyncStore;
