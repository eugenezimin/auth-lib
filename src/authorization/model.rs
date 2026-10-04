//! Authorization domain models — the permission catalog, grants and the
//! decoded view of a token's permissions.
//!
//! Contains **only** plain data structures (plus small accessors).
//! - Persistence contract → [`crate::authorization::repository`]
//! - Token encoding       → [`crate::authorization::codec`]
//! - Service contracts    → [`crate::authorization::service`]

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

// ── Catalog ───────────────────────────────────────────────────────────────────

/// What kind of value a permission holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
pub enum PermissionKind {
    /// Granted or not.
    Bool,
    /// Exactly one of the permission's options.
    Single,
    /// Any subset of the permission's options.
    Multi,
    /// A free-form string of at most `max_length` characters.
    Text { max_length: u32 },
}

/// One choosable value of a `single` / `multi` permission.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PermissionOption {
    pub id: Uuid,
    pub code: String,
    /// Permanent position in the token encoding; never reused.
    pub position: u32,
}

/// A catalog entry, defined by the application.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Permission {
    pub id: Uuid,
    /// Immutable identifier used in code and UIs, e.g. `reports.export`.
    pub code: String,
    pub kind: PermissionKind,
    pub description: Option<String>,
    /// Permanent position of a `bool` / `text` permission; `None` for
    /// `single` / `multi`, whose options carry the positions.
    pub position: Option<u32>,
    pub options: Vec<PermissionOption>,
    pub created_at: DateTime<Utc>,
}

/// Ready-to-insert catalog entry.  The store assigns ids and positions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NewPermission {
    pub code: String,
    pub kind: PermissionKind,
    pub description: Option<String>,
    /// Option codes (`single` / `multi` only).
    pub options: Vec<String>,
}

/// The whole catalog.  `version` is the highest position in use: it grows
/// whenever something is added, so a client holding an older version knows
/// to refetch.  Deletions never require a refetch (unknown positions are
/// simply not granted).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PermissionCatalog {
    pub version: u64,
    pub permissions: Vec<Permission>,
}

// ── Values and grants ─────────────────────────────────────────────────────────

/// A permission value — what is granted, and what a token decodes to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "type", content = "value", rename_all = "snake_case")
)]
pub enum PermissionValue {
    /// A `bool` permission is granted.
    Allow,
    /// The chosen option of a `single` permission.
    Choice(String),
    /// The chosen options of a `multi` permission.
    Choices(Vec<String>),
    /// The value of a `text` permission.
    Text(String),
}

/// A validated grant, as stored: which permission, which options, which
/// text.  Replaces any existing grant of the same permission for the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionAssignment {
    pub permission_id: Uuid,
    /// Chosen options (`single`: exactly one, `multi`: one or more).
    pub option_ids: Vec<Uuid>,
    /// `text` value.
    pub text: Option<String>,
}

/// One granted position of the token encoding: a `bool` permission or a
/// chosen option (`text: None`), or a `text` permission with its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGrant {
    pub position: u32,
    pub text: Option<String>,
}

/// A user's merged grants, ready to encode into a token.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EffectiveGrants {
    /// Catalog version at read time.
    pub catalog_version: u64,
    pub grants: Vec<PermissionGrant>,
}

// ── Decoded view ──────────────────────────────────────────────────────────────

/// A token's permissions decoded against a catalog — what applications
/// check.  Codes the token doesn't grant (or the catalog doesn't know) are
/// simply absent: everything fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EffectivePermissions {
    values: BTreeMap<String, PermissionValue>,
    /// The token was encoded against a newer catalog than the one used to
    /// decode it; permissions added since then read as not granted.
    pub catalog_outdated: bool,
}

impl EffectivePermissions {
    pub fn new(values: BTreeMap<String, PermissionValue>, catalog_outdated: bool) -> Self {
        Self {
            values,
            catalog_outdated,
        }
    }

    /// Anything granted for `code`: a `bool` allowed, at least one option
    /// chosen, or a text value set.
    pub fn allowed(&self, code: &str) -> bool {
        self.values.contains_key(code)
    }

    /// The chosen option of a `single` permission.
    pub fn choice(&self, code: &str) -> Option<&str> {
        match self.values.get(code)? {
            PermissionValue::Choice(option) => Some(option),
            _ => None,
        }
    }

    /// The chosen options of a `multi` permission (empty if none).
    pub fn choices(&self, code: &str) -> &[String] {
        match self.values.get(code) {
            Some(PermissionValue::Choices(options)) => options,
            _ => &[],
        }
    }

    /// The value of a `text` permission.
    pub fn text(&self, code: &str) -> Option<&str> {
        match self.values.get(code)? {
            PermissionValue::Text(text) => Some(text),
            _ => None,
        }
    }

    /// Every granted permission, by code.
    pub fn values(&self) -> &BTreeMap<String, PermissionValue> {
        &self.values
    }
}
