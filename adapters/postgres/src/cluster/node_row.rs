//! The node registry's row and enum types (`node_state`,
//! `heartbeat_status`).

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;
use z_auth::AuthError;
use z_auth_cluster::shared::{HeartbeatStatus, NodeInfo, NodeRecord, NodeState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "node_state", rename_all = "snake_case")]
pub(super) enum PgNodeState {
    Joining,
    Active,
    Leaving,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "heartbeat_status", rename_all = "snake_case")]
pub(super) enum PgHeartbeatStatus {
    Online,
    Offline,
    Missing,
}

impl From<PgNodeState> for NodeState {
    fn from(s: PgNodeState) -> Self {
        match s {
            PgNodeState::Joining => Self::Joining,
            PgNodeState::Active => Self::Active,
            PgNodeState::Leaving => Self::Leaving,
        }
    }
}

impl From<NodeState> for PgNodeState {
    fn from(s: NodeState) -> Self {
        match s {
            NodeState::Joining => Self::Joining,
            NodeState::Active => Self::Active,
            NodeState::Leaving => Self::Leaving,
        }
    }
}

impl From<PgHeartbeatStatus> for HeartbeatStatus {
    fn from(s: PgHeartbeatStatus) -> Self {
        match s {
            PgHeartbeatStatus::Online => Self::Online,
            PgHeartbeatStatus::Offline => Self::Offline,
            PgHeartbeatStatus::Missing => Self::Missing,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(super) struct NodeRow {
    id: Uuid,
    service: String,
    ip: Option<IpAddr>,
    dns_name: Option<String>,
    port: i32,
    version: String,
    state: PgNodeState,
    heartbeat: PgHeartbeatStatus,
    started_at: DateTime<Utc>,
    state_changed_at: DateTime<Utc>,
    heartbeat_changed_at: DateTime<Utc>,
}

impl TryFrom<NodeRow> for NodeRecord {
    type Error = AuthError;

    fn try_from(r: NodeRow) -> Result<Self, AuthError> {
        Ok(Self {
            info: NodeInfo {
                node_id: r.id,
                service: r.service,
                ip: r.ip,
                dns_name: r.dns_name,
                port: u16::try_from(r.port)
                    .map_err(|_| AuthError::Storage("node port out of range".into()))?,
                version: r.version,
                started_at: r.started_at,
            },
            state: r.state.into(),
            heartbeat: r.heartbeat.into(),
            state_changed_at: r.state_changed_at,
            heartbeat_changed_at: r.heartbeat_changed_at,
        })
    }
}
