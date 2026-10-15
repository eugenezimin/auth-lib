//! This instance as advertised to its peers (`AUTH_CLUSTER_*`).

use std::sync::Arc;

use uuid::Uuid;

use crate::config::ClusterSettings;
use crate::shared::NodeInfo;
use z_auth::utils::clock::Clock;
use z_auth::utils::error::AuthError;

pub(crate) fn local_node(
    settings: &ClusterSettings,
    node_id: Uuid,
    clock: &Arc<dyn Clock>,
) -> Result<NodeInfo, AuthError> {
    let c = &settings.cluster;
    if c.advertise_ip.is_none() && c.advertise_dns.is_none() {
        return Err(AuthError::Config(
            "cluster configured: set AUTH_CLUSTER_ADVERTISE_IP or AUTH_CLUSTER_ADVERTISE_DNS"
                .into(),
        ));
    }
    Ok(NodeInfo {
        node_id,
        service: c.service.clone(),
        ip: c.advertise_ip,
        dns_name: c.advertise_dns.clone(),
        port: c.advertise_port.ok_or_else(|| {
            AuthError::Config("cluster configured: set AUTH_CLUSTER_ADVERTISE_PORT".into())
        })?,
        // The z-auth version, so peers see which library they talk to.
        version: z_auth::VERSION.into(),
        started_at: clock.now(),
    })
}
