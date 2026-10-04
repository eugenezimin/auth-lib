//! Sends signed messages through the host's [`ClusterTransport`], and the
//! [`EventPublisher`] implementation that pushes domain events to peers.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::join_all;
use uuid::Uuid;

use crate::clock::Clock;
use crate::cluster::model::{ClusterEnvelope, ClusterMessage};
use crate::cluster::signer::EnvelopeSigner;
use crate::cluster::state::{ClusterState, Outgoing};
use crate::cluster::transport::ClusterTransport;
use crate::error::AuthError;
use crate::events::{DomainEvent, EventPublisher};

pub(crate) struct ClusterMessenger {
    pub state: Arc<ClusterState>,
    pub signer: EnvelopeSigner,
    transport: Arc<dyn ClusterTransport>,
    clock: Arc<dyn Clock>,
}

/// Delivery counts of one fan-out.
#[derive(Default)]
pub(crate) struct Delivery {
    pub sent: usize,
    pub failed: usize,
}

impl ClusterMessenger {
    pub fn new(
        state: Arc<ClusterState>,
        signer: EnvelopeSigner,
        transport: Arc<dyn ClusterTransport>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            state,
            signer,
            transport,
            clock,
        }
    }

    pub fn seal(
        &self,
        message_id: Uuid,
        payload: ClusterMessage,
    ) -> Result<ClusterEnvelope, AuthError> {
        self.signer.seal(
            message_id,
            self.state.local.node_id,
            self.clock.now(),
            payload,
        )
    }

    /// Send to one peer; returns the verified reply, if any.
    pub async fn send(
        &self,
        to: Uuid,
        message_id: Uuid,
        payload: ClusterMessage,
    ) -> Result<Option<ClusterEnvelope>, AuthError> {
        let address = self
            .state
            .address(to)
            .ok_or_else(|| AuthError::ClusterUnreachable(format!("unknown peer {to}")))?;
        let envelope = self.seal(message_id, payload)?;
        let reply = self.transport.send(&address, &envelope).await?;
        match reply {
            Some(r) if r.from != to || !self.signer.verify(&r) => Err(
                AuthError::ClusterMessageRejected("reply not signed by the peer".into()),
            ),
            reply => Ok(reply),
        }
    }

    /// Send `payload` to every current peer (online or offline),
    /// concurrently.  With `retry`, failed deliveries go to the outbox.
    pub async fn broadcast(&self, payload: ClusterMessage, retry: bool) -> Delivery {
        let message_id = Uuid::new_v4();
        let targets: Vec<Uuid> = self
            .state
            .peers()
            .into_iter()
            .map(|p| p.info.node_id)
            .collect();
        let results = join_all(
            targets
                .iter()
                .map(|&to| self.send(to, message_id, payload.clone())),
        )
        .await;
        let mut delivery = Delivery::default();
        for (to, result) in targets.into_iter().zip(results) {
            match result {
                Ok(_) => delivery.sent += 1,
                Err(_) => {
                    delivery.failed += 1;
                    if retry {
                        self.state.enqueue(Outgoing {
                            to,
                            message_id,
                            payload: payload.clone(),
                            attempts: 1,
                        });
                    }
                }
            }
        }
        delivery
    }
}

/// [`EventPublisher`] that pushes every event to all peers immediately.
pub struct ClusterPublisher {
    messenger: Arc<ClusterMessenger>,
}

impl ClusterPublisher {
    pub(crate) fn new(messenger: Arc<ClusterMessenger>) -> Self {
        Self { messenger }
    }
}

#[async_trait]
impl EventPublisher for ClusterPublisher {
    async fn publish(&self, event: DomainEvent) {
        self.messenger
            .broadcast(ClusterMessage::Event(event), true)
            .await;
    }
}
