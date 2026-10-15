//! # z-auth-cluster
//!
//! Optional clustering for [z-auth](z_auth): how z-auth instances
//! find each other and keep their state in sync.  The service application
//! imports it — z-auth itself knows nothing about clusters — and plugs a
//! cluster into [`ZAuth`](z_auth::ZAuth) as an
//! [`Extension`](z_auth::Extension):
//!
//! ```rust,ignore
//! use z_auth_cluster::{SharedCluster, config::{ClusterConfigLoader, ClusterEnvLoader}};
//!
//! let cluster = Arc::new(SharedCluster::new(ClusterEnvLoader.load_settings()?, transport, nodes));
//! let auth = ZAuth::builder(config, repos).extension(cluster.clone()).build()?;
//! auth.start().await?;            // joins the cluster
//! // every heartbeat:             auth.tick().await?;
//! // inbound cluster endpoint:    cluster.receive(envelope).await?;
//! ```
//!
//! Two modes, one feature each:
//!
//! - `shared` — [`shared`] mode: every instance of every service over one
//!   z-auth database; the cluster pushes revocations (denylist changes),
//!   key events and catalog changes to all peers ([`SharedCluster`]).
//! - `federation` *(default, implies `shared`)* — [`federation`] mode:
//!   database per service; the authority owns identity, every other service
//!   keeps a session store, and session state is synced between them
//!   ([`Federation`]).  [`sync`] is the data carried between clusters.
//!
//! [`Cluster`] picks the mode from `AUTH_DEPLOYMENT_MODE`.  Settings are
//! loaded separately from z-auth's own: see [`config`].
//!
//! z-auth-cluster ships **no client and no server**: the host provides a
//! [`ClusterTransport`](shared::ClusterTransport) (outbound), an inbound
//! endpoint handing envelopes to `receive`, and the storage ports
//! ([`NodeRepository`](shared::NodeRepository), and in federation mode a
//! [`SyncStore`](federation::SyncStore)).

pub mod config;
pub mod constants;
#[cfg(feature = "federation")]
pub mod federation;
#[cfg(feature = "federation")]
pub(crate) mod fence;
mod mode;
pub mod prelude;
pub mod report;
pub mod shared;
#[cfg(feature = "federation")]
pub mod sync;

#[cfg(feature = "federation")]
pub use federation::{Federation, SessionRepositories};
pub use mode::{Cluster, ClusterAdapters};
pub use report::ClusterReportExt;
pub use shared::SharedCluster;
