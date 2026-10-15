//! Cluster configuration, separate from z-auth's own `AuthConfig`:
//! [`model`] (data) and [`loaders`] (environment / direct, validation).

pub mod loaders;
pub mod model;

pub use loaders::{ClusterConfigLoader, ClusterDirectLoader, ClusterEnvLoader};
pub use model::{
    ClusterConfig, ClusterSettings, DeploymentMode, FederationConfig, ForkPolicy, LinkConfig,
    RawClusterConfig, SeedAddress, SelfFence, SessionDistribution,
};
