//! Authentication context — login sessions (with an optional second
//! factor), token rotation and the refresh policy.

pub mod account;
pub mod flow;
pub mod gate;
pub mod linking;
pub mod model;
pub mod policy;
pub mod second_factor;
pub mod service;
pub mod service_impl;

pub use account::{RefreshAccount, RefreshAccountSource, StoreAccountSource};
pub use flow::{FlowStateRepository, flow_key};
pub use gate::RefreshGate;
pub use linking::{AccountLinkService, AccountLinkServiceImpl, ExternalStores};
pub use model::{
    ChallengeDelivery, ClientContext, Credentials, ExternalLoginOutcome, LinkChallenge,
    LinkConfirmation, LoginChallenge, LoginOutcome, SecondFactorProof, TokenPair,
};
pub use second_factor::{SecondFactorDecision, SecondFactorGate, VerifiedSecondFactor};
pub use service::AuthenticationService;
pub use service_impl::AuthenticationServiceImpl;
