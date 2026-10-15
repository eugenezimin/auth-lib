//! Security contexts — who the caller is ([`authentication`]), what they may
//! do ([`authorization`]) and the tokens that carry all of it ([`token`]),
//! over the login [`session`].

pub mod authentication;
pub mod authorization;
pub mod session;
pub mod token;
