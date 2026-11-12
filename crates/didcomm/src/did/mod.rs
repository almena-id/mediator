//! DIDs and DID documents (W3C DID Core) for DIDComm.

pub mod document;
pub mod key;
pub mod multikey;
pub mod peer;
pub mod resolver;
pub mod web;
pub mod webvh;

pub use document::{DidCommEndpoint, DidDocument, Service, VerificationMethod, did_of};
pub use resolver::{ChainResolver, DidResolver, LocalResolver, StaticResolver};
