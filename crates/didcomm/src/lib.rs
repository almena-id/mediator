//! DIDComm Messaging v2.0 (<https://identity.foundation/didcomm-messaging/spec/v2.0/>).
//!
//! Message format, envelopes (JWS, anoncrypt and authcrypt JWE), the crypto
//! behind them and DID resolution. Nothing here knows about HTTP, storage or
//! mediation, so both the mediator and the wallet can use it.
//!
//! ```no_run
//! # async fn demo() -> almena_didcomm::Result<()> {
//! use almena_didcomm::{LocalResolver, InMemorySecrets, Message, PackOptions, unpack};
//! # let (resolver, secrets) = (LocalResolver::new(), InMemorySecrets::new());
//! # let (alice, bob) = ("did:peer:2...", "did:peer:2...");
//! let message = Message::new("https://didcomm.org/trust-ping/2.0/ping", serde_json::json!({}))
//!     .from(alice)
//!     .to([bob]);
//! let packed = message
//!     .pack_encrypted(bob, Some(alice), None, &resolver, &secrets, PackOptions::default())
//!     .await?;
//! let (received, metadata) = unpack(&packed.message, &resolver, &secrets).await?;
//! assert!(metadata.authenticated);
//! # Ok(()) }
//! ```

pub mod b64;
pub mod crypto;
pub mod did;
mod error;
pub mod from_prior;
pub mod jwk;
pub mod message;
mod pack;
pub mod possession;
pub mod secrets;
mod unpack;

pub use crypto::content::ContentEncryption;
pub use crypto::keys::{Curve, PublicKey, SecretKey};
pub use did::{DidDocument, DidResolver, LocalResolver, StaticResolver};
pub use error::{Error, Result};
pub use from_prior::FromPrior;
pub use jwk::Jwk;
pub use message::{Attachment, Message};
pub use pack::{FORWARD, PackOptions, PackedMessage, Routed, URGENCY, Urgency, route, route_with};
pub use possession::PossessionProof;
pub use secrets::{InMemorySecrets, SecretsResolver};
pub use unpack::{UnpackMetadata, unpack};
