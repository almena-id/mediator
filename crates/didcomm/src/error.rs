/// Errors returned by this crate.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// Input that does not parse or breaks the DIDComm / JOSE structure rules.
    #[error("malformed: {0}")]
    Malformed(String),
    /// Well-formed input that uses an algorithm, curve or feature we do not support.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Key material that is not a valid key for its type.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// A signature, tag or key unwrap that does not verify.
    #[error("cryptographic check failed: {0}")]
    Crypto(&'static str),
    /// A DID that could not be resolved.
    #[error("DID not found: {0}")]
    DidNotFound(String),
    /// A DID URL (key or service reference) that its DID document does not contain.
    #[error("DID URL not found: {0}")]
    DidUrlNotFound(String),
    /// None of our secrets can act for the given key ids.
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    /// Sender and recipient have no key agreement keys on a common curve.
    #[error("no compatible keys: {0}")]
    NoCompatibleKeys(String),
    /// Envelope layers or headers that contradict each other (spec: "Message Layer
    /// Addressing Consistency"), or a key used outside its verification relationship.
    #[error("inconsistent message: {0}")]
    Inconsistent(String),
    /// A DID resolver or secrets store failed for reasons of its own (I/O, network).
    #[error("resolver failed: {0}")]
    Resolver(String),
}

/// Result alias for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub(crate) fn malformed(msg: impl Into<String>) -> Self {
        Self::Malformed(msg.into())
    }

    pub(crate) fn unsupported(msg: impl Into<String>) -> Self {
        Self::Unsupported(msg.into())
    }

    pub(crate) fn invalid_key(msg: impl Into<String>) -> Self {
        Self::InvalidKey(msg.into())
    }

    pub(crate) fn inconsistent(msg: impl Into<String>) -> Self {
        Self::Inconsistent(msg.into())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Malformed(format!("JSON: {err}"))
    }
}
