//! DID resolution.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::did::document::DidDocument;
use crate::did::{key, peer};
use crate::{Error, Result};

/// Resolves DIDs to DID documents.
#[async_trait]
pub trait DidResolver: Send + Sync {
    /// Returns [`Error::DidNotFound`] when this resolver does not know `did`,
    /// so that resolvers can be chained.
    async fn resolve(&self, did: &str) -> Result<DidDocument>;
}

#[async_trait]
impl<T: DidResolver + ?Sized> DidResolver for Arc<T> {
    async fn resolve(&self, did: &str) -> Result<DidDocument> {
        (**self).resolve(did).await
    }
}

/// Methods that resolve without any network: `did:key`, `did:peer:2` and
/// `did:peer:4`. Short-form `did:peer:4` DIDs resolve only after their long
/// form went through this resolver; it remembers up to [`Self::PEER4_CAPACITY`]
/// of them that resolved, the oldest going first when full (not all at once,
/// so a flood of made-up ones does not forget every contact together).
#[derive(Default)]
pub struct LocalResolver {
    peer4_long_forms: Mutex<Peer4Forms>,
}

/// Long forms by short form, and the short forms in the order remembered.
#[derive(Default)]
struct Peer4Forms {
    by_short: HashMap<String, String>,
    order: std::collections::VecDeque<String>,
}

impl LocalResolver {
    pub const PEER4_CAPACITY: usize = 10_000;

    pub fn new() -> Self {
        Self::default()
    }

    fn remember_peer4(&self, long: &str) -> Result<()> {
        let short = peer::peer4_short(long)?.to_owned();
        let mut map = self
            .peer4_long_forms
            .lock()
            .map_err(|_| Error::Resolver("peer4 cache poisoned".into()))?;
        if map.by_short.contains_key(&short) {
            return Ok(());
        }
        while map.by_short.len() >= Self::PEER4_CAPACITY {
            let Some(oldest) = map.order.pop_front() else {
                break;
            };
            map.by_short.remove(&oldest);
        }
        map.order.push_back(short.clone());
        map.by_short.insert(short, long.to_owned());
        Ok(())
    }
}

#[async_trait]
impl DidResolver for LocalResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument> {
        if did.starts_with("did:key:") {
            key::resolve(did)
        } else if did.starts_with("did:peer:2.") {
            peer::resolve_peer2(did)
        } else if let Some(rest) = did.strip_prefix("did:peer:4") {
            if rest.contains(':') {
                let doc = peer::resolve_peer4(did, did)?;
                self.remember_peer4(did)?;
                Ok(doc)
            } else {
                let long = self
                    .peer4_long_forms
                    .lock()
                    .map_err(|_| Error::Resolver("peer4 cache poisoned".into()))?
                    .by_short
                    .get(did)
                    .cloned()
                    .ok_or_else(|| Error::DidNotFound(did.to_owned()))?;
                peer::resolve_peer4(&long, did)
            }
        } else {
            Err(Error::DidNotFound(did.to_owned()))
        }
    }
}

/// A fixed set of documents, e.g. pinned peers or tests.
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    docs: HashMap<String, DidDocument>,
}

impl StaticResolver {
    pub fn new(docs: impl IntoIterator<Item = DidDocument>) -> Self {
        Self {
            docs: docs.into_iter().map(|d| (d.id.clone(), d)).collect(),
        }
    }
}

#[async_trait]
impl DidResolver for StaticResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument> {
        self.docs
            .get(did)
            .cloned()
            .ok_or_else(|| Error::DidNotFound(did.to_owned()))
    }
}

/// Tries each resolver in turn; the first answer other than
/// [`Error::DidNotFound`] wins.
#[derive(Default, Clone)]
pub struct ChainResolver {
    resolvers: Vec<Arc<dyn DidResolver>>,
}

impl ChainResolver {
    pub fn new(resolvers: Vec<Arc<dyn DidResolver>>) -> Self {
        Self { resolvers }
    }
}

#[async_trait]
impl DidResolver for ChainResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument> {
        for resolver in &self.resolvers {
            match resolver.resolve(did).await {
                Err(Error::DidNotFound(_)) => continue,
                other => return other,
            }
        }
        Err(Error::DidNotFound(did.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::peer::{peer4, peer4_short};

    #[tokio::test]
    async fn short_peer4_resolves_only_after_its_long_form() {
        let resolver = LocalResolver::new();
        let long = peer4(&serde_json::json!({"verificationMethod": []})).unwrap();
        let short = peer4_short(&long).unwrap();
        assert!(matches!(
            resolver.resolve(short).await,
            Err(Error::DidNotFound(_))
        ));
        resolver.resolve(&long).await.unwrap();
        assert_eq!(resolver.resolve(short).await.unwrap().id, short);
    }

    #[tokio::test]
    async fn chain_falls_through_not_found() {
        let doc = DidDocument {
            id: "did:example:a".into(),
            ..DidDocument::default()
        };
        let chain = ChainResolver::new(vec![
            Arc::new(LocalResolver::new()),
            Arc::new(StaticResolver::new([doc])),
        ]);
        assert_eq!(
            chain.resolve("did:example:a").await.unwrap().id,
            "did:example:a"
        );
        assert!(chain.resolve("did:example:b").await.is_err());
    }
}
