//! Test helpers: a mediator on the in-memory store, and wallets that talk to it.

use std::sync::Arc;

use almena_didcomm::did::peer::{Purpose, peer2};
use almena_didcomm::did::{ChainResolver, LocalResolver, StaticResolver};
use almena_didcomm::{Curve, InMemorySecrets, Message, PackOptions, SecretKey, unpack};
use serde_json::json;

use crate::dispatch::{Limits, Mediator, Outcome};
use crate::identity::Identity;
use crate::store::{MemoryStore, QueueLimits, Store};

pub const LIMITS: Limits = Limits {
    max_message_bytes: 64 * 1024,
    queue: QueueLimits {
        ttl_secs: 3600,
        max_messages: 5,
        max_bytes: 1024 * 1024,
    },
    max_recipient_dids: 3,
    push_min_interval_secs: 0,
    push_ring_interval_secs: 0,
    // Off so tests can register any DID; the proof has tests of its own.
    recipient_proof: false,
    mediation_ttl_secs: 90 * 24 * 3600,
};

/// A mediator at `https://mediator.example.com` with an empty in-memory store.
pub fn mediator() -> Mediator {
    mediator_on(Arc::new(MemoryStore::new()))
}

/// A mediator at `https://mediator.example.com` on `store`.
pub fn mediator_on(store: Arc<dyn Store>) -> Mediator {
    Mediator::new(
        Identity::ephemeral("https://mediator.example.com").unwrap(),
        store,
        LIMITS,
        None,
    )
}

/// A wallet with a `did:peer:2` identity (Ed25519 signing key, key agreement
/// on the given curve).
pub struct Wallet {
    pub did: String,
    pub secrets: InMemorySecrets,
}

impl Wallet {
    pub fn new(curve: Curve) -> Self {
        Self::with_services(curve, &[])
    }

    /// A wallet whose DID says "reach me through `mediator_did`".
    pub fn mediated_by(mediator_did: &str) -> Self {
        Self::with_services(
            Curve::X25519,
            &[
                json!({"type": "DIDCommMessaging", "serviceEndpoint": {"uri": mediator_did, "accept": ["didcomm/v2"]}}),
            ],
        )
    }

    fn with_services(curve: Curve, services: &[serde_json::Value]) -> Self {
        let signing = SecretKey::generate(Curve::Ed25519).unwrap();
        let agreement = SecretKey::generate(curve).unwrap();
        let did = peer2(
            &[
                (Purpose::Verification, &signing.public_key()),
                (Purpose::Encryption, &agreement.public_key()),
            ],
            services,
        )
        .unwrap();
        let mut secrets = InMemorySecrets::new();
        secrets.insert(format!("{did}#key-1"), signing);
        secrets.insert(format!("{did}#key-2"), agreement);
        Self { did, secrets }
    }

    pub fn resolver(mediator: &Identity) -> ChainResolver {
        ChainResolver::new(vec![
            Arc::new(StaticResolver::new([mediator.document.clone()])),
            Arc::new(LocalResolver::new()),
        ])
    }

    /// A possession proof of this wallet's DID for `mediation` at `mediator`,
    /// issued at `iat`.
    pub async fn proof(&self, mediator: &Identity, mediation: &str, iat: u64) -> String {
        let mut proof = almena_didcomm::PossessionProof::new(&self.did, &mediator.did, mediation);
        proof.iat = iat;
        proof
            .pack(None, &LocalResolver::new(), &self.secrets)
            .await
            .unwrap()
    }

    /// Encrypts `message` to the mediator, authcrypt unless `anonymous`.
    pub async fn send(&self, mediator: &Identity, message: Message, anonymous: bool) -> String {
        let from = (!anonymous).then_some(self.did.as_str());
        message
            .to([mediator.did.as_str()])
            .pack_encrypted(
                &mediator.did,
                from,
                None,
                &Self::resolver(mediator),
                &self.secrets,
                PackOptions::default(),
            )
            .await
            .unwrap()
            .message
    }

    /// Opens a reply from the mediator and checks it is authcrypted by the mediator.
    pub async fn open(&self, mediator: &Identity, reply: &str) -> Message {
        let (message, meta) = unpack(reply, &Self::resolver(mediator), &self.secrets)
            .await
            .unwrap();
        assert!(
            meta.authenticated,
            "replies are authcrypted by the mediator"
        );
        assert_eq!(message.from.as_deref(), Some(mediator.did.as_str()));
        message
    }

    /// Sends an authcrypted request with `return_route: "all"` and returns the reply.
    pub async fn request(
        &self,
        mediator: &Mediator,
        type_: &str,
        body: serde_json::Value,
    ) -> Message {
        let message = Message::new(type_, body)
            .from(&self.did)
            .header("return_route", json!("all"));
        let packed = self.send(mediator.identity(), message, false).await;
        match mediator.receive(&packed, None).await.unwrap() {
            Outcome::Reply(reply) => self.open(mediator.identity(), &reply).await,
            Outcome::Accepted => panic!("{type_}: expected a reply"),
        }
    }
}

/// What a [`RecordingPusher`] was asked to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    Wake,
    Ring,
}

/// A [`Pusher`](crate::push::Pusher) that records the wake-ups and rings it
/// is asked for. Tokens starting with `dead` are reported invalid.
pub struct RecordingPusher {
    services: Vec<crate::push::Service>,
    sent: tokio::sync::mpsc::UnboundedSender<(Pushed, crate::push::Service, String)>,
}

impl RecordingPusher {
    pub fn new(
        services: &[crate::push::Service],
    ) -> (
        Arc<Self>,
        tokio::sync::mpsc::UnboundedReceiver<(Pushed, crate::push::Service, String)>,
    ) {
        let (sent, received) = tokio::sync::mpsc::unbounded_channel();
        (
            Arc::new(Self {
                services: services.to_vec(),
                sent,
            }),
            received,
        )
    }

    fn record(
        &self,
        pushed: Pushed,
        service: crate::push::Service,
        token: &str,
    ) -> crate::push::Sent {
        let _ = self.sent.send((pushed, service, token.to_owned()));
        if token.starts_with("dead") {
            crate::push::Sent::InvalidToken
        } else {
            crate::push::Sent::Delivered
        }
    }
}

#[async_trait::async_trait]
impl crate::push::Pusher for RecordingPusher {
    fn services(&self) -> &[crate::push::Service] {
        &self.services
    }

    async fn wake(
        &self,
        service: crate::push::Service,
        token: &str,
    ) -> anyhow::Result<crate::push::Sent> {
        Ok(self.record(Pushed::Wake, service, token))
    }

    async fn ring(
        &self,
        service: crate::push::Service,
        token: &str,
    ) -> anyhow::Result<crate::push::Sent> {
        Ok(self.record(Pushed::Ring, service, token))
    }
}

/// A mediator at `public_url` on its own in-memory store.
pub fn mediator_at(
    public_url: &str,
    transport: Option<Arc<dyn crate::transport::Transport>>,
) -> Arc<Mediator> {
    Arc::new(Mediator::new(
        Identity::ephemeral(public_url).unwrap(),
        Arc::new(MemoryStore::new()),
        LIMITS,
        transport,
    ))
}

/// A [`Transport`](crate::transport::Transport) that talks to mediators in
/// this process, by origin.
#[derive(Default)]
pub struct InProcess {
    mediators: std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<Mediator>>>,
}

impl InProcess {
    pub fn add(&self, origin: &str, mediator: &Arc<Mediator>) {
        self.mediators
            .lock()
            .unwrap()
            .insert(origin.to_owned(), Arc::downgrade(mediator));
    }

    fn find(&self, url: &str) -> anyhow::Result<(String, Arc<Mediator>)> {
        let mediators = self.mediators.lock().unwrap();
        let (origin, mediator) = mediators
            .iter()
            .find(|(origin, _)| url.starts_with(origin.as_str()))
            .ok_or_else(|| anyhow::anyhow!("no mediator at {url}"))?;
        let path = url[origin.len()..].to_owned();
        Ok((
            path,
            mediator
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("mediator gone"))?,
        ))
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for InProcess {
    async fn get_json(&self, url: &str) -> anyhow::Result<serde_json::Value> {
        let (path, mediator) = self.find(url)?;
        anyhow::ensure!(path == "/.well-known/did.json", "not found: {url}");
        Ok(mediator.identity().document.to_json())
    }

    async fn get_text(&self, url: &str) -> anyhow::Result<String> {
        anyhow::bail!("not found: {url}")
    }

    async fn post_didcomm(&self, url: &str, message: &str) -> anyhow::Result<()> {
        let (path, mediator) = self.find(url)?;
        anyhow::ensure!(path == crate::identity::DIDCOMM_PATH, "not found: {url}");
        mediator.receive(message, None).await?;
        Ok(())
    }
}
