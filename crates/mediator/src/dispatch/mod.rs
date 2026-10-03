//! The DIDComm side of the mediator: unpacks what arrives at `/didcomm`, runs the
//! protocols addressed to the mediator itself, queues `forward` payloads and packs
//! the replies.

mod devices;
pub mod live;
mod mediation;
mod pickup;
pub mod protocols;
mod relay;
pub mod turn;

use std::sync::Arc;

use almena_didcomm::did::{ChainResolver, DidResolver, LocalResolver, StaticResolver};
use almena_didcomm::message::now;
use almena_didcomm::{Attachment, FORWARD, Message, PackOptions, unpack};
use tokio::sync::mpsc;

use crate::identity::Identity;
use crate::metrics::{self, METRICS, MessageOutcome, Transport as Via};
use crate::push::{self, Pusher};
use crate::store::{QueueLimits, Queued, Store};
use crate::transport::{Transport, WebResolver};
use live::{LiveHub, Session};
use protocols::Problem;
use turn::TurnServer;

/// How often idle mediations are looked for, and how many go per batch.
const CLEANUP_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);
const CLEANUP_BATCH: usize = 100;

/// Removes every mediation idle for more than `ttl_secs` at `now`.
pub(crate) async fn remove_idle(
    store: &dyn Store,
    ttl_secs: u64,
    now: u64,
) -> anyhow::Result<usize> {
    let cutoff = now.saturating_sub(ttl_secs);
    let mut total = 0;
    loop {
        let removed = store.remove_idle_mediations(cutoff, CLEANUP_BATCH).await?;
        total += removed.len();
        if removed.len() < CLEANUP_BATCH {
            break;
        }
    }
    if total > 0 {
        tracing::info!(removed = total, "idle mediations removed");
        METRICS.mediations_removed(total as u64);
    }
    Ok(total)
}

/// Limits the mediator enforces (SPEC.md §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_message_bytes: usize,
    pub queue: QueueLimits,
    pub max_recipient_dids: usize,
    /// Least time between two pushes to one mediation.
    pub push_min_interval_secs: u64,
    /// Least time between two call rings to one mediation.
    pub push_ring_interval_secs: u64,
    /// Registering a recipient DID other than the mediation's own needs a
    /// possession proof signed by that DID (SPEC.md §6.2).
    pub recipient_proof: bool,
    /// A mediation whose wallet sends nothing for this long is removed with
    /// all it owns; 0 keeps mediations forever.
    pub mediation_ttl_secs: u64,
}

/// What the HTTP layer should answer after a message was accepted.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Processed; nothing goes back on this connection.
    Accepted,
    /// Processed; this encrypted reply goes back on this connection
    /// (the sender asked for it with `return_route`).
    Reply(String),
}

/// Why a message was not accepted. None of these can be answered over
/// DIDComm: the envelope did not open, or it was a `forward`, whose sender
/// is anonymous by design.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    #[error(transparent)]
    Unpack(#[from] almena_didcomm::Error),
    #[error("invalid forward: {0}")]
    BadForward(&'static str),
    #[error("the forward's next recipient is not mediated here")]
    UnknownRecipient,
    #[error("the recipient's queue is full")]
    QueueFull,
    #[error("storage: {0:#}")]
    Store(#[from] anyhow::Error),
}

/// What a protocol handler decided.
#[expect(
    clippy::large_enum_variant,
    reason = "returned once per request and consumed at once; boxing buys nothing"
)]
pub(crate) enum Handled {
    Reply(Message),
    Problem(Problem),
    Nothing,
}

pub struct Mediator {
    identity: Identity,
    resolver: ChainResolver,
    store: Arc<dyn Store>,
    limits: Limits,
    live: LiveHub,
    /// Outbound traffic to other mediators; `None` turns federation off.
    transport: Option<Arc<dyn Transport>>,
    /// Push wake-ups; `None` turns them off.
    pusher: Option<Arc<dyn Pusher>>,
    /// TURN credentials; `None` turns the TURN protocol off.
    turn: Option<TurnServer>,
}

impl Mediator {
    pub fn new(
        identity: Identity,
        store: Arc<dyn Store>,
        limits: Limits,
        transport: Option<Arc<dyn Transport>>,
    ) -> Self {
        // Our own did:web resolves from memory, did:key / did:peer locally,
        // other did:web DIDs over HTTPS when federation is on.
        let mut resolvers: Vec<Arc<dyn DidResolver>> = vec![
            Arc::new(StaticResolver::new([identity.document.clone()])),
            Arc::new(LocalResolver::new()),
        ];
        if let Some(transport) = &transport {
            resolvers.push(Arc::new(WebResolver::new(Arc::clone(transport))));
        }
        Self {
            identity,
            resolver: ChainResolver::new(resolvers),
            store,
            limits,
            live: LiveHub::default(),
            transport,
            pusher: None,
            turn: None,
        }
    }

    /// Turns push wake-ups on.
    pub fn with_pusher(mut self, pusher: Arc<dyn Pusher>) -> Self {
        self.pusher = Some(pusher);
        self
    }

    /// Turns the TURN protocol on: wallets get credentials for `turn`.
    pub fn with_turn(mut self, turn: TurnServer) -> Self {
        self.turn = Some(turn);
        self
    }

    pub(crate) fn turn(&self) -> Option<&TurnServer> {
        self.turn.as_ref()
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn store(&self) -> &dyn Store {
        self.store.as_ref()
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub(crate) fn resolver(&self) -> &ChainResolver {
        &self.resolver
    }

    pub(crate) fn transport(&self) -> Option<&Arc<dyn Transport>> {
        self.transport.as_ref()
    }

    pub(crate) fn live(&self) -> &LiveHub {
        &self.live
    }

    /// Starts removing idle mediations in the background, once an hour
    /// (unless `mediation_ttl_secs` is 0).
    pub fn start_cleanup(&self) {
        let ttl = self.limits.mediation_ttl_secs;
        if ttl == 0 {
            return;
        }
        let store = Arc::clone(&self.store);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CLEANUP_EVERY);
            loop {
                tick.tick().await;
                if let Err(err) = remove_idle(store.as_ref(), ttl, now()).await {
                    tracing::warn!(error = %format!("{err:#}"), "mediation cleanup failed");
                }
            }
        });
    }

    /// Starts retrying failed relays in the background (federation only).
    pub fn start_relay_retries(&self) {
        if let Some(transport) = &self.transport {
            relay::spawn_retries(Arc::clone(&self.store), Arc::clone(transport));
        }
    }

    pub(crate) fn pusher(&self) -> Option<&Arc<dyn Pusher>> {
        self.pusher.as_ref()
    }

    /// Something was queued for `mediation`: wakes its devices in the
    /// background, unless a live session will deliver it anyway.
    pub(crate) fn wake(&self, mediation: &str) {
        let Some(pusher) = &self.pusher else {
            return;
        };
        if self.live.is_live(mediation) {
            return;
        }
        let (store, pusher, mediation) = (
            Arc::clone(&self.store),
            Arc::clone(pusher),
            mediation.to_owned(),
        );
        // A sent push stops further ones until the wallet picks up, but
        // never for longer than messages can wait.
        let hold = self.limits.queue.ttl_secs;
        let retry = self.limits.push_min_interval_secs;
        tokio::spawn(async move {
            if let Err(err) =
                push::wake(store.as_ref(), pusher.as_ref(), &mediation, hold, retry).await
            {
                tracing::warn!(%mediation, error = %format!("{err:#}"), "push wake-up failed");
            }
        });
    }

    /// A call offer was queued for `mediation`: rings its devices in the
    /// background, unless a live session will deliver it anyway.
    pub(crate) fn ring(&self, mediation: &str) {
        let Some(pusher) = &self.pusher else {
            return;
        };
        if self.live.is_live(mediation) {
            return;
        }
        let (store, pusher, mediation) = (
            Arc::clone(&self.store),
            Arc::clone(pusher),
            mediation.to_owned(),
        );
        let interval = self.limits.push_ring_interval_secs;
        tokio::spawn(async move {
            if let Err(err) =
                push::ring(store.as_ref(), pusher.as_ref(), &mediation, interval).await
            {
                tracing::warn!(%mediation, error = %format!("{err:#}"), "call push failed");
            }
        });
    }

    /// The wallet of `mediation` is picking up: pushes may resume after the
    /// minimum interval.
    pub(crate) async fn picked_up(&self, mediation: &str) -> anyhow::Result<()> {
        if self.pusher.is_some() {
            self.store
                .release_push(mediation, now(), self.limits.push_min_interval_secs)
                .await?;
        }
        Ok(())
    }

    /// Starts a live-capable session (a WebSocket connection). Its
    /// connection task reads live pushes from the receiver and passes each to
    /// [`Mediator::live_delivery`].
    pub fn open_session(&self) -> (Session, mpsc::Receiver<Queued>) {
        METRICS.websocket_opened();
        self.live.open()
    }

    /// Ends a session: no more live pushes for it.
    pub fn close_session(&self, session: &mut Session) {
        METRICS.websocket_closed();
        self.live.disable(session);
    }

    /// Packs a live push as a Message Pickup `delivery` for the session's
    /// mediation. The message stays queued until acknowledged.
    pub async fn live_delivery(&self, session: &Session, queued: Queued) -> Option<String> {
        let mediation = session.live_mediation()?;
        let delivery = Message::new(protocols::DELIVERY, serde_json::json!({}))
            .attachment(Attachment::base64(queued.message.as_bytes()).with_id(queued.id));
        self.pack_reply(delivery, mediation, false)
            .await
            .map(|packed| packed.message)
    }

    /// Handles one envelope. `session` is the live-capable connection it
    /// came on (a WebSocket), or `None` for HTTP.
    pub async fn receive(
        &self,
        packed: &str,
        session: Option<&mut Session>,
    ) -> Result<Outcome, ReceiveError> {
        let transport = if session.is_some() {
            Via::WebSocket
        } else {
            Via::Http
        };
        let started = std::time::Instant::now();
        let result = self.handle(packed, session).await;
        METRICS.message_took(started.elapsed());
        if let Err(ReceiveError::Store(_)) = &result {
            METRICS.store_error();
        }
        METRICS.message(
            transport,
            match &result {
                Ok(Outcome::Accepted) => MessageOutcome::Accepted,
                Ok(Outcome::Reply(_)) => MessageOutcome::Reply,
                Err(_) => MessageOutcome::Rejected,
            },
        );
        if let Err(
            ReceiveError::BadForward(_) | ReceiveError::UnknownRecipient | ReceiveError::QueueFull,
        ) = &result
        {
            METRICS.forward(metrics::Forward::Refused, 1);
        }
        result
    }

    async fn handle(
        &self,
        packed: &str,
        mut session: Option<&mut Session>,
    ) -> Result<Outcome, ReceiveError> {
        let (message, meta) = unpack(packed, &self.resolver, self.identity.secrets()).await?;
        if !meta.encrypted {
            return Err(almena_didcomm::Error::Malformed(
                "the mediator accepts encrypted messages only".into(),
            )
            .into());
        }
        tracing::debug!(id = %message.id, r#type = %message.type_, authenticated = meta.authenticated, "received");
        // Unpack guarantees `from` is the authcrypt sender when authenticated.
        let requester = message.from.as_deref().filter(|_| meta.authenticated);

        let handled = if message.is_expired_at(now()) {
            Handled::Problem(Problem::Expired)
        } else {
            let t = message.type_.as_str();
            match t {
                FORWARD => {
                    mediation::forward(self, &message).await?;
                    Handled::Nothing
                }
                protocols::PING => {
                    protocols::trust_ping(&message).map_or(Handled::Nothing, Handled::Reply)
                }
                protocols::QUERIES => {
                    let push = self.pusher.as_ref().map_or(&[][..], |p| p.services());
                    match protocols::discover_features(
                        &message,
                        self.limits.max_message_bytes,
                        push,
                        self.turn.is_some(),
                    ) {
                        Ok(disclose) => Handled::Reply(disclose),
                        Err(problem) => Handled::Problem(problem),
                    }
                }
                protocols::PROBLEM_REPORT => {
                    tracing::warn!(
                        code = ?message.body.get("code"),
                        comment = ?message.body.get("comment"),
                        pthid = ?message.pthid,
                        "problem report received"
                    );
                    Handled::Nothing
                }
                _ if t.starts_with(protocols::COORDINATE_MEDIATION)
                    || t.starts_with(protocols::PICKUP)
                    || t.starts_with(protocols::PUSH_FCM)
                    || t.starts_with(protocols::PUSH_APNS)
                    || t.starts_with(protocols::TURN) =>
                {
                    // The wallet is alive: its mediation is not idle. Asking
                    // for TURN credentials alone does not count (SPEC.md §11):
                    // a mediation kept only for them holds nothing.
                    if let Some(requester) = requester
                        && !t.starts_with(protocols::TURN)
                    {
                        self.store.touch_mediation(requester, now()).await?;
                    }
                    match requester {
                        None => Handled::Problem(Problem::Unauthenticated),
                        Some(requester) if t.starts_with(protocols::PICKUP) => {
                            pickup::handle(self, requester, &message, session.as_deref_mut())
                                .await?
                        }
                        Some(requester) if t.starts_with(protocols::COORDINATE_MEDIATION) => {
                            mediation::handle(self, requester, &message).await?
                        }
                        Some(requester) if t.starts_with(protocols::TURN) => {
                            turn::handle(self, requester, &message).await?
                        }
                        Some(requester) => devices::handle(self, requester, &message).await?,
                    }
                }
                _ => Handled::Problem(Problem::UnsupportedType),
            }
        };

        let reply = match handled {
            Handled::Reply(reply) => reply,
            Handled::Problem(problem) => problem.report(&message),
            Handled::Nothing => return Ok(Outcome::Accepted),
        };
        Ok(self
            .route_back(&message, reply, session.is_some(), meta.authenticated)
            .await)
    }

    /// Packs `reply` for the sender of `request` to travel back on the same
    /// connection when the request asks for it (`return_route`, implied on a
    /// WebSocket). Otherwise an authenticated sender gets it through
    /// [`Mediator::send_reply`]; an anonymous one gets nothing
    /// (SPEC.md §6.6).
    async fn route_back(
        &self,
        request: &Message,
        reply: Message,
        websocket: bool,
        authenticated: bool,
    ) -> Outcome {
        let Some(sender) = request.from.as_deref() else {
            tracing::debug!(id = %request.id, "anonymous sender, reply dropped");
            return Outcome::Accepted;
        };
        // Our replies are always in the request's thread, so `thread` means
        // the same as `all` for them; `none` turns even the socket's off.
        let route_back = match request
            .extra_headers
            .get("return_route")
            .and_then(|v| v.as_str())
        {
            Some("all" | "thread") => true,
            Some(_) => false,
            None => websocket,
        };
        if route_back {
            return self
                .pack_reply(reply, sender, false)
                .await
                .map_or(Outcome::Accepted, |packed| Outcome::Reply(packed.message));
        }
        // Pickup answers describe the queue: put into it, each status
        // request would add to what it reports. They only travel back on the
        // connection.
        if request.type_.starts_with(protocols::PICKUP) {
            tracing::debug!(id = %request.id, "pickup without return route, reply dropped");
            return Outcome::Accepted;
        }
        // Only to a sender the authcrypt proved: an unauthenticated `from`
        // could name anyone, and we would be sending them our replies.
        if authenticated {
            self.send_reply(reply, sender).await;
        } else {
            tracing::debug!(id = %request.id, "unauthenticated sender, reply dropped");
        }
        Outcome::Accepted
    }

    /// Delivers a reply that cannot go back on the connection, as the spec
    /// asks: into the sender's queue when it is mediated here — a recipient
    /// DID of a mediation, or a mediation DID itself, registered or not —
    /// never wrapped; else to its `DIDCommMessaging` service (through its
    /// mediators) in the background, with the relay retries. Without a
    /// service the reply is dropped.
    async fn send_reply(&self, reply: Message, sender: &str) {
        let sender = almena_didcomm::did::did_of(sender);
        let mediation = match self.store.mediation_of(sender).await {
            Ok(None) => match self.store.has_mediation(sender).await {
                Ok(true) => Ok(Some(sender.to_owned())),
                Ok(false) => Ok(None),
                Err(err) => Err(err),
            },
            other => other,
        };
        match mediation {
            Ok(Some(mediation)) => {
                let Some(packed) = self.pack_reply(reply, sender, false).await else {
                    return;
                };
                match mediation::queue(self, &mediation, sender, packed.message).await {
                    Ok(()) => {
                        tracing::debug!(%sender, "reply queued for pickup");
                        self.wake(&mediation);
                    }
                    Err(err) => tracing::info!(%sender, error = %err, "reply dropped"),
                }
            }
            Ok(None) => {
                let Some(transport) = self.transport.clone() else {
                    tracing::debug!(%sender, "no federation, reply dropped");
                    return;
                };
                let Some(packed) = self.pack_reply(reply, sender, true).await else {
                    return;
                };
                let Some(uri) = packed.service_uri else {
                    tracing::debug!(%sender, "sender has no DIDComm service, reply dropped");
                    return;
                };
                if relay::own_endpoints(self).contains(&uri) {
                    tracing::debug!(%sender, "sender routes through us unregistered, reply dropped");
                    return;
                }
                let store = Arc::clone(&self.store);
                tokio::spawn(async move {
                    relay::deliver(store.as_ref(), transport.as_ref(), uri, packed.message).await;
                });
            }
            Err(err) => {
                tracing::warn!(%sender, error = %format!("{err:#}"), "reply dropped");
            }
        }
    }

    /// Authcrypts `reply` from the mediator to `recipient`, never wrapped for the
    /// recipient's mediators: it goes back on the connection it came from.
    async fn pack_reply(
        &self,
        reply: Message,
        recipient: &str,
        forward: bool,
    ) -> Option<almena_didcomm::PackedMessage> {
        let sender = recipient;
        let reply = reply.from(&self.identity.did).to([sender]);
        // Back on the connection, or into the sender's queue here: never
        // wrapped. To the sender's service: wrapped for its mediators.
        let options = PackOptions {
            forward,
            ..PackOptions::default()
        };
        match reply
            .pack_encrypted(
                sender,
                Some(&self.identity.did),
                None,
                &self.resolver,
                self.identity.secrets(),
                options,
            )
            .await
        {
            Ok(packed) => Some(packed),
            Err(err) => {
                tracing::warn!(%sender, error = %err, "could not pack reply");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use almena_didcomm::Curve;
    use serde_json::json;

    use super::*;
    use crate::testing::Wallet;

    fn mediator() -> Mediator {
        crate::testing::mediator()
    }

    fn ping(wallet: &Wallet) -> Message {
        Message::new(protocols::PING, json!({"response_requested": true}))
            .from(&wallet.did)
            .header("return_route", json!("all"))
    }

    #[tokio::test]
    async fn ping_with_return_route_gets_a_response_on_every_curve_the_mediator_has() {
        let mediator = mediator();
        for curve in [Curve::X25519, Curve::P384] {
            let wallet = Wallet::new(curve);
            let request = ping(&wallet);
            let packed = wallet
                .send(mediator.identity(), request.clone(), false)
                .await;
            let Outcome::Reply(reply) = mediator.receive(&packed, None).await.unwrap() else {
                panic!("expected a reply");
            };
            let response = wallet.open(mediator.identity(), &reply).await;
            assert_eq!(response.type_, protocols::PING_RESPONSE);
            assert_eq!(response.thid.as_deref(), Some(request.id.as_str()));
        }
    }

    #[tokio::test]
    async fn anoncrypted_ping_from_a_known_did_is_answered() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let packed = wallet.send(mediator.identity(), ping(&wallet), true).await;
        assert!(matches!(
            mediator.receive(&packed, None).await.unwrap(),
            Outcome::Reply(_)
        ));
    }

    #[tokio::test]
    async fn without_return_route_nothing_comes_back() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let mut request = ping(&wallet);
        request.extra_headers.remove("return_route");
        let packed = wallet.send(mediator.identity(), request, false).await;
        assert_eq!(
            mediator.receive(&packed, None).await.unwrap(),
            Outcome::Accepted
        );
    }

    #[tokio::test]
    async fn return_route_values() {
        let mediator = mediator();
        let wallet = Wallet::new(Curve::X25519);
        for (value, websocket, replies) in [
            (Some("all"), false, true),
            (Some("thread"), false, true),
            (Some("none"), false, false),
            (None, false, false),
            (None, true, true),
            (Some("none"), true, false),
        ] {
            let mut ping = Message::new(protocols::PING, json!({})).from(&wallet.did);
            if let Some(value) = value {
                ping = ping.header("return_route", json!(value));
            }
            let packed = wallet.send(mediator.identity(), ping, false).await;
            let mut session = websocket.then(|| mediator.open_session().0);
            let outcome = mediator.receive(&packed, session.as_mut()).await.unwrap();
            assert_eq!(
                matches!(outcome, Outcome::Reply(_)),
                replies,
                "return_route {value:?} on websocket {websocket}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_types_get_a_problem_report() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let request = Message::new("https://example.com/chess/1.0/move", json!({}))
            .from(&wallet.did)
            .header("return_route", json!("all"));
        let packed = wallet
            .send(mediator.identity(), request.clone(), false)
            .await;
        let Outcome::Reply(reply) = mediator.receive(&packed, None).await.unwrap() else {
            panic!("expected a problem report");
        };
        let report = wallet.open(mediator.identity(), &reply).await;
        assert_eq!(report.type_, protocols::PROBLEM_REPORT);
        assert_eq!(report.body["code"], "e.m.msg.unsupported-type");
        assert_eq!(report.pthid.as_deref(), Some(request.id.as_str()));
    }

    #[tokio::test]
    async fn expired_messages_get_a_problem_report() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let mut request = ping(&wallet);
        request.expires_time = Some(1);
        let packed = wallet.send(mediator.identity(), request, false).await;
        let Outcome::Reply(reply) = mediator.receive(&packed, None).await.unwrap() else {
            panic!("expected a problem report");
        };
        assert_eq!(
            wallet.open(mediator.identity(), &reply).await.body["code"],
            "e.m.req.time.expired"
        );
    }

    #[tokio::test]
    async fn plaintext_is_refused() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let plain = ping(&wallet)
            .to([mediator.identity().did.as_str()])
            .pack_plaintext()
            .unwrap();
        assert!(matches!(
            mediator.receive(&plain, None).await,
            Err(ReceiveError::Unpack(_))
        ));
    }

    #[tokio::test]
    async fn envelopes_for_someone_else_are_refused() {
        let mediator = mediator();
        let (wallet, other) = (Wallet::new(Curve::X25519), Wallet::new(Curve::X25519));
        let packed = ping(&wallet)
            .to([other.did.as_str()])
            .pack_encrypted(
                &other.did,
                Some(&wallet.did),
                None,
                &LocalResolver::new(),
                &wallet.secrets,
                PackOptions::default(),
            )
            .await
            .unwrap()
            .message;
        assert!(matches!(
            mediator.receive(&packed, None).await,
            Err(ReceiveError::Unpack(almena_didcomm::Error::SecretNotFound(
                _
            )))
        ));
    }

    // ---- Coordinate Mediation, forward and Message Pickup ----

    use almena_didcomm::{Attachment, b64};

    /// Grants mediation to `wallet` and registers its own DID as a recipient.
    async fn mediate(mediator: &Mediator, wallet: &Wallet) {
        let grant = wallet
            .request(mediator, protocols::MEDIATE_REQUEST, json!({}))
            .await;
        assert_eq!(grant.type_, protocols::MEDIATE_GRANT);
        assert_eq!(grant.body["routing_did"], json!([mediator.identity().did]));
        let response = wallet
            .request(
                mediator,
                protocols::RECIPIENT_UPDATE,
                json!({"updates": [{"recipient_did": wallet.did, "action": "add"}]}),
            )
            .await;
        assert_eq!(response.body["updated"][0]["result"], "success");
    }

    /// Alice → (forward via the mediator) → Bob, as Alice's wallet would send it.
    async fn send_via_mediator(
        mediator: &Mediator,
        alice: &Wallet,
        bob: &Wallet,
        text: &str,
    ) -> Result<Outcome, ReceiveError> {
        send_via_mediator_with(mediator, alice, bob, text, almena_didcomm::Urgency::Normal).await
    }

    /// [`send_via_mediator`], with the forward marked `urgency`.
    async fn send_via_mediator_with(
        mediator: &Mediator,
        alice: &Wallet,
        bob: &Wallet,
        text: &str,
        urgency: almena_didcomm::Urgency,
    ) -> Result<Outcome, ReceiveError> {
        let packed = Message::new(
            "https://example.com/chat/1.0/message",
            json!({ "text": text }),
        )
        .from(&alice.did)
        .to([bob.did.as_str()])
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &Wallet::resolver(mediator.identity()),
            &alice.secrets,
            PackOptions {
                urgency,
                ..PackOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(packed.forwarded, "Bob's DID routes through the mediator");
        assert_eq!(
            packed.service_uri.as_deref(),
            Some("https://mediator.example.com/didcomm")
        );
        mediator.receive(&packed.message, None).await
    }

    #[tokio::test]
    async fn a_message_travels_from_alice_to_bob_through_the_mediator() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;

        assert_eq!(
            send_via_mediator(&mediator, &alice, &bob, "hi Bob")
                .await
                .unwrap(),
            Outcome::Accepted
        );

        let status = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(status.type_, protocols::STATUS);
        assert_eq!(status.body["message_count"], 1);
        assert_eq!(status.body["live_delivery"], false);

        let delivery = bob
            .request(&mediator, protocols::DELIVERY_REQUEST, json!({"limit": 10}))
            .await;
        assert_eq!(delivery.type_, protocols::DELIVERY);
        let attachments = delivery.attachments.unwrap();
        assert_eq!(attachments.len(), 1);
        let packed =
            String::from_utf8(b64::decode(attachments[0].data.base64.as_deref().unwrap()).unwrap())
                .unwrap();
        let (message, meta) = unpack(
            &packed,
            &Wallet::resolver(mediator.identity()),
            &bob.secrets,
        )
        .await
        .unwrap();
        assert!(meta.authenticated);
        assert_eq!(message.from.as_deref(), Some(alice.did.as_str()));
        assert_eq!(message.body["text"], "hi Bob");

        // Delivered messages stay until acknowledged.
        let again = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(again.body["message_count"], 1);
        let id = attachments[0].id.clone().unwrap();
        let after = bob
            .request(
                &mediator,
                protocols::MESSAGES_RECEIVED,
                json!({"message_id_list": [id]}),
            )
            .await;
        assert_eq!(after.type_, protocols::STATUS);
        assert_eq!(after.body["message_count"], 0);

        // With an empty queue, a delivery request answers with a status.
        let empty = bob
            .request(&mediator, protocols::DELIVERY_REQUEST, json!({"limit": 10}))
            .await;
        assert_eq!(empty.type_, protocols::STATUS);
    }

    #[tokio::test]
    async fn pickup_filters_by_recipient_did() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let bob_other = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        bob.request(
            &mediator,
            protocols::RECIPIENT_UPDATE,
            json!({"updates": [{"recipient_did": bob_other.did, "action": "add"}]}),
        )
        .await;
        send_via_mediator(&mediator, &alice, &bob, "one")
            .await
            .unwrap();
        send_via_mediator(&mediator, &alice, &bob_other, "two")
            .await
            .unwrap();

        let all = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(all.body["message_count"], 2);
        let one = bob
            .request(
                &mediator,
                protocols::STATUS_REQUEST,
                json!({"recipient_did": bob_other.did}),
            )
            .await;
        assert_eq!(one.body["message_count"], 1);
        assert_eq!(one.body["recipient_did"], bob_other.did);

        let stranger = Wallet::new(Curve::X25519);
        let report = bob
            .request(
                &mediator,
                protocols::DELIVERY_REQUEST,
                json!({"limit": 1, "recipient_did": stranger.did}),
            )
            .await;
        assert_eq!(report.body["code"], "e.m.msg.unknown-recipient");
    }

    #[tokio::test]
    async fn recipient_updates_report_each_result() {
        let mediator = mediator();
        let (bob, carol) = (Wallet::new(Curve::X25519), Wallet::new(Curve::X25519));
        mediate(&mediator, &bob).await;
        mediate(&mediator, &carol).await;
        let response = bob
            .request(
                &mediator,
                protocols::RECIPIENT_UPDATE,
                json!({"updates": [
                    {"recipient_did": bob.did, "action": "add"},
                    {"recipient_did": carol.did, "action": "add"},
                    {"recipient_did": "did:example:new", "action": "add"},
                    {"recipient_did": "did:example:x#key-1", "action": "add"},
                    {"recipient_did": "did:example:y", "action": "remove"},
                    {"recipient_did": "did:example:new", "action": "rename"}
                ]}),
            )
            .await;
        let results: Vec<_> = response.body["updated"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["result"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            results,
            [
                "no_change",
                "client_error",
                "success",
                "client_error",
                "no_change",
                "client_error"
            ]
        );
    }

    fn mediator_requiring_proof() -> Mediator {
        Mediator::new(
            Identity::ephemeral("https://mediator.example.com").unwrap(),
            Arc::new(crate::store::MemoryStore::new()),
            Limits {
                recipient_proof: true,
                ..crate::testing::LIMITS
            },
            None,
        )
    }

    fn add(did: &str, proof: Option<&str>) -> serde_json::Value {
        let mut update = json!({"recipient_did": did, "action": "add"});
        if let Some(proof) = proof {
            update["proof"] = json!(proof);
        }
        json!({ "updates": [update] })
    }

    async fn add_result(
        mediator: &Mediator,
        by: &Wallet,
        did: &str,
        proof: Option<&str>,
    ) -> String {
        let reply = by
            .request(mediator, protocols::RECIPIENT_UPDATE, add(did, proof))
            .await;
        reply.body["updated"][0]["result"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn registering_another_did_needs_a_proof_from_it() {
        let mediator = mediator_requiring_proof();
        let id = mediator.identity();
        let (bob, bob_other, mallory) = (
            Wallet::new(Curve::X25519),
            Wallet::new(Curve::X25519),
            Wallet::new(Curve::X25519),
        );
        // Its own DID needs none: the authcrypt already proves it.
        mediate(&mediator, &bob).await;
        mediate(&mediator, &mallory).await;
        let now = now();
        let good = bob_other.proof(id, &bob.did, now).await;

        assert_eq!(
            add_result(&mediator, &bob, &bob_other.did, None).await,
            "client_error"
        );
        // Bob's proof replayed by Mallory's mediation.
        assert_eq!(
            add_result(&mediator, &mallory, &bob_other.did, Some(&good)).await,
            "client_error"
        );
        // Made for another mediator.
        let elsewhere = Identity::ephemeral("https://other.example.com").unwrap();
        let foreign = bob_other.proof(&elsewhere, &bob.did, now).await;
        assert_eq!(
            add_result(&mediator, &bob, &bob_other.did, Some(&foreign)).await,
            "client_error"
        );
        // Too old.
        let stale = bob_other.proof(id, &bob.did, now - 3600).await;
        assert_eq!(
            add_result(&mediator, &bob, &bob_other.did, Some(&stale)).await,
            "client_error"
        );
        // Mallory proving her own DID does not prove Bob's.
        let hers = mallory.proof(id, &bob.did, now).await;
        assert_eq!(
            add_result(&mediator, &bob, &bob_other.did, Some(&hers)).await,
            "client_error"
        );
        assert_eq!(
            add_result(&mediator, &bob, &bob_other.did, Some(&good)).await,
            "success"
        );
        assert_eq!(
            mediator.store().mediation_of(&bob_other.did).await.unwrap(),
            Some(bob.did.clone())
        );
    }

    #[tokio::test]
    async fn idle_mediations_are_removed_and_active_ones_kept() {
        let mediator = mediator();
        let (idle, active) = (Wallet::new(Curve::X25519), Wallet::new(Curve::X25519));
        // Both granted long ago...
        for wallet in [&idle, &active] {
            mediator
                .store()
                .grant_mediation(&wallet.did, 1_000)
                .await
                .unwrap();
        }
        // ...but one wallet still picks up.
        active
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;

        let removed = remove_idle(mediator.store(), 3600, now()).await.unwrap();
        assert_eq!(removed, 1);
        assert!(!mediator.store().has_mediation(&idle.did).await.unwrap());
        assert!(mediator.store().has_mediation(&active.did).await.unwrap());
        let report = idle
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(report.body["code"], "e.m.req.no-mediation");
    }

    /// Bob's ping without `return_route`, authcrypted unless `anonymous`.
    async fn ping_without_return_route(mediator: &Mediator, bob: &Wallet, anonymous: bool) {
        let ping = Message::new(protocols::PING, json!({})).from(&bob.did);
        let packed = bob.send(mediator.identity(), ping, anonymous).await;
        assert_eq!(
            mediator.receive(&packed, None).await.unwrap(),
            Outcome::Accepted
        );
    }

    #[tokio::test]
    async fn a_reply_without_return_route_waits_in_the_senders_queue() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        mediate(&mediator, &bob).await;
        ping_without_return_route(&mediator, &bob, false).await;

        let delivery = bob
            .request(&mediator, protocols::DELIVERY_REQUEST, json!({"limit": 10}))
            .await;
        let attachments = delivery.attachments.unwrap();
        assert_eq!(attachments.len(), 1);
        let queued =
            String::from_utf8(b64::decode(attachments[0].data.base64.as_deref().unwrap()).unwrap())
                .unwrap();
        let pong = bob.open(mediator.identity(), &queued).await;
        assert_eq!(pong.type_, protocols::PING_RESPONSE);
    }

    #[tokio::test]
    async fn a_mediation_did_gets_its_replies_unregistered_and_unwrapped() {
        let mediator = mediator();
        // Mediated here, its DID not registered as a recipient, and naming
        // the mediator as its own: a reply wrapped for its service would
        // come back here and be dropped.
        let bob = Wallet::mediated_by(&mediator.identity().did);
        bob.request(&mediator, protocols::MEDIATE_REQUEST, json!({}))
            .await;
        ping_without_return_route(&mediator, &bob, false).await;

        let delivery = bob
            .request(&mediator, protocols::DELIVERY_REQUEST, json!({"limit": 10}))
            .await;
        let attachments = delivery.attachments.unwrap();
        assert_eq!(attachments.len(), 1);
        let queued =
            String::from_utf8(b64::decode(attachments[0].data.base64.as_deref().unwrap()).unwrap())
                .unwrap();
        assert_eq!(
            bob.open(mediator.identity(), &queued).await.type_,
            protocols::PING_RESPONSE
        );
    }

    #[tokio::test]
    async fn pickup_answers_only_travel_back_on_the_connection() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        mediate(&mediator, &bob).await;
        let status = Message::new(protocols::STATUS_REQUEST, json!({})).from(&bob.did);
        let packed = bob.send(mediator.identity(), status, false).await;
        assert_eq!(
            mediator.receive(&packed, None).await.unwrap(),
            Outcome::Accepted
        );
        let status = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(status.body["message_count"], 0);
    }

    #[tokio::test]
    async fn an_unauthenticated_sender_gets_no_reply_anywhere() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        mediate(&mediator, &bob).await;
        // Anyone can write Bob's DID as `from` in an anoncrypted message.
        ping_without_return_route(&mediator, &bob, true).await;
        let status = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(status.body["message_count"], 0);
    }

    #[tokio::test]
    async fn recipient_limit_is_enforced() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        let updates: Vec<_> = (0..crate::testing::LIMITS.max_recipient_dids)
            .map(|i| json!({"recipient_did": format!("did:example:{i}"), "action": "add"}))
            .collect();
        let response = bob
            .request(
                &mediator,
                protocols::RECIPIENT_UPDATE,
                json!({ "updates": updates }),
            )
            .await;
        // One slot was already taken by Bob's own DID.
        assert_eq!(
            response.body["updated"].as_array().unwrap().last().unwrap()["result"],
            "client_error"
        );

        // More updates than a mediation may hold DIDs: refused whole, before
        // any proof is looked at.
        let updates: Vec<_> = (0..=crate::testing::LIMITS.max_recipient_dids)
            .map(|i| json!({"recipient_did": format!("did:example:x{i}"), "action": "add"}))
            .collect();
        let report = bob
            .request(
                &mediator,
                protocols::RECIPIENT_UPDATE,
                json!({ "updates": updates }),
            )
            .await;
        assert_eq!(report.body["code"], "e.m.msg.invalid-body");
    }

    #[tokio::test]
    async fn recipient_query_paginates() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        bob.request(
            &mediator,
            protocols::RECIPIENT_UPDATE,
            json!({"updates": [{"recipient_did": "did:example:a", "action": "add"}, {"recipient_did": "did:example:b", "action": "add"}]}),
        )
        .await;
        let all = bob
            .request(&mediator, protocols::RECIPIENT_QUERY, json!({}))
            .await;
        assert_eq!(all.body["dids"].as_array().unwrap().len(), 3);
        assert!(all.body.get("pagination").is_none());

        let page = bob
            .request(
                &mediator,
                protocols::RECIPIENT_QUERY,
                json!({"paginate": {"limit": 1, "offset": 1}}),
            )
            .await;
        assert_eq!(
            page.body["dids"],
            json!([{"recipient_did": "did:example:b"}])
        );
        assert_eq!(
            page.body["pagination"],
            json!({"count": 1, "offset": 1, "remaining": 1})
        );
    }

    #[tokio::test]
    async fn mediation_and_pickup_need_an_authenticated_sender() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        let request = Message::new(protocols::MEDIATE_REQUEST, json!({}))
            .from(&bob.did)
            .header("return_route", json!("all"));
        let packed = bob.send(mediator.identity(), request, true).await;
        let Outcome::Reply(reply) = mediator.receive(&packed, None).await.unwrap() else {
            panic!("expected a problem report");
        };
        let report = bob.open(mediator.identity(), &reply).await;
        assert_eq!(report.body["code"], "e.m.trust.unauthenticated");
        assert!(!mediator.store().has_mediation(&bob.did).await.unwrap());
    }

    #[tokio::test]
    async fn pickup_without_mediation_is_refused() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        let report = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(report.body["code"], "e.m.req.no-mediation");
    }

    #[tokio::test]
    async fn live_mode_is_refused_over_http() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        let on = bob
            .request(
                &mediator,
                protocols::LIVE_DELIVERY_CHANGE,
                json!({"live_delivery": true}),
            )
            .await;
        assert_eq!(on.body["code"], "e.m.live-mode-not-supported");
        let off = bob
            .request(
                &mediator,
                protocols::LIVE_DELIVERY_CHANGE,
                json!({"live_delivery": false}),
            )
            .await;
        assert_eq!(off.type_, protocols::STATUS);
    }

    #[tokio::test]
    async fn a_full_queue_refuses_more_forwards() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        for i in 0..crate::testing::LIMITS.queue.max_messages {
            send_via_mediator(&mediator, &alice, &bob, &i.to_string())
                .await
                .unwrap();
        }
        let err = send_via_mediator(&mediator, &alice, &bob, "one too many")
            .await
            .unwrap_err();
        assert!(matches!(err, ReceiveError::QueueFull));
    }

    #[tokio::test]
    async fn forwards_for_unknown_recipients_are_refused() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        let err = send_via_mediator(&mediator, &alice, &bob, "hi")
            .await
            .unwrap_err();
        assert!(matches!(err, ReceiveError::UnknownRecipient));
    }

    #[tokio::test]
    async fn forwards_must_carry_encrypted_messages() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        let forward = Message::new(almena_didcomm::FORWARD, json!({"next": bob.did}))
            .attachment(Attachment::json(json!({"not": "a jwe"})));
        let packed = bob.send(mediator.identity(), forward, true).await;
        let err = mediator.receive(&packed, None).await.unwrap_err();
        assert!(matches!(err, ReceiveError::BadForward(_)));
        assert_eq!(
            mediator
                .store()
                .summary(&bob.did, None, now(), 3600)
                .await
                .unwrap()
                .count,
            0
        );
    }

    // ---- Federation ----

    use crate::testing::{InProcess, mediator_at};
    use almena_didcomm::did::{
        ChainResolver as Chain, LocalResolver as Local, StaticResolver as Static,
    };

    /// Alice hands a message for Bob (mediated at B) to her own mediator A,
    /// which relays it to B.
    #[tokio::test]
    async fn a_mediator_relays_forwards_to_the_recipients_mediator() {
        let net = Arc::new(InProcess::default());
        let (a, b, bob) =
            federation(net.clone() as Arc<dyn crate::transport::Transport>, &net).await;
        let to_a = forward_via(&a, &b, &bob).await;
        assert_eq!(a.receive(&to_a, None).await.unwrap(), Outcome::Accepted);
        let status = bob.request(&b, protocols::STATUS_REQUEST, json!({})).await;
        assert_eq!(status.body["message_count"], 1);
    }

    /// Mediators A (with `a_transport`) and B on `net`, and Bob mediated at B.
    async fn federation(
        a_transport: Arc<dyn crate::transport::Transport>,
        net: &Arc<InProcess>,
    ) -> (Arc<Mediator>, Arc<Mediator>, Wallet) {
        let a = mediator_at("https://a.example", Some(a_transport));
        let b = mediator_at(
            "https://b.example",
            Some(net.clone() as Arc<dyn crate::transport::Transport>),
        );
        net.add("https://a.example", &a);
        net.add("https://b.example", &b);
        let bob = Wallet::mediated_by(&b.identity().did);
        mediate(&b, &bob).await;
        (a, b, bob)
    }

    /// Alice's message for Bob, handed to A in a forward whose next is B.
    async fn forward_via(a: &Mediator, b: &Mediator, bob: &Wallet) -> String {
        let alice = Wallet::new(Curve::X25519);
        let resolver = Chain::new(vec![
            Arc::new(Static::new([
                a.identity().document.clone(),
                b.identity().document.clone(),
            ])),
            Arc::new(Local::new()),
        ]);
        // What Alice's wallet would send B directly...
        let for_b = Message::new(
            "https://example.com/chat/1.0/message",
            json!({"text": "via A"}),
        )
        .from(&alice.did)
        .to([bob.did.as_str()])
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &resolver,
            &alice.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();
        assert!(for_b.forwarded);
        // ...handed to A instead.
        let envelope: serde_json::Value = serde_json::from_str(&for_b.message).unwrap();
        Message::new(FORWARD, json!({"next": b.identity().did}))
            .to([a.identity().did.as_str()])
            .attachment(Attachment::json(envelope))
            .pack_encrypted(
                &a.identity().did,
                None,
                None,
                &resolver,
                &alice.secrets,
                PackOptions {
                    forward: false,
                    ..PackOptions::default()
                },
            )
            .await
            .unwrap()
            .message
    }

    #[tokio::test]
    async fn a_reply_to_a_sender_mediated_elsewhere_goes_through_its_mediator() {
        let net = Arc::new(InProcess::default());
        let (a, b, bob) =
            federation(net.clone() as Arc<dyn crate::transport::Transport>, &net).await;
        // Bob pings A, without return_route: A's answer travels to B.
        ping_without_return_route(&a, &bob, false).await;
        for _ in 0..100 {
            let queued = b
                .store()
                .summary(&bob.did, None, now(), 3600)
                .await
                .unwrap()
                .count;
            if queued == 1 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("A's reply never reached Bob's queue at B");
    }

    /// A transport whose first `failures` POSTs fail.
    struct Flaky {
        net: Arc<InProcess>,
        failures: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::transport::Transport for Flaky {
        async fn get_json(&self, url: &str) -> anyhow::Result<serde_json::Value> {
            self.net.get_json(url).await
        }

        async fn get_text(&self, url: &str) -> anyhow::Result<String> {
            self.net.get_text(url).await
        }

        async fn post_didcomm(&self, url: &str, message: &str) -> anyhow::Result<()> {
            use std::sync::atomic::Ordering;
            if self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                anyhow::bail!("{url} is down");
            }
            self.net.post_didcomm(url, message).await
        }
    }

    fn flaky(net: &Arc<InProcess>, failures: usize) -> Arc<Flaky> {
        Arc::new(Flaky {
            net: net.clone(),
            failures: failures.into(),
        })
    }

    #[tokio::test]
    async fn a_failed_relay_is_stored_and_retried() {
        let net = Arc::new(InProcess::default());
        let transport = flaky(&net, 1);
        let (a, b, bob) = federation(transport.clone(), &net).await;
        let to_a = forward_via(&a, &b, &bob).await;
        assert_eq!(a.receive(&to_a, None).await.unwrap(), Outcome::Accepted);
        let count = |b: Arc<Mediator>, bob_did: String| async move {
            b.store()
                .summary(&bob_did, None, now(), 3600)
                .await
                .unwrap()
                .count
        };
        assert_eq!(count(b.clone(), bob.did.clone()).await, 0);

        // Waiting in A's store, not yet due...
        let start = now();
        relay::retry_due(a.store(), transport.as_ref(), start + 1)
            .await
            .unwrap();
        assert_eq!(count(b.clone(), bob.did.clone()).await, 0);
        // ...then delivered, and gone from the store.
        relay::retry_due(a.store(), transport.as_ref(), start + 5)
            .await
            .unwrap();
        assert_eq!(count(b.clone(), bob.did.clone()).await, 1);
        assert!(
            a.store()
                .due_relays(start + 100_000, 60, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_relay_is_abandoned_after_the_last_retry() {
        let net = Arc::new(InProcess::default());
        let transport = flaky(&net, usize::MAX);
        let (a, b, bob) = federation(transport.clone(), &net).await;
        let to_a = forward_via(&a, &b, &bob).await;
        assert_eq!(a.receive(&to_a, None).await.unwrap(), Outcome::Accepted);

        let mut at = now();
        for wait in [5, 30, 120, 600] {
            at += wait;
            assert_eq!(a.store().due_relays(at - 1, 0, 10).await.unwrap().len(), 0);
            relay::retry_due(a.store(), transport.as_ref(), at)
                .await
                .unwrap();
        }
        assert!(
            a.store()
                .due_relays(at + 100_000, 60, 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            b.store()
                .summary(&bob.did, None, now(), 3600)
                .await
                .unwrap()
                .count,
            0
        );
    }

    #[tokio::test]
    async fn without_federation_foreign_recipients_are_unknown() {
        let net = Arc::new(InProcess::default());
        let a = mediator_at("https://a.example", None);
        let b = mediator_at(
            "https://b.example",
            Some(net.clone() as Arc<dyn crate::transport::Transport>),
        );
        net.add("https://b.example", &b);
        let bob = Wallet::mediated_by(&b.identity().did);
        mediate(&b, &bob).await;
        let forward = Message::new(FORWARD, json!({"next": b.identity().did})).attachment(
            Attachment::json(serde_json::from_str(&some_jwe(&bob).await).unwrap()),
        );
        let packed = bob.send(a.identity(), forward, true).await;
        assert!(matches!(
            a.receive(&packed, None).await,
            Err(ReceiveError::UnknownRecipient)
        ));
    }

    #[tokio::test]
    async fn a_route_back_to_this_mediator_is_not_followed() {
        let net = Arc::new(InProcess::default());
        let a = mediator_at(
            "https://a.example",
            Some(net.clone() as Arc<dyn crate::transport::Transport>),
        );
        net.add("https://a.example", &a);
        // Carol names A as her mediator but never registered.
        let carol = Wallet::mediated_by(&a.identity().did);
        let forward = Message::new(FORWARD, json!({"next": carol.did})).attachment(
            Attachment::json(serde_json::from_str(&some_jwe(&carol).await).unwrap()),
        );
        let packed = carol.send(a.identity(), forward, true).await;
        assert!(matches!(
            a.receive(&packed, None).await,
            Err(ReceiveError::UnknownRecipient)
        ));
    }

    /// Any encrypted message for `wallet`.
    async fn some_jwe(wallet: &Wallet) -> String {
        Message::new("t", json!({}))
            .to([wallet.did.as_str()])
            .pack_encrypted(
                &wallet.did,
                None,
                None,
                &Local::new(),
                &wallet.secrets,
                PackOptions {
                    forward: false,
                    ..PackOptions::default()
                },
            )
            .await
            .unwrap()
            .message
    }

    // ---- Push wake-ups ----

    use crate::push::Service;
    use crate::testing::{Pushed, RecordingPusher};
    use almena_didcomm::Urgency;
    use tokio::sync::mpsc::UnboundedReceiver;

    type Sent = UnboundedReceiver<(Pushed, Service, String)>;

    const FCM_SET: &str = "https://didcomm.org/push-notifications-fcm/1.0/set-device-info";
    const FCM_GET: &str = "https://didcomm.org/push-notifications-fcm/1.0/get-device-info";
    const APNS_SET: &str = "https://didcomm.org/push-notifications-apns/1.0/set-device-info";
    const APNS_GET: &str = "https://didcomm.org/push-notifications-apns/1.0/get-device-info";

    fn mediator_with_push() -> (Mediator, Sent) {
        let (pusher, sent) = RecordingPusher::new(&[Service::Fcm, Service::Apns]);
        (mediator().with_pusher(pusher), sent)
    }

    async fn next_push(sent: &mut Sent) -> (Pushed, Service, String) {
        tokio::time::timeout(std::time::Duration::from_secs(2), sent.recv())
            .await
            .expect("a push")
            .unwrap()
    }

    async fn no_push(sent: &mut Sent) {
        let waited = tokio::time::timeout(std::time::Duration::from_millis(200), sent.recv()).await;
        assert!(waited.is_err(), "unexpected push: {waited:?}");
    }

    #[tokio::test]
    async fn push_protocols_are_unsupported_while_push_is_off() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        let report = bob
            .request(
                &mediator,
                FCM_SET,
                json!({"device_token": "t", "device_platform": "android"}),
            )
            .await;
        assert_eq!(report.body["code"], "e.m.msg.unsupported-type");
    }

    #[tokio::test]
    async fn devices_are_registered_read_and_removed() {
        let (mediator, _sent) = mediator_with_push();
        let bob = Wallet::new(Curve::X25519);
        let set = json!({"device_token": "fcm-token", "device_platform": "android"});

        let report = bob.request(&mediator, FCM_SET, set.clone()).await;
        assert_eq!(report.body["code"], "e.m.req.no-mediation");
        mediate(&mediator, &bob).await;

        let ack = bob.request(&mediator, FCM_SET, set).await;
        assert_eq!(ack.type_, protocols::ACK);
        assert_eq!(ack.body["status"], "OK");
        let info = bob.request(&mediator, FCM_GET, json!({})).await;
        assert_eq!(
            info.type_,
            "https://didcomm.org/push-notifications-fcm/1.0/device-info"
        );
        assert_eq!(info.body["device_token"], "fcm-token");
        assert_eq!(info.body["device_platform"], "android");

        bob.request(
            &mediator,
            FCM_SET,
            json!({"device_token": null, "device_platform": null}),
        )
        .await;
        let info = bob.request(&mediator, FCM_GET, json!({})).await;
        assert!(info.body["device_token"].is_null());

        let bad = bob
            .request(&mediator, APNS_SET, json!({"device_token": "not hex"}))
            .await;
        assert_eq!(bad.body["code"], "e.m.msg.invalid-body");

        let disclose = bob
            .request(
                &mediator,
                protocols::QUERIES,
                json!({"queries": [{"feature-type": "protocol", "match": "https://didcomm.org/push-notifications-*"}]}),
            )
            .await;
        assert_eq!(disclose.body["disclosures"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_forward_wakes_the_devices_once_until_the_wallet_picks_up() {
        let (mediator, mut sent) = mediator_with_push();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        bob.request(&mediator, APNS_SET, json!({"device_token": "a1b2"}))
            .await;

        send_via_mediator(&mediator, &alice, &bob, "one")
            .await
            .unwrap();
        assert_eq!(
            next_push(&mut sent).await,
            (Pushed::Wake, Service::Apns, "a1b2".into())
        );
        send_via_mediator(&mediator, &alice, &bob, "two")
            .await
            .unwrap();
        no_push(&mut sent).await;

        // Picking up re-arms it (the test minimum interval is 0).
        bob.request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        send_via_mediator(&mediator, &alice, &bob, "three")
            .await
            .unwrap();
        assert_eq!(
            next_push(&mut sent).await,
            (Pushed::Wake, Service::Apns, "a1b2".into())
        );
    }

    #[tokio::test]
    async fn a_live_session_needs_no_push() {
        let (mediator, mut sent) = mediator_with_push();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        bob.request(&mediator, APNS_SET, json!({"device_token": "a1b2"}))
            .await;

        let (mut session, _live) = mediator.open_session();
        let on = Message::new(
            protocols::LIVE_DELIVERY_CHANGE,
            json!({"live_delivery": true}),
        )
        .from(&bob.did);
        let packed = bob.send(mediator.identity(), on, false).await;
        mediator.receive(&packed, Some(&mut session)).await.unwrap();

        send_via_mediator(&mediator, &alice, &bob, "hi")
            .await
            .unwrap();
        // Nor a ring: the call offer reaches the wallet live.
        send_via_mediator_with(&mediator, &alice, &bob, "call", Urgency::Call)
            .await
            .unwrap();
        no_push(&mut sent).await;
    }

    #[tokio::test]
    async fn a_call_rings_and_a_message_wakes() {
        let (mediator, mut sent) = mediator_with_push();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        bob.request(
            &mediator,
            FCM_SET,
            json!({"device_token": "phone", "device_platform": "android"}),
        )
        .await;

        send_via_mediator(&mediator, &alice, &bob, "hi")
            .await
            .unwrap();
        assert_eq!(
            next_push(&mut sent).await,
            (Pushed::Wake, Service::Fcm, "phone".into())
        );
        // The wake-up hold does not keep a call from ringing.
        send_via_mediator_with(&mediator, &alice, &bob, "call", Urgency::Call)
            .await
            .unwrap();
        assert_eq!(
            next_push(&mut sent).await,
            (Pushed::Ring, Service::Fcm, "phone".into())
        );
        no_push(&mut sent).await;
    }

    #[tokio::test]
    async fn calls_ring_once_per_ring_interval() {
        let (pusher, mut sent) = RecordingPusher::new(&[Service::Fcm]);
        let mediator = Mediator::new(
            Identity::ephemeral("https://mediator.example.com").unwrap(),
            Arc::new(crate::store::MemoryStore::new()),
            Limits {
                push_ring_interval_secs: 3600,
                ..crate::testing::LIMITS
            },
            None,
        )
        .with_pusher(pusher);
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        bob.request(
            &mediator,
            FCM_SET,
            json!({"device_token": "phone", "device_platform": "android"}),
        )
        .await;

        send_via_mediator_with(&mediator, &alice, &bob, "offer", Urgency::Call)
            .await
            .unwrap();
        assert_eq!(next_push(&mut sent).await.0, Pushed::Ring);
        // The caller sends its offer again: the phone is already ringing.
        send_via_mediator_with(&mediator, &alice, &bob, "offer again", Urgency::Call)
            .await
            .unwrap();
        no_push(&mut sent).await;
    }

    #[tokio::test]
    async fn an_iphone_registers_its_voip_token_with_the_apns_protocol() {
        let (mediator, mut sent) = mediator_with_push();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        let info = || bob.request(&mediator, APNS_GET, json!({}));

        bob.request(
            &mediator,
            APNS_SET,
            json!({"device_token": "a1b2", "voip_device_token": "c3d4"}),
        )
        .await;
        let body = info().await.body;
        assert_eq!(body["device_token"], "a1b2");
        assert_eq!(body["voip_device_token"], "c3d4");

        // A call rings the VoIP token alone; a message wakes the alert one.
        send_via_mediator_with(&mediator, &alice, &bob, "call", Urgency::Call)
            .await
            .unwrap();
        assert_eq!(
            next_push(&mut sent).await,
            (Pushed::Ring, Service::ApnsVoip, "c3d4".into())
        );
        send_via_mediator(&mediator, &alice, &bob, "hi")
            .await
            .unwrap();
        assert_eq!(
            next_push(&mut sent).await,
            (Pushed::Wake, Service::Apns, "a1b2".into())
        );
        no_push(&mut sent).await;

        // Replaced.
        bob.request(
            &mediator,
            APNS_SET,
            json!({"device_token": "a1b2", "voip_device_token": "e5f6"}),
        )
        .await;
        assert_eq!(info().await.body["voip_device_token"], "e5f6");
        // A registration without it says the device has none.
        bob.request(&mediator, APNS_SET, json!({"device_token": "a1b2"}))
            .await;
        let body = info().await.body;
        assert_eq!(body["device_token"], "a1b2");
        assert!(body["voip_device_token"].is_null());
        // All null removes both.
        bob.request(
            &mediator,
            APNS_SET,
            json!({"device_token": null, "voip_device_token": "e5f6"}),
        )
        .await;
        bob.request(
            &mediator,
            APNS_SET,
            json!({"device_token": null, "voip_device_token": null}),
        )
        .await;
        assert!(mediator.store().devices(&bob.did).await.unwrap().is_empty());
        let bad = bob
            .request(
                &mediator,
                APNS_SET,
                json!({"device_token": "a1b2", "voip_device_token": "not hex"}),
            )
            .await;
        assert_eq!(bad.body["code"], "e.m.msg.invalid-body");
    }

    /// Alice hands her call offer for Bob, mediated at B, to her own mediator
    /// A: the forward A wraps for B still says it is a call.
    #[tokio::test]
    async fn a_relayed_call_still_rings() {
        let net = Arc::new(InProcess::default());
        let (pusher, mut sent) = RecordingPusher::new(&[Service::Fcm]);
        let a = mediator_at(
            "https://a.example",
            Some(net.clone() as Arc<dyn crate::transport::Transport>),
        );
        let b = Arc::new(
            Mediator::new(
                Identity::ephemeral("https://b.example").unwrap(),
                Arc::new(crate::store::MemoryStore::new()),
                crate::testing::LIMITS,
                Some(net.clone() as Arc<dyn crate::transport::Transport>),
            )
            .with_pusher(pusher),
        );
        net.add("https://a.example", &a);
        net.add("https://b.example", &b);
        let bob = Wallet::mediated_by(&b.identity().did);
        mediate(&b, &bob).await;
        bob.request(
            &b,
            FCM_SET,
            json!({"device_token": "phone", "device_platform": "android"}),
        )
        .await;

        let alice = Wallet::new(Curve::X25519);
        let offer = Message::new("https://example.com/call/1.0/offer", json!({}))
            .from(&alice.did)
            .to([bob.did.as_str()])
            .pack_encrypted(
                &bob.did,
                Some(&alice.did),
                None,
                &Local::new(),
                &alice.secrets,
                PackOptions {
                    forward: false,
                    ..PackOptions::default()
                },
            )
            .await
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&offer.message).unwrap();
        let forward = Message::new(FORWARD, json!({"next": bob.did}))
            .header(almena_didcomm::URGENCY, json!("call"))
            .attachment(Attachment::json(envelope));
        let packed = alice.send(a.identity(), forward, true).await;
        assert_eq!(a.receive(&packed, None).await.unwrap(), Outcome::Accepted);
        assert_eq!(
            next_push(&mut sent).await,
            (Pushed::Ring, Service::Fcm, "phone".into())
        );
    }

    #[tokio::test]
    async fn rejected_tokens_are_forgotten() {
        let (mediator, mut sent) = mediator_with_push();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        bob.request(
            &mediator,
            FCM_SET,
            json!({"device_token": "dead-token", "device_platform": "android"}),
        )
        .await;

        send_via_mediator(&mediator, &alice, &bob, "hi")
            .await
            .unwrap();
        assert_eq!(next_push(&mut sent).await.2, "dead-token");
        for _ in 0..50 {
            if mediator.store().devices(&bob.did).await.unwrap().is_empty() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the rejected token is still registered");
    }

    // ---- TURN credentials ----

    #[tokio::test]
    async fn turn_credentials_need_the_protocol_on_and_a_mediation() {
        let bob = Wallet::new(Curve::X25519);
        let off = mediator();
        mediate(&off, &bob).await;
        let report = bob
            .request(&off, protocols::TURN_CREDENTIALS_REQUEST, json!({}))
            .await;
        assert_eq!(report.body["code"], "e.m.msg.unsupported-type");

        let on = mediator().with_turn(TurnServer::new(
            vec!["turn:turn.example.com:3478".into()],
            "secret",
            600,
        ));
        let report = bob
            .request(&on, protocols::TURN_CREDENTIALS_REQUEST, json!({}))
            .await;
        assert_eq!(report.body["code"], "e.m.req.no-mediation");

        mediate(&on, &bob).await;
        let request = protocols::TURN_CREDENTIALS_REQUEST;
        let credentials = bob.request(&on, request, json!({})).await;
        assert_eq!(credentials.type_, protocols::TURN_CREDENTIALS);
        assert_eq!(credentials.body["ttl"], 600);
        let server = &credentials.body["ice_servers"][0];
        assert_eq!(server["urls"], json!(["turn:turn.example.com:3478"]));
        let expiry: u64 = server["username"]
            .as_str()
            .unwrap()
            .split(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(expiry > now() && expiry <= now() + 600);
        assert!(server["credential"].is_string());

        let disclose = bob
            .request(
                &on,
                protocols::QUERIES,
                json!({"queries": [{"feature-type": "protocol", "match": "https://almena.id/*"}]}),
            )
            .await;
        assert_eq!(
            disclose.body["disclosures"],
            json!([{"feature-type": "protocol", "id": "https://almena.id/protocols/turn/1.0", "roles": ["server"]}])
        );
    }

    #[tokio::test]
    async fn turn_credentials_need_an_authenticated_sender() {
        let mediator = mediator().with_turn(TurnServer::new(
            vec!["turn:turn.example.com".into()],
            "secret",
            600,
        ));
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        let request = Message::new(protocols::TURN_CREDENTIALS_REQUEST, json!({}))
            .from(&bob.did)
            .header("return_route", json!("all"));
        let packed = bob.send(mediator.identity(), request, true).await;
        let Outcome::Reply(reply) = mediator.receive(&packed, None).await.unwrap() else {
            panic!("expected a problem report");
        };
        assert_eq!(
            bob.open(mediator.identity(), &reply).await.body["code"],
            "e.m.trust.unauthenticated"
        );
    }
}
