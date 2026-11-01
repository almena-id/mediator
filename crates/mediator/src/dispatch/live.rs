//! Live delivery (Message Pickup 3.0 "Live Mode"): WebSocket sessions that
//! asked for it get new messages for their mediation as soon as they are
//! queued.
//!
//! Live messages are pushed *and* stay queued until acknowledged with
//! `messages-received`, so a connection that drops mid-delivery loses
//! nothing (SPEC.md D7).
//!
//! Sessions live in the process that holds their socket. With several
//! instances on one Redis (SPEC.md, Appendix E), each says in the store
//! which mediations it holds live sessions for ([`PRESENCE_TTL_SECS`],
//! renewed while they last), and a message queued on one instance for a
//! mediation live on another goes to it over pub/sub ([`share`]); each
//! instance passes on what it hears to its own sessions. A mediation live
//! anywhere is online: no instance pushes to its devices.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use almena_didcomm::message::now;
use tokio::sync::mpsc;

use crate::metrics::METRICS;
use crate::store::{LiveEvent, Queued, Store};

/// How long an instance's word that it holds a live session for a
/// mediation lasts, unless renewed: an instance that dies stops silencing
/// pushes after this.
pub const PRESENCE_TTL_SECS: u64 = 60;
/// How often an instance renews it.
const PRESENCE_RENEW: Duration = Duration::from_secs(20);

/// Messages a live session can fall behind by; beyond that, pushes are
/// dropped (the messages are still in the queue).
const BUFFER: usize = 64;

/// A connection that can receive live deliveries (a WebSocket).
pub struct Session {
    id: u64,
    sender: mpsc::Sender<Queued>,
    /// The mediation this session receives live messages for, once enabled.
    live: Option<String>,
}

impl Session {
    /// Whether live mode is on for `mediation` on this session.
    pub fn is_live_for(&self, mediation: &str) -> bool {
        self.live.as_deref() == Some(mediation)
    }

    pub fn live_mediation(&self) -> Option<&str> {
        self.live.as_deref()
    }
}

type Subscribers = Vec<(u64, mpsc::Sender<Queued>)>;

/// In-process registry of live sessions per mediation, and this instance's
/// part in sharing them with the others.
pub struct LiveHub {
    next_id: AtomicU64,
    sessions: Mutex<HashMap<String, Subscribers>>,
    /// This instance's name among those sharing the store.
    instance: String,
    /// Whether it shares live sessions with other instances ([`start_sharing`]).
    shared: AtomicBool,
}

impl Default for LiveHub {
    fn default() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            sessions: Mutex::default(),
            instance: instance_name(),
            shared: AtomicBool::new(false),
        }
    }
}

/// 16 random hex digits: unique enough among a deployment's instances.
fn instance_name() -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 8];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        // Then the clock: two instances started in the same nanosecond
        // would share a name, and only miss each other's live events.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        bytes = (nanos as u64).to_be_bytes();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl LiveHub {
    pub fn instance(&self) -> &str {
        &self.instance
    }

    pub fn is_shared(&self) -> bool {
        self.shared.load(Ordering::Relaxed)
    }

    /// The mediations this instance holds live sessions for.
    pub fn mediations(&self) -> Vec<String> {
        self.sessions
            .lock()
            .map(|sessions| sessions.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// A new session and the receiver its connection task reads pushes from.
    pub fn open(&self) -> (Session, mpsc::Receiver<Queued>) {
        let (sender, receiver) = mpsc::channel(BUFFER);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        (
            Session {
                id,
                sender,
                live: None,
            },
            receiver,
        )
    }

    /// Turns live mode on for `mediation` (off for any other it had).
    /// Returns the mediation it had, if this instance holds no other live
    /// session for it any more.
    pub fn enable(&self, session: &mut Session, mediation: &str) -> Option<String> {
        let left = self.disable(session);
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions
                .entry(mediation.to_owned())
                .or_default()
                .push((session.id, session.sender.clone()));
            session.live = Some(mediation.to_owned());
            METRICS.live_session_opened();
        }
        left.filter(|left| left != mediation)
    }

    /// Turns live mode off. Returns the mediation it was on for, if this
    /// instance holds no other live session for it.
    pub fn disable(&self, session: &mut Session) -> Option<String> {
        let mediation = session.live.take()?;
        METRICS.live_session_closed();
        let mut sessions = self.sessions.lock().ok()?;
        let list = sessions.get_mut(&mediation)?;
        list.retain(|(id, _)| *id != session.id);
        if !list.is_empty() {
            return None;
        }
        sessions.remove(&mediation);
        Some(mediation)
    }

    /// Whether some session has live mode on for `mediation`.
    pub fn is_live(&self, mediation: &str) -> bool {
        self.sessions
            .lock()
            .is_ok_and(|sessions| sessions.get(mediation).is_some_and(|list| !list.is_empty()))
    }

    /// Pushes a newly queued message to the mediation's live sessions.
    /// Never blocks: a session that is behind or gone just misses the push.
    pub fn notify(&self, mediation: &str, queued: &Queued) {
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(list) = sessions.get_mut(mediation)
        {
            list.retain(|(_, sender)| match sender.try_send(queued.clone()) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            });
        }
    }
}

/// Whether `mediation` is online: a live session on this instance, or on
/// another one that shares the store. Not knowing counts as offline: a
/// needless push is better than a missing one.
pub async fn is_online(hub: &LiveHub, store: &dyn Store, mediation: &str) -> bool {
    if hub.is_live(mediation) {
        return true;
    }
    if !hub.is_shared() {
        return false;
    }
    match store.live_instances(mediation, now()).await {
        Ok(instances) => !instances.is_empty(),
        Err(err) => {
            METRICS.store_error();
            tracing::warn!(%mediation, error = %format!("{err:#}"), "live presence unknown");
            false
        }
    }
}

/// Messages just queued for `mediation`, already pushed to this instance's
/// sessions: sent to the other instances when one of them holds a live
/// session for it.
pub async fn share(hub: &LiveHub, store: &dyn Store, mediation: &str, queued: Vec<Queued>) {
    if !hub.is_shared() {
        return;
    }
    let elsewhere = match store.live_instances(mediation, now()).await {
        Ok(instances) => instances.iter().any(|i| i != hub.instance()),
        Err(err) => {
            METRICS.store_error();
            tracing::warn!(%mediation, error = %format!("{err:#}"), "live presence unknown");
            return;
        }
    };
    if !elsewhere {
        return;
    }
    for queued in queued {
        let event = LiveEvent {
            instance: hub.instance().to_owned(),
            mediation: mediation.to_owned(),
            queued,
        };
        if let Err(err) = store.publish_live(&event).await {
            METRICS.store_error();
            tracing::warn!(%mediation, error = %format!("{err:#}"), "live event not published");
        }
    }
}

/// Says in the store that this instance holds live sessions for
/// `mediation` (when sharing).
pub async fn present(hub: &LiveHub, store: &dyn Store, mediation: &str) {
    if hub.is_shared()
        && let Err(err) = store
            .set_live(mediation, hub.instance(), now(), PRESENCE_TTL_SECS)
            .await
    {
        METRICS.store_error();
        tracing::warn!(%mediation, error = %format!("{err:#}"), "live presence not stored");
    }
}

/// Takes back [`present`]: this instance holds no live session for
/// `mediation` any more.
pub async fn absent(hub: &LiveHub, store: &dyn Store, mediation: &str) {
    if hub.is_shared()
        && let Err(err) = store.clear_live(mediation, hub.instance()).await
    {
        METRICS.store_error();
        tracing::warn!(%mediation, error = %format!("{err:#}"), "live presence not cleared");
    }
}

/// Shares live sessions with the other instances on `store`, when it can be
/// shared (Redis): passes the events they publish to this instance's
/// sessions, and renews this instance's presence. Returns whether it does.
pub fn start_sharing(hub: &Arc<LiveHub>, store: &Arc<dyn Store>) -> bool {
    let Some(mut events) = store.subscribe_live() else {
        return false;
    };
    hub.shared.store(true, Ordering::Relaxed);
    let listening = Arc::clone(hub);
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if event.instance != listening.instance() {
                listening.notify(&event.mediation, &event.queued);
            }
        }
    });
    let (hub, store) = (Arc::clone(hub), Arc::clone(store));
    tokio::spawn(async move {
        let mut renew = tokio::time::interval(PRESENCE_RENEW);
        loop {
            renew.tick().await;
            for mediation in hub.mediations() {
                present(&hub, store.as_ref(), &mediation).await;
            }
        }
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queued(id: &str) -> Queued {
        Queued {
            id: id.into(),
            recipient: "did:example:r".into(),
            received: 0,
            message: "{}".into(),
        }
    }

    #[test]
    fn only_live_sessions_of_the_mediation_get_pushes() {
        let hub = LiveHub::default();
        let (mut a, mut a_rx) = hub.open();
        let (mut b, mut b_rx) = hub.open();
        let (_c, mut c_rx) = hub.open();
        hub.enable(&mut a, "did:example:m");
        hub.enable(&mut b, "did:example:other");

        hub.notify("did:example:m", &queued("1-0"));
        assert_eq!(a_rx.try_recv().unwrap().id, "1-0");
        assert!(b_rx.try_recv().is_err());
        assert!(c_rx.try_recv().is_err());

        hub.disable(&mut a);
        assert!(!a.is_live_for("did:example:m"));
        hub.notify("did:example:m", &queued("2-0"));
        assert!(a_rx.try_recv().is_err());
    }

    #[test]
    fn closed_sessions_are_forgotten() {
        let hub = LiveHub::default();
        let (mut a, a_rx) = hub.open();
        hub.enable(&mut a, "did:example:m");
        drop(a_rx);
        hub.notify("did:example:m", &queued("1-0"));
        assert!(
            hub.sessions
                .lock()
                .unwrap()
                .get("did:example:m")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_last_session_of_a_mediation_says_it_left() {
        let hub = LiveHub::default();
        let (mut a, _a_rx) = hub.open();
        let (mut b, _b_rx) = hub.open();
        assert_eq!(hub.enable(&mut a, "did:example:m"), None);
        assert_eq!(hub.enable(&mut b, "did:example:m"), None);
        assert_eq!(hub.mediations(), ["did:example:m"]);
        assert_eq!(hub.disable(&mut a), None);
        // Moving to another mediation leaves the first.
        assert_eq!(
            hub.enable(&mut b, "did:example:other").as_deref(),
            Some("did:example:m")
        );
        assert_eq!(hub.disable(&mut b).as_deref(), Some("did:example:other"));
        assert_eq!(hub.disable(&mut b), None);
        assert!(hub.mediations().is_empty());
    }

    #[tokio::test]
    async fn presence_is_checked_in_the_store_only_when_shared() {
        let store = crate::store::MemoryStore::new();
        let hub = LiveHub::default();
        store
            .set_live("did:example:m", "elsewhere", now(), 60)
            .await
            .unwrap();
        assert!(!is_online(&hub, &store, "did:example:m").await);
        hub.shared.store(true, Ordering::Relaxed);
        assert!(is_online(&hub, &store, "did:example:m").await);
        present(&hub, &store, "did:example:n").await;
        assert_eq!(
            store.live_instances("did:example:n", now()).await.unwrap(),
            [hub.instance()]
        );
        absent(&hub, &store, "did:example:n").await;
        assert!(!is_online(&hub, &store, "did:example:n").await);
    }
}
