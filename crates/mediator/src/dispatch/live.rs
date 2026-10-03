//! Live delivery (Message Pickup 3.0 "Live Mode"): WebSocket sessions that
//! asked for it get new messages for their mediation as soon as they are
//! queued.
//!
//! Live messages are pushed *and* stay queued until acknowledged with
//! `messages-received`, so a connection that drops mid-delivery loses
//! nothing (SPEC.md D7).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::store::Queued;

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

/// In-process registry of live sessions per mediation. A deployment with
/// several mediator instances would need to fan out through Redis pub/sub.
#[derive(Default)]
pub struct LiveHub {
    next_id: AtomicU64,
    sessions: Mutex<HashMap<String, Subscribers>>,
}

impl LiveHub {
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
    pub fn enable(&self, session: &mut Session, mediation: &str) {
        self.disable(session);
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions
                .entry(mediation.to_owned())
                .or_default()
                .push((session.id, session.sender.clone()));
            session.live = Some(mediation.to_owned());
            crate::metrics::METRICS.live_session_opened();
        }
    }

    pub fn disable(&self, session: &mut Session) {
        let Some(mediation) = session.live.take() else {
            return;
        };
        crate::metrics::METRICS.live_session_closed();
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(list) = sessions.get_mut(&mediation)
        {
            list.retain(|(id, _)| *id != session.id);
            if list.is_empty() {
                sessions.remove(&mediation);
            }
        }
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
}
