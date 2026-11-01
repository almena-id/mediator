//! Federation: passing a `forward` payload on to the mediator that mediates its
//! `next` recipient (SPEC.md §6.7).
//!
//! The payload is routed as a sender would route it: resolve `next`, wrap it
//! for the hops its `DIDCommMessaging` service lists. Then it is stored and
//! the `forward` answered; a background worker POSTs it to the service URI
//! at once and, if that fails, again with backoff ([`attempt`]), so neither a
//! slow destination nor a restart holds up or loses anything. Before it is
//! stored, each destination host is held to a rate (`ALMENA_RELAY_RATE_LIMIT`),
//! so strangers cannot turn the mediator against one host.

use std::sync::Arc;
use std::time::Duration;

use almena_didcomm::did::did_of;
use almena_didcomm::message::now;
use almena_didcomm::{ContentEncryption, Urgency, b64, route_with};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, Semaphore};

use super::{Mediator, ReceiveError};
use crate::identity::DIDCOMM_PATH;
use crate::metrics::{Forward, METRICS, Retry};
use crate::store::{PendingRelay, RelayLimits, Store};
use crate::transport::Transport;

/// Seconds before each retry after a failed attempt: five attempts in all.
const BACKOFF: [u64; 4] = [5, 30, 120, 600];
/// Relays waiting to be sent, at most: destinations that stay down must not
/// fill the store with copies, and one of them must not crowd out the rest.
const LIMITS: RelayLimits = RelayLimits {
    pending: 1000,
    per_destination: 50,
    bytes: 128 * 1024 * 1024,
};
/// How long a relay being tried is kept from other workers: longer than an
/// attempt takes, each being bounded by the transport's timeout.
const LEASE_SECS: u64 = 60;
/// Relays leased per store call, and how often the worker looks for due ones
/// when nothing wakes it.
const BATCH: usize = 16;
const TICK: Duration = Duration::from_secs(1);
/// Attempts in flight at once: one destination that never answers holds up
/// at most these, never the requests that brought the relays.
const CONCURRENCY: usize = 64;
/// The window of the per-destination rate limit.
const RATE_WINDOW_SECS: u64 = 60;

/// Routes `payloads` to `next` and hands them to the background worker; the
/// `forward`s around them carry `urgency` on, as the one that brought them
/// here did.
pub async fn relay(
    mediator: &Mediator,
    next: &str,
    payloads: Vec<String>,
    urgency: Urgency,
) -> Result<(), ReceiveError> {
    if mediator.transport().is_none() {
        return Err(ReceiveError::UnknownRecipient);
    }
    let own = &mediator.identity().did;
    let own_endpoint = own_endpoints(mediator);
    // Route them all before storing any: a payload that cannot be routed
    // refuses the forward whole, so the sender's retry duplicates nothing.
    let mut routed_all = Vec::with_capacity(payloads.len());
    for payload in payloads {
        let routed = route_with(
            payload,
            next,
            mediator.resolver(),
            ContentEncryption::A256CbcHs512,
            urgency,
        )
        .await
        .map_err(|err| {
            tracing::debug!(%next, error = %err, "cannot route forward");
            ReceiveError::UnknownRecipient
        })?;
        let Some(uri) = routed.service_uri else {
            tracing::debug!(%next, "next has no DIDComm service");
            return Err(ReceiveError::UnknownRecipient);
        };
        // A route that comes back to this mediator means `next` names us as its
        // mediator without having registered: nowhere to deliver.
        if routed.first_hop.as_deref().map(did_of) == Some(own.as_str())
            || own_endpoint.contains(&uri)
        {
            return Err(ReceiveError::UnknownRecipient);
        }
        routed_all.push((uri, routed.message));
    }
    send(mediator, routed_all).await
}

/// Stores already routed messages for the worker, after holding their
/// destinations to the rate limit: over it, none is stored. A relay with no
/// room left is dropped (SPEC.md §6.7); a store that fails refuses them.
pub(super) async fn send(
    mediator: &Mediator,
    routed: Vec<(String, String)>,
) -> Result<(), ReceiveError> {
    let relays: Vec<PendingRelay> = routed
        .into_iter()
        .map(|(uri, message)| PendingRelay {
            id: relay_id(&uri, &message),
            uri,
            message,
            attempts: 0,
        })
        .collect();
    let limit = mediator.limits().relay_rate_limit;
    if limit > 0 {
        let at = now();
        for relay in &relays {
            let key = format!("relay:{}", relay.destination());
            if mediator.store().hit(&key, RATE_WINDOW_SECS, at).await? > limit {
                tracing::info!(destination = %relay.destination(), "relay rate limit reached");
                METRICS.relay_rate_limited();
                return Err(ReceiveError::RelayRateLimited);
            }
        }
    }
    let due = now();
    for relay in &relays {
        if mediator.store().schedule_relay(relay, due, LIMITS).await? {
            tracing::debug!(uri = %relay.uri, "relay stored");
        } else {
            tracing::warn!(uri = %relay.uri, "too many relays waiting, dropped");
            METRICS.forward(Forward::RelayDropped, 1);
        }
    }
    mediator.relays_waiting().notify_one();
    Ok(())
}

pub(super) fn own_endpoints(mediator: &Mediator) -> Vec<String> {
    mediator
        .identity()
        .document
        .didcomm_services()
        .flat_map(|s| s.didcomm_endpoints().unwrap_or_default())
        .map(|e| e.uri)
        .filter(|uri| uri.ends_with(DIDCOMM_PATH))
        .collect()
}

/// The same payload for the same destination is one relay.
fn relay_id(uri: &str, message: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(uri.as_bytes());
    hash.update([0]);
    hash.update(message.as_bytes());
    b64::encode(hash.finalize())
}

/// Tries the relays due by `now` once each, all at once, and waits for
/// them: what the worker does, in one round, for tests to drive. The ones
/// that fail are rescheduled, or dropped after the last retry.
#[cfg(test)]
pub async fn retry_due(
    store: &dyn Store,
    transport: &dyn Transport,
    now: u64,
) -> anyhow::Result<()> {
    let due = store.due_relays(now, LEASE_SECS, BATCH).await?;
    let tried = due
        .into_iter()
        .map(|relay| attempt(store, transport, relay, now));
    futures_util::future::join_all(tried)
        .await
        .into_iter()
        .collect()
}

/// One attempt at `relay`: forgotten once delivered, rescheduled after a
/// failure, dropped after the last retry.
async fn attempt(
    store: &dyn Store,
    transport: &dyn Transport,
    relay: PendingRelay,
    now: u64,
) -> anyhow::Result<()> {
    let first = relay.attempts == 0;
    let attempt = relay.attempts + 1;
    match transport.post_didcomm(&relay.uri, &relay.message).await {
        Ok(()) => {
            tracing::debug!(uri = %relay.uri, attempt, "forward relayed");
            if first {
                METRICS.forward(Forward::Relayed, 1);
            } else {
                METRICS.relay_retry(Retry::Delivered);
            }
            store.finish_relay(&relay).await?;
        }
        Err(err) => {
            if let Some(wait) = BACKOFF.get(relay.attempts as usize) {
                tracing::info!(uri = %relay.uri, attempt, error = %format!("{err:#}"), "relay failed, will retry");
                if first {
                    METRICS.forward(Forward::RelayScheduled, 1);
                } else {
                    METRICS.relay_retry(Retry::Rescheduled);
                }
                let relay = PendingRelay {
                    attempts: attempt,
                    ..relay
                };
                // Already counted in: rescheduling it is never refused.
                store.schedule_relay(&relay, now + wait, LIMITS).await?;
            } else {
                tracing::warn!(uri = %relay.uri, attempt, error = %format!("{err:#}"), "relay abandoned after retries");
                METRICS.relay_retry(Retry::Abandoned);
                store.finish_relay(&relay).await?;
            }
        }
    }
    Ok(())
}

/// The worker: until the process ends, leases the relays that are due —
/// every second, and at once when `waiting` is notified — and tries each in
/// a task of its own, [`CONCURRENCY`] at most at a time.
pub fn spawn_worker(store: Arc<dyn Store>, transport: Arc<dyn Transport>, waiting: Arc<Notify>) {
    tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(CONCURRENCY));
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                () = waiting.notified() => {}
            }
            loop {
                let room = permits.available_permits().min(BATCH);
                if room == 0 {
                    break;
                }
                let due = match store.due_relays(now(), LEASE_SECS, room).await {
                    Ok(due) => due,
                    Err(err) => {
                        METRICS.store_error();
                        tracing::warn!(error = %format!("{err:#}"), "relay worker: store failed");
                        break;
                    }
                };
                let leased = due.len();
                for relay in due {
                    // There is a permit for each: `room` counted them.
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        break;
                    };
                    let (store, transport) = (Arc::clone(&store), Arc::clone(&transport));
                    tokio::spawn(async move {
                        if let Err(err) =
                            attempt(store.as_ref(), transport.as_ref(), relay, now()).await
                        {
                            METRICS.store_error();
                            tracing::warn!(error = %format!("{err:#}"), "relay attempt: store failed");
                        }
                        drop(permit);
                    });
                }
                if leased < room {
                    break;
                }
            }
        }
    });
}
