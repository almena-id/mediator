//! Mediation state and message queues.
//!
//! [`Store`] is what the mediator needs from storage. Production uses Redis
//! ([`RedisStore`]); [`MemoryStore`] keeps everything in the process, for
//! tests and for `ALMENA_REDIS_URL=memory://` during development.
//!
//! A *mediation* is keyed by the DID the wallet used to request it. It owns a
//! set of recipient DIDs (the ones `forward` messages may name as `next`) and
//! one queue holding the messages for all of them, oldest first. Queue ids
//! look like Redis stream ids (`<ms>-<seq>`) and are the attachment ids of
//! Message Pickup deliveries.

mod memory;
mod redis;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

pub use self::memory::MemoryStore;
pub use self::redis::RedisStore;
use crate::push::{Device, Service};

/// Result of registering a recipient DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddRecipient {
    Added,
    /// Already registered by this mediation.
    AlreadyYours,
    /// Registered by another mediation.
    TakenByOther,
    /// The mediation has as many recipient DIDs as it may.
    LimitReached,
}

/// Result of removing a recipient DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveRecipient {
    Removed,
    NotRegistered,
    /// Registered by another mediation.
    NotYours,
}

/// A queued message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub id: String,
    pub recipient: String,
    /// Epoch seconds.
    pub received: u64,
    pub message: String,
}

/// Counts over a queue (or the part of it for one recipient).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueSummary {
    pub count: usize,
    /// Epoch seconds of the oldest and newest message.
    pub oldest: Option<u64>,
    pub newest: Option<u64>,
    pub total_bytes: u64,
}

/// A `forward` payload waiting to be relayed to another mediator again.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingRelay {
    /// Stable for the same payload and destination.
    pub id: String,
    pub uri: String,
    pub message: String,
    /// Retries already made.
    pub retries: u32,
}

impl PendingRelay {
    /// The host it goes to: what [`RelayLimits::per_destination`] counts.
    pub fn destination(&self) -> String {
        url::Url::parse(&self.uri)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
            .unwrap_or_else(|| self.uri.clone())
    }

    /// What it weighs: what [`RelayLimits::bytes`] counts.
    pub fn bytes(&self) -> u64 {
        self.message.len() as u64
    }
}

/// How many relays may wait for a retry, so that destinations that stay down
/// (or never answer) cannot fill the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Relays waiting in all.
    pub pending: usize,
    /// Relays waiting for one destination host.
    pub per_destination: usize,
    /// Bytes of the relays waiting in all.
    pub bytes: u64,
}

/// Queue limits, from the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLimits {
    /// Messages older than this (seconds) are dropped.
    pub ttl_secs: u64,
    /// Per mediation.
    pub max_messages: usize,
    /// Bytes of queued messages per mediation.
    pub max_bytes: u64,
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Checks the store is reachable.
    async fn ping(&self) -> Result<()>;
    /// `"redis"` or `"memory"`, for logs.
    fn kind(&self) -> &'static str;

    /// Records a granted mediation (idempotent) and counts it as active now.
    async fn grant_mediation(&self, mediation: &str, now: u64) -> Result<()>;
    /// The mediation's wallet did something at `now`; nothing if there is no
    /// such mediation.
    async fn touch_mediation(&self, mediation: &str, now: u64) -> Result<()>;
    /// Removes up to `limit` mediations last active at or before `cutoff`,
    /// with everything they own: recipient DIDs, queue, devices. Returns them.
    async fn remove_idle_mediations(&self, cutoff: u64, limit: usize) -> Result<Vec<String>>;
    async fn has_mediation(&self, mediation: &str) -> Result<bool>;

    /// Registers `recipient` for `mediation`, first come first served.
    async fn add_recipient(
        &self,
        mediation: &str,
        recipient: &str,
        max: usize,
    ) -> Result<AddRecipient>;
    /// Unregisters `recipient`. Its queued messages stay until picked up or expired.
    async fn remove_recipient(&self, mediation: &str, recipient: &str) -> Result<RemoveRecipient>;
    /// The mediation's recipient DIDs, sorted.
    async fn recipients(&self, mediation: &str) -> Result<Vec<String>>;
    /// The mediation that registered `recipient`, if any.
    async fn mediation_of(&self, recipient: &str) -> Result<Option<String>>;

    /// Appends messages to the mediation's queue, all of them or none: `None`
    /// when they would not all fit (as many messages or as many bytes as the
    /// limits allow), so a sender's retry never duplicates part of them.
    async fn enqueue_all(
        &self,
        mediation: &str,
        recipient: &str,
        messages: &[String],
        now: u64,
        limits: QueueLimits,
    ) -> Result<Option<Vec<String>>>;
    /// One message: [`Store::enqueue_all`] of one.
    async fn enqueue(
        &self,
        mediation: &str,
        recipient: &str,
        message: &str,
        now: u64,
        limits: QueueLimits,
    ) -> Result<Option<String>> {
        let ids = self
            .enqueue_all(mediation, recipient, &[message.to_owned()], now, limits)
            .await?;
        Ok(ids.and_then(|ids| ids.into_iter().next()))
    }
    /// Counts over the queue, or over `recipient`'s messages in it.
    async fn summary(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<QueueSummary>;
    /// Up to `limit` messages, oldest first, without removing them.
    async fn peek(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        limit: usize,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Vec<Queued>>;
    /// Removes messages by id; unknown ids are ignored. Returns how many went.
    async fn remove(&self, mediation: &str, ids: &[String]) -> Result<usize>;

    /// Counts a hit on `key` in the current fixed window of `window_secs`
    /// and returns the hits in that window so far.
    async fn hit(&self, key: &str, window_secs: u64, now: u64) -> Result<u64>;

    /// Stores `relay` to be tried again at `due` (epoch seconds), replacing
    /// any entry with its id. A new one is refused (`false`) when it would go
    /// over any of the `limits`.
    async fn schedule_relay(
        &self,
        relay: &PendingRelay,
        due: u64,
        limits: RelayLimits,
    ) -> Result<bool>;
    /// Up to `limit` relays due by `now`. They are leased for `lease_secs`:
    /// until [`Store::schedule_relay`] or [`Store::finish_relay`] is called or
    /// the lease runs out, nobody else gets them.
    async fn due_relays(
        &self,
        now: u64,
        lease_secs: u64,
        limit: usize,
    ) -> Result<Vec<PendingRelay>>;
    /// Forgets a relay: delivered, or given up.
    async fn finish_relay(&self, relay: &PendingRelay) -> Result<()>;

    /// Registers the mediation's device for `service`, replacing the one it
    /// had, or removes it (`None`).
    async fn set_device(
        &self,
        mediation: &str,
        service: Service,
        device: Option<&Device>,
    ) -> Result<()>;
    /// The mediation's devices, one per service at most, sorted by service.
    async fn devices(&self, mediation: &str) -> Result<Vec<(Service, Device)>>;
    /// Removes the device for `service` if its token is still `token`.
    async fn remove_device(&self, mediation: &str, service: Service, token: &str) -> Result<()>;
    /// Takes the turn to push to the mediation: `false` if a push went out
    /// and the wallet has not picked up since. The turn is held for at most
    /// `hold_secs`.
    async fn claim_push(&self, mediation: &str, now: u64, hold_secs: u64) -> Result<bool>;
    /// The wallet picked up: the next push may go `min_interval_secs` after
    /// the last one.
    async fn release_push(&self, mediation: &str, now: u64, min_interval_secs: u64) -> Result<()>;
    /// Takes the turn to ring the mediation for a call: `false` if a ring
    /// went out less than `interval_secs` ago. Independent of the wake-up
    /// turn of [`Store::claim_push`]; with an interval of 0 it always is.
    async fn claim_ring(&self, mediation: &str, now: u64, interval_secs: u64) -> Result<bool>;
}

/// Opens the store named by `url`: `memory://` for the in-process store,
/// anything else is a Redis URL, authenticated with `password` if given.
pub async fn open(url: &str, password: Option<&str>) -> Result<Arc<dyn Store>> {
    if url == "memory://" {
        Ok(Arc::new(MemoryStore::new()))
    } else {
        Ok(Arc::new(RedisStore::connect(url, password).await?))
    }
}

/// Whether `id` has the `<ms>-<seq>` shape of a queue id.
fn is_queue_id(id: &str) -> bool {
    id.split_once('-').is_some_and(|(ms, seq)| {
        !ms.is_empty()
            && !seq.is_empty()
            && ms.bytes().chain(seq.bytes()).all(|b| b.is_ascii_digit())
    })
}

/// Epoch milliseconds of a queue id.
fn id_millis(id: &str) -> u64 {
    id.split_once('-')
        .and_then(|(ms, _)| ms.parse().ok())
        .unwrap_or(0)
}

/// Shared behaviour tests, run against every [`Store`] implementation.
#[cfg(test)]
pub(crate) mod contract {
    use super::*;

    const LIMITS: QueueLimits = QueueLimits {
        ttl_secs: 3600,
        max_messages: 3,
        max_bytes: 1024,
    };

    pub async fn run(store: &dyn Store) {
        // Unique names so the Redis run does not trip over earlier runs.
        let tag = uuid();
        let (m1, m2) = (format!("did:peer:m1-{tag}"), format!("did:peer:m2-{tag}"));
        let (r1, r2, r3) = (
            format!("did:peer:r1-{tag}"),
            format!("did:peer:r2-{tag}"),
            format!("did:peer:r3-{tag}"),
        );
        store.ping().await.unwrap();

        assert!(!store.has_mediation(&m1).await.unwrap());
        store.grant_mediation(&m1, 100).await.unwrap();
        store.grant_mediation(&m1, 100).await.unwrap();
        store.grant_mediation(&m2, 100).await.unwrap();
        assert!(store.has_mediation(&m1).await.unwrap());

        assert_eq!(
            store.add_recipient(&m1, &r2, 2).await.unwrap(),
            AddRecipient::Added
        );
        assert_eq!(
            store.add_recipient(&m1, &r1, 2).await.unwrap(),
            AddRecipient::Added
        );
        assert_eq!(
            store.add_recipient(&m1, &r1, 2).await.unwrap(),
            AddRecipient::AlreadyYours
        );
        assert_eq!(
            store.add_recipient(&m1, &r3, 2).await.unwrap(),
            AddRecipient::LimitReached
        );
        assert_eq!(
            store.add_recipient(&m2, &r1, 2).await.unwrap(),
            AddRecipient::TakenByOther
        );
        assert_eq!(
            store.recipients(&m1).await.unwrap(),
            [r1.clone(), r2.clone()]
        );
        assert_eq!(store.mediation_of(&r1).await.unwrap(), Some(m1.clone()));
        assert_eq!(store.mediation_of(&r3).await.unwrap(), None);

        assert_eq!(
            store.remove_recipient(&m2, &r2).await.unwrap(),
            RemoveRecipient::NotYours
        );
        assert_eq!(
            store.remove_recipient(&m1, &r3).await.unwrap(),
            RemoveRecipient::NotRegistered
        );

        let now = now_for_tests();
        let a = store
            .enqueue(&m1, &r1, "a", now - 10, LIMITS)
            .await
            .unwrap()
            .unwrap();
        let b = store
            .enqueue(&m1, &r2, "bb", now - 5, LIMITS)
            .await
            .unwrap()
            .unwrap();
        let c = store
            .enqueue(&m1, &r1, "ccc", now, LIMITS)
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .enqueue(&m1, &r1, "full", now, LIMITS)
                .await
                .unwrap()
                .is_none()
        );
        assert!(is_queue_id(&a) && is_queue_id(&b) && is_queue_id(&c));

        let all = store
            .summary(&m1, None, now, LIMITS.ttl_secs)
            .await
            .unwrap();
        assert_eq!((all.count, all.total_bytes), (3, 6));
        assert!(all.oldest <= all.newest);
        let only_r1 = store
            .summary(&m1, Some(&r1), now, LIMITS.ttl_secs)
            .await
            .unwrap();
        assert_eq!((only_r1.count, only_r1.total_bytes), (2, 4));
        assert_eq!(
            store
                .summary(&m2, None, now, LIMITS.ttl_secs)
                .await
                .unwrap()
                .count,
            0
        );

        let first_two = store
            .peek(&m1, None, 2, now, LIMITS.ttl_secs)
            .await
            .unwrap();
        let bodies: Vec<_> = first_two.iter().map(|q| q.message.as_str()).collect();
        assert_eq!(bodies, ["a", "bb"]);
        let r1_msgs = store
            .peek(&m1, Some(&r1), 10, now, LIMITS.ttl_secs)
            .await
            .unwrap();
        assert_eq!(
            r1_msgs.iter().map(|q| q.id.clone()).collect::<Vec<_>>(),
            [a.clone(), c.clone()]
        );

        // Another mediation cannot remove these; bad ids are ignored.
        assert_eq!(
            store.remove(&m2, std::slice::from_ref(&a)).await.unwrap(),
            0
        );
        let removed = store
            .remove(&m1, &[a.clone(), "bogus".into(), "1-1:x".into()])
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            store
                .summary(&m1, None, now, LIMITS.ttl_secs)
                .await
                .unwrap()
                .count,
            2
        );

        assert_eq!(
            store.remove_recipient(&m1, &r1).await.unwrap(),
            RemoveRecipient::Removed
        );
        assert_eq!(store.mediation_of(&r1).await.unwrap(), None);
        assert_eq!(
            store.recipients(&m1).await.unwrap(),
            std::slice::from_ref(&r2)
        );

        // Several at once: all of them, or none when they do not all fit.
        let few = QueueLimits {
            ttl_secs: 3600,
            max_messages: 3,
            max_bytes: 100,
        };
        let m4 = format!("did:peer:m4-{tag}");
        let batch = |n: usize| vec!["x".to_owned(); n];
        assert!(
            store
                .enqueue_all(&m4, &r3, &batch(4), now, few)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(store.summary(&m4, None, now, 3600).await.unwrap().count, 0);
        let ids = store
            .enqueue_all(&m4, &r3, &batch(2), now, few)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert!(
            store
                .enqueue_all(&m4, &r3, &batch(2), now, few)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(store.summary(&m4, None, now, 3600).await.unwrap().count, 2);
        let bytes = QueueLimits {
            max_messages: 100,
            max_bytes: 3,
            ..few
        };
        assert!(
            store
                .enqueue_all(&m4, &r3, &["ab".to_owned(), "cd".to_owned()], now, bytes)
                .await
                .unwrap()
                .is_none()
        );
        store.remove(&m4, &ids).await.unwrap();

        // The byte limit: full at 5 bytes, freed by pickup and by expiry.
        let tight = QueueLimits {
            ttl_secs: 3600,
            max_messages: 100,
            max_bytes: 5,
        };
        let m3 = format!("did:peer:m3-{tag}");
        let abc = store
            .enqueue(&m3, &r3, "abc", now, tight)
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .enqueue(&m3, &r3, "def", now, tight)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .enqueue(&m3, &r3, "de", now, tight)
                .await
                .unwrap()
                .is_some()
        );
        store.remove(&m3, std::slice::from_ref(&abc)).await.unwrap();
        assert!(
            store
                .enqueue(&m3, &r3, "xyz", now, tight)
                .await
                .unwrap()
                .is_some()
        );
        // Two hours on, everything queued has expired and its bytes are free.
        assert!(
            store
                .enqueue(&m3, &r3, "12345", now + 7200, tight)
                .await
                .unwrap()
                .is_some()
        );

        // Idle mediations go with everything they own; active ones stay.
        let (idle, active) = (
            format!("did:peer:idle-{tag}"),
            format!("did:peer:active-{tag}"),
        );
        let idle_r = format!("did:peer:idle-r-{tag}");
        store.grant_mediation(&idle, 1_000).await.unwrap();
        store.grant_mediation(&active, 1_000).await.unwrap();
        store.touch_mediation(&active, 5_000).await.unwrap();
        store
            .touch_mediation(&format!("did:peer:none-{tag}"), 5_000)
            .await
            .unwrap();
        store.add_recipient(&idle, &idle_r, 5).await.unwrap();
        store
            .enqueue(&idle, &idle_r, "left behind", now, LIMITS)
            .await
            .unwrap();
        store
            .set_device(
                &idle,
                Service::Fcm,
                Some(&Device {
                    token: "t".into(),
                    platform: Some("android".into()),
                }),
            )
            .await
            .unwrap();
        let removed = store.remove_idle_mediations(2_000, 1000).await.unwrap();
        assert!(removed.contains(&idle) && !removed.contains(&active));
        assert!(!store.has_mediation(&idle).await.unwrap());
        assert!(store.has_mediation(&active).await.unwrap());
        assert_eq!(store.mediation_of(&idle_r).await.unwrap(), None);
        assert!(store.recipients(&idle).await.unwrap().is_empty());
        assert!(store.devices(&idle).await.unwrap().is_empty());
        assert_eq!(
            store.summary(&idle, None, now, 3600).await.unwrap().count,
            0
        );
        // A DID freed this way can be registered again.
        assert_eq!(
            store.add_recipient(&active, &idle_r, 5).await.unwrap(),
            AddRecipient::Added
        );

        // Relays: due in order, leased while being tried, capped.
        let relay = |n: u32| PendingRelay {
            id: format!("relay-{tag}-{n}"),
            uri: format!("https://{tag}.example/didcomm"),
            message: format!("payload {n}"),
            retries: n,
        };
        let roomy = RelayLimits {
            pending: 1000,
            per_destination: 1000,
            bytes: 1 << 30,
        };
        let far = now + 1_000_000;
        assert!(
            store
                .schedule_relay(&relay(1), far + 5, roomy)
                .await
                .unwrap()
        );
        assert!(
            store
                .schedule_relay(&relay(2), far + 30, roomy)
                .await
                .unwrap()
        );
        assert!(store.due_relays(far, 60, 10).await.unwrap().is_empty());
        let due = store.due_relays(far + 10, 60, 10).await.unwrap();
        assert!(due.contains(&relay(1)) && !due.contains(&relay(2)));
        // Leased: not handed out again until the lease runs out.
        assert!(
            !store
                .due_relays(far + 20, 60, 10)
                .await
                .unwrap()
                .contains(&relay(1))
        );
        assert!(
            store
                .due_relays(far + 71, 60, 10)
                .await
                .unwrap()
                .contains(&relay(1))
        );
        // Rescheduled, and finished.
        let mut again = relay(1);
        again.retries = 2;
        assert!(
            store
                .schedule_relay(&again, far + 200, roomy)
                .await
                .unwrap()
        );
        let later = store.due_relays(far + 300, 60, 10).await.unwrap();
        assert!(later.contains(&again) && later.contains(&relay(2)));
        store.finish_relay(&again).await.unwrap();
        store.finish_relay(&relay(2)).await.unwrap();
        // Finishing twice (two workers) counts it out once.
        store.finish_relay(&relay(2)).await.unwrap();
        assert!(
            store
                .due_relays(far + 10_000, 60, 10)
                .await
                .unwrap()
                .iter()
                .all(|r| !r.id.contains(&tag))
        );
        // Nothing more than the limits wait: in all, for one destination,
        // in bytes. Rescheduling one that waits is always fine.
        let one_each = RelayLimits {
            per_destination: 1,
            ..roomy
        };
        assert!(
            store
                .schedule_relay(&relay(3), far + 5, one_each)
                .await
                .unwrap()
        );
        assert!(
            !store
                .schedule_relay(&relay(4), far + 5, one_each)
                .await
                .unwrap()
        );
        assert!(
            store
                .schedule_relay(&relay(3), far + 9, one_each)
                .await
                .unwrap()
        );
        let elsewhere = PendingRelay {
            id: format!("relay-{tag}-elsewhere"),
            uri: format!("https://other-{tag}.example/didcomm"),
            ..relay(4)
        };
        assert!(
            store
                .schedule_relay(&elsewhere, far + 5, one_each)
                .await
                .unwrap()
        );
        let tight = RelayLimits {
            bytes: relay(3).bytes() + elsewhere.bytes(),
            ..roomy
        };
        assert!(
            !store
                .schedule_relay(&relay(4), far + 5, tight)
                .await
                .unwrap()
        );
        store.finish_relay(&elsewhere).await.unwrap();
        assert!(
            store
                .schedule_relay(&relay(4), far + 5, tight)
                .await
                .unwrap()
        );
        assert!(
            !store
                .schedule_relay(
                    &relay(5),
                    far + 5,
                    RelayLimits {
                        pending: 1,
                        ..roomy
                    }
                )
                .await
                .unwrap()
        );
        store.finish_relay(&relay(3)).await.unwrap();
        store.finish_relay(&relay(4)).await.unwrap();

        let key = format!("rate-{tag}");
        assert_eq!(store.hit(&key, 60, now).await.unwrap(), 1);
        assert_eq!(store.hit(&key, 60, now).await.unwrap(), 2);
        assert_eq!(store.hit(&key, 60, now + 60).await.unwrap(), 1);

        // Devices: one per service, replaced, removed only with the same token.
        let phone = Device {
            token: "t1".into(),
            platform: Some("android".into()),
        };
        let newer = Device {
            token: "t2".into(),
            platform: Some("android".into()),
        };
        let iphone = Device {
            token: "abcd".into(),
            platform: None,
        };
        let voip = Device {
            token: "ef01".into(),
            platform: None,
        };
        assert!(store.devices(&m1).await.unwrap().is_empty());
        store
            .set_device(&m1, Service::Apns, Some(&iphone))
            .await
            .unwrap();
        store
            .set_device(&m1, Service::Fcm, Some(&phone))
            .await
            .unwrap();
        store
            .set_device(&m1, Service::Fcm, Some(&newer))
            .await
            .unwrap();
        store
            .set_device(&m1, Service::ApnsVoip, Some(&voip))
            .await
            .unwrap();
        assert_eq!(
            store.devices(&m1).await.unwrap(),
            [
                (Service::Fcm, newer.clone()),
                (Service::Apns, iphone.clone()),
                (Service::ApnsVoip, voip.clone())
            ]
        );
        store
            .set_device(&m1, Service::ApnsVoip, None)
            .await
            .unwrap();
        assert_eq!(store.devices(&m1).await.unwrap().len(), 2);
        store.remove_device(&m1, Service::Fcm, "t1").await.unwrap();
        assert_eq!(store.devices(&m1).await.unwrap().len(), 2);
        store.remove_device(&m1, Service::Fcm, "t2").await.unwrap();
        store.set_device(&m1, Service::Apns, None).await.unwrap();
        assert!(store.devices(&m1).await.unwrap().is_empty());
        assert!(store.devices(&m2).await.unwrap().is_empty());

        // One push until the wallet picks up, then not before the interval.
        assert!(store.claim_push(&m1, now, 3600).await.unwrap());
        assert!(!store.claim_push(&m1, now + 100, 3600).await.unwrap());
        assert!(store.claim_push(&m2, now, 3600).await.unwrap());
        store.release_push(&m1, now + 10, 60).await.unwrap();
        assert!(!store.claim_push(&m1, now + 10, 3600).await.unwrap());
        store.release_push(&m2, now + 60, 60).await.unwrap();
        assert!(store.claim_push(&m2, now + 60, 3600).await.unwrap());
        // Releasing with nothing claimed is harmless.
        store.release_push(&r3, now, 60).await.unwrap();
        assert!(store.claim_push(&r3, now, 3600).await.unwrap());

        // Rings: one per interval, whatever the wake-up turn says.
        assert!(store.claim_ring(&m1, now, 60).await.unwrap());
        assert!(!store.claim_ring(&m1, now + 59, 60).await.unwrap());
        assert!(store.claim_ring(&m2, now, 60).await.unwrap());
        assert!(store.claim_ring(&r3, now, 0).await.unwrap());
        assert!(store.claim_ring(&r3, now, 0).await.unwrap());
    }

    fn uuid() -> String {
        almena_didcomm::Message::new("t", serde_json::json!({})).id
    }
}

#[cfg(test)]
pub(crate) fn now_for_tests() -> u64 {
    almena_didcomm::message::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_ids() {
        assert!(is_queue_id("1695460000000-0"));
        assert!(!is_queue_id("1695460000000"));
        assert!(!is_queue_id("a-1"));
        assert!(!is_queue_id("1-1:x"));
        assert_eq!(id_millis("1695460000000-3"), 1_695_460_000_000);
    }
}
