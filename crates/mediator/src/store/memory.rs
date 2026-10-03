//! In-process [`Store`]: everything is lost on restart. For tests and local
//! development only.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

use anyhow::{Result, anyhow};
use async_trait::async_trait;

use super::{
    AddRecipient, PendingRelay, QueueLimits, QueueSummary, Queued, RelayLimits, RemoveRecipient,
    Store, id_millis,
};
use crate::push::{Device, Service};

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    mediations: HashSet<String>,
    /// Recipient DID → mediation.
    owners: HashMap<String, String>,
    recipients: HashMap<String, BTreeSet<String>>,
    queues: HashMap<String, Vec<Queued>>,
    /// Key → (window, hits).
    hits: HashMap<String, (u64, u64)>,
    seq: u64,
    devices: HashMap<String, BTreeMap<Service, Device>>,
    /// Mediation → (when the last push went, when the marker lapses).
    push_sent: HashMap<String, (u64, u64)>,
    /// Mediation → when the next call ring may go.
    rings: HashMap<String, u64>,
    /// Relay id → (when it is due, the relay).
    relays: BTreeMap<String, (u64, PendingRelay)>,
    /// Mediation → when its wallet was last active.
    seen: HashMap<String, u64>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| anyhow!("memory store poisoned"))
    }
}

impl Inner {
    /// The mediation's queue with expired messages dropped.
    fn queue(&mut self, mediation: &str, now: u64, ttl_secs: u64) -> &mut Vec<Queued> {
        let queue = self.queues.entry(mediation.to_owned()).or_default();
        let cutoff = now.saturating_sub(ttl_secs);
        queue.retain(|q| q.received >= cutoff);
        queue
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn ping(&self) -> Result<()> {
        self.lock().map(|_| ())
    }

    fn kind(&self) -> &'static str {
        "memory"
    }

    async fn grant_mediation(&self, mediation: &str, now: u64) -> Result<()> {
        let mut inner = self.lock()?;
        inner.mediations.insert(mediation.to_owned());
        inner.seen.insert(mediation.to_owned(), now);
        Ok(())
    }

    async fn touch_mediation(&self, mediation: &str, now: u64) -> Result<()> {
        let mut inner = self.lock()?;
        if inner.mediations.contains(mediation) {
            inner.seen.insert(mediation.to_owned(), now);
        }
        Ok(())
    }

    async fn remove_idle_mediations(&self, cutoff: u64, limit: usize) -> Result<Vec<String>> {
        let mut inner = self.lock()?;
        let idle: Vec<String> = inner
            .seen
            .iter()
            .filter(|(_, seen)| **seen <= cutoff)
            .map(|(m, _)| m.clone())
            .take(limit)
            .collect();
        for mediation in &idle {
            inner.seen.remove(mediation);
            inner.mediations.remove(mediation);
            for recipient in inner.recipients.remove(mediation).unwrap_or_default() {
                inner.owners.remove(&recipient);
            }
            inner.queues.remove(mediation);
            inner.devices.remove(mediation);
            inner.push_sent.remove(mediation);
            inner.rings.remove(mediation);
        }
        Ok(idle)
    }

    async fn has_mediation(&self, mediation: &str) -> Result<bool> {
        Ok(self.lock()?.mediations.contains(mediation))
    }

    async fn add_recipient(
        &self,
        mediation: &str,
        recipient: &str,
        max: usize,
    ) -> Result<AddRecipient> {
        let mut inner = self.lock()?;
        match inner.owners.get(recipient) {
            Some(owner) if owner == mediation => return Ok(AddRecipient::AlreadyYours),
            Some(_) => return Ok(AddRecipient::TakenByOther),
            None => {}
        }
        let set = inner.recipients.entry(mediation.to_owned()).or_default();
        if set.len() >= max {
            return Ok(AddRecipient::LimitReached);
        }
        set.insert(recipient.to_owned());
        inner
            .owners
            .insert(recipient.to_owned(), mediation.to_owned());
        Ok(AddRecipient::Added)
    }

    async fn remove_recipient(&self, mediation: &str, recipient: &str) -> Result<RemoveRecipient> {
        let mut inner = self.lock()?;
        match inner.owners.get(recipient) {
            None => Ok(RemoveRecipient::NotRegistered),
            Some(owner) if owner != mediation => Ok(RemoveRecipient::NotYours),
            Some(_) => {
                inner.owners.remove(recipient);
                if let Some(set) = inner.recipients.get_mut(mediation) {
                    set.remove(recipient);
                }
                Ok(RemoveRecipient::Removed)
            }
        }
    }

    async fn recipients(&self, mediation: &str) -> Result<Vec<String>> {
        Ok(self
            .lock()?
            .recipients
            .get(mediation)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn mediation_of(&self, recipient: &str) -> Result<Option<String>> {
        Ok(self.lock()?.owners.get(recipient).cloned())
    }

    async fn enqueue_all(
        &self,
        mediation: &str,
        recipient: &str,
        messages: &[String],
        now: u64,
        limits: QueueLimits,
    ) -> Result<Option<Vec<String>>> {
        let mut inner = self.lock()?;
        let seq = inner.seq;
        inner.seq += messages.len() as u64;
        let queue = inner.queue(mediation, now, limits.ttl_secs);
        let bytes: u64 = queue.iter().map(|q| q.message.len() as u64).sum();
        let adding: u64 = messages.iter().map(|m| m.len() as u64).sum();
        if queue.len() + messages.len() > limits.max_messages || bytes + adding > limits.max_bytes {
            return Ok(None);
        }
        let mut ids = Vec::with_capacity(messages.len());
        for (n, message) in messages.iter().enumerate() {
            let id = format!("{}-{}", now * 1000, seq + n as u64 + 1);
            queue.push(Queued {
                id: id.clone(),
                recipient: recipient.to_owned(),
                received: id_millis(&id) / 1000,
                message: message.clone(),
            });
            ids.push(id);
        }
        Ok(Some(ids))
    }

    async fn summary(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<QueueSummary> {
        let mut inner = self.lock()?;
        let mut summary = QueueSummary::default();
        for q in inner
            .queue(mediation, now, ttl_secs)
            .iter()
            .filter(|q| recipient.is_none_or(|r| q.recipient == r))
        {
            summary.count += 1;
            summary.total_bytes += q.message.len() as u64;
            summary.oldest = Some(summary.oldest.map_or(q.received, |o| o.min(q.received)));
            summary.newest = Some(summary.newest.map_or(q.received, |n| n.max(q.received)));
        }
        Ok(summary)
    }

    async fn peek(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        limit: usize,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Vec<Queued>> {
        let mut inner = self.lock()?;
        Ok(inner
            .queue(mediation, now, ttl_secs)
            .iter()
            .filter(|q| recipient.is_none_or(|r| q.recipient == r))
            .take(limit)
            .cloned()
            .collect())
    }

    async fn remove(&self, mediation: &str, ids: &[String]) -> Result<usize> {
        let mut inner = self.lock()?;
        let Some(queue) = inner.queues.get_mut(mediation) else {
            return Ok(0);
        };
        let before = queue.len();
        queue.retain(|q| !ids.contains(&q.id));
        Ok(before - queue.len())
    }

    async fn hit(&self, key: &str, window_secs: u64, now: u64) -> Result<u64> {
        let window = now / window_secs.max(1);
        let mut inner = self.lock()?;
        if inner.hits.len() > 100_000 {
            inner.hits.retain(|_, (w, _)| *w == window);
        }
        let entry = inner.hits.entry(key.to_owned()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        Ok(entry.1)
    }

    async fn schedule_relay(
        &self,
        relay: &PendingRelay,
        due: u64,
        limits: RelayLimits,
    ) -> Result<bool> {
        let mut inner = self.lock()?;
        if !inner.relays.contains_key(&relay.id) {
            let destination = relay.destination();
            let waiting = inner.relays.values().map(|(_, r)| r);
            let (mut to_it, mut bytes) = (0, 0);
            for other in waiting {
                to_it += usize::from(other.destination() == destination);
                bytes += other.bytes();
            }
            if inner.relays.len() >= limits.pending
                || to_it >= limits.per_destination
                || bytes + relay.bytes() > limits.bytes
            {
                return Ok(false);
            }
        }
        inner.relays.insert(relay.id.clone(), (due, relay.clone()));
        Ok(true)
    }

    async fn due_relays(
        &self,
        now: u64,
        lease_secs: u64,
        limit: usize,
    ) -> Result<Vec<PendingRelay>> {
        let mut inner = self.lock()?;
        let mut due: Vec<_> = inner
            .relays
            .values_mut()
            .filter(|(at, _)| *at <= now)
            .collect();
        due.sort_by_key(|(at, _)| *at);
        Ok(due
            .into_iter()
            .take(limit)
            .map(|(at, relay)| {
                *at = now + lease_secs;
                relay.clone()
            })
            .collect())
    }

    async fn finish_relay(&self, relay: &PendingRelay) -> Result<()> {
        self.lock()?.relays.remove(&relay.id);
        Ok(())
    }

    async fn set_device(
        &self,
        mediation: &str,
        service: Service,
        device: Option<&Device>,
    ) -> Result<()> {
        let mut inner = self.lock()?;
        let devices = inner.devices.entry(mediation.to_owned()).or_default();
        match device {
            Some(device) => devices.insert(service, device.clone()),
            None => devices.remove(&service),
        };
        Ok(())
    }

    async fn devices(&self, mediation: &str) -> Result<Vec<(Service, Device)>> {
        Ok(self
            .lock()?
            .devices
            .get(mediation)
            .map(|devices| devices.iter().map(|(s, d)| (*s, d.clone())).collect())
            .unwrap_or_default())
    }

    async fn remove_device(&self, mediation: &str, service: Service, token: &str) -> Result<()> {
        if let Some(devices) = self.lock()?.devices.get_mut(mediation)
            && devices.get(&service).is_some_and(|d| d.token == token)
        {
            devices.remove(&service);
        }
        Ok(())
    }

    async fn claim_push(&self, mediation: &str, now: u64, hold_secs: u64) -> Result<bool> {
        let mut inner = self.lock()?;
        if inner
            .push_sent
            .get(mediation)
            .is_some_and(|&(_, until)| now < until)
        {
            return Ok(false);
        }
        inner
            .push_sent
            .insert(mediation.to_owned(), (now, now.saturating_add(hold_secs)));
        Ok(true)
    }

    async fn release_push(&self, mediation: &str, now: u64, min_interval_secs: u64) -> Result<()> {
        let mut inner = self.lock()?;
        if let Some((sent, until)) = inner.push_sent.get_mut(mediation) {
            *until = (*until).min(sent.saturating_add(min_interval_secs));
            if *until <= now {
                inner.push_sent.remove(mediation);
            }
        }
        Ok(())
    }

    async fn claim_ring(&self, mediation: &str, now: u64, interval_secs: u64) -> Result<bool> {
        let mut inner = self.lock()?;
        if inner.rings.get(mediation).is_some_and(|&until| now < until) {
            return Ok(false);
        }
        inner
            .rings
            .insert(mediation.to_owned(), now.saturating_add(interval_secs));
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn contract() {
        super::super::contract::run(&MemoryStore::new()).await;
    }

    #[tokio::test]
    async fn expired_messages_disappear() {
        let store = MemoryStore::new();
        let limits = QueueLimits {
            ttl_secs: 60,
            max_messages: 10,
            max_bytes: 1024,
        };
        store.enqueue("m", "r", "old", 1_000, limits).await.unwrap();
        store.enqueue("m", "r", "new", 1_050, limits).await.unwrap();
        let left = store.peek("m", None, 10, 1_070, 60).await.unwrap();
        assert_eq!(
            left.iter().map(|q| q.message.as_str()).collect::<Vec<_>>(),
            ["new"]
        );
    }
}
