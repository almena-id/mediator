//! Redis [`Store`].
//!
//! Keys (`M` = mediation DID, `R` = recipient DID):
//!
//! | Key | Type | Holds |
//! |---|---|---|
//! | `mediation:{M}` | string | Grant time (epoch seconds) |
//! | `mediations:seen` | sorted set | Mediations by when their wallet was last active |
//! | `mediation:{M}:recipients` | set | Recipient DIDs registered by `M` |
//! | `recipient:{R}` | string | The mediation that registered `R` |
//! | `mediation:{M}:queue` | stream | One entry per queued message: `r` recipient, `s` size in bytes |
//! | `mediation:{M}:msg:{id}` | string | Body of queue entry `id`, expiring with the queue TTL |
//! | `mediation:{M}:bytes` | string | Total size of the queued messages, for `max_bytes` |
//! | `rate:{key}:{window}` | string | Hit counter of one rate-limit window |
//! | `push:{M}` | hash | Push service (`fcm`, `apns`, `apns-voip`) → device, as JSON |
//! | `push-sent:{M}` | string | Time of the last push, until the wallet picks up |
//! | `ring:{M}` | string | Time of the last call ring, for the ring interval |
//! | `relay:due` | sorted set | Relay ids by when they are next tried |
//! | `relay:items` | hash | Relay id → the pending relay, as JSON |
//! | `relay:hosts` | hash | Destination host → relays waiting for it |
//! | `relay:bytes` | string | Total size of the relays waiting |
//!
//! Bodies live outside the stream so that status queries read only the small
//! entries. Multi-key updates run as Lua scripts, so they are atomic; every
//! script that adds, expires or removes queue entries keeps the byte counter
//! in step.

use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use redis::streams::StreamRangeReply;

use super::{
    AddRecipient, PendingRelay, QueueLimits, QueueSummary, Queued, RelayLimits, RemoveRecipient,
    Store, id_millis, is_queue_id,
};
use crate::push::{Device, Service};

const ADD_RECIPIENT: &str = r"
local owner = redis.call('GET', KEYS[1])
if owner == ARGV[1] then return 'mine' end
if owner then return 'taken' end
if redis.call('SCARD', KEYS[2]) >= tonumber(ARGV[3]) then return 'limit' end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('SADD', KEYS[2], ARGV[2])
return 'added'
";

const REMOVE_RECIPIENT: &str = r"
local owner = redis.call('GET', KEYS[1])
if not owner then return 'none' end
if owner ~= ARGV[1] then return 'theirs' end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
return 'removed'
";

/// Lua helpers shared by the queue scripts: the size of a stream entry, and
/// trimming expired entries while taking their bytes off the counter.
const QUEUE_LUA: &str = r"
local function entry_size(entry)
  local fields = entry[2]
  for i = 1, #fields, 2 do
    if fields[i] == 's' then return tonumber(fields[i + 1]) end
  end
  return 0
end
local function uncount(bytes, freed)
  if freed > 0 and redis.call('DECRBY', bytes, freed) < 0 then
    redis.call('SET', bytes, 0, 'KEEPTTL')
  end
end
local function trim(queue, bytes, minid)
  local freed = 0
  for _, entry in ipairs(redis.call('XRANGE', queue, '-', '(' .. minid)) do
    freed = freed + entry_size(entry)
  end
  redis.call('XTRIM', queue, 'MINID', minid)
  uncount(bytes, freed)
end
";

/// KEYS[1] queue, KEYS[2] byte counter; ARGV: min id, max messages, max
/// bytes, recipient, ttl, body key prefix, then the bodies. All or none.
static ENQUEUE: LazyLock<String> = LazyLock::new(|| {
    format!(
        r"{QUEUE_LUA}
trim(KEYS[1], KEYS[2], ARGV[1])
local first = 7
if redis.call('XLEN', KEYS[1]) + #ARGV - first + 1 > tonumber(ARGV[2]) then return false end
local adding = 0
for i = first, #ARGV do adding = adding + #ARGV[i] end
local used = tonumber(redis.call('GET', KEYS[2]) or '0')
if used + adding > tonumber(ARGV[3]) then return false end
local ids = {{}}
for i = first, #ARGV do
  local id = redis.call('XADD', KEYS[1], '*', 'r', ARGV[4], 's', #ARGV[i])
  redis.call('SET', ARGV[6] .. id, ARGV[i], 'EX', ARGV[5])
  table.insert(ids, id)
end
redis.call('INCRBY', KEYS[2], adding)
redis.call('EXPIRE', KEYS[1], ARGV[5])
redis.call('EXPIRE', KEYS[2], ARGV[5])
return ids
"
    )
});

/// KEYS[1] queue, KEYS[2] byte counter; ARGV: min id.
static TRIM: LazyLock<String> =
    LazyLock::new(|| format!("{QUEUE_LUA}\ntrim(KEYS[1], KEYS[2], ARGV[1])\nreturn 0"));

/// KEYS[1] queue, KEYS[2] byte counter; ARGV: body key prefix, then the ids.
static REMOVE: LazyLock<String> = LazyLock::new(|| {
    format!(
        r"{QUEUE_LUA}
local removed, freed = 0, 0
for i = 2, #ARGV do
  local entry = redis.call('XRANGE', KEYS[1], ARGV[i], ARGV[i])[1]
  if entry then
    freed = freed + entry_size(entry)
    removed = removed + redis.call('XDEL', KEYS[1], ARGV[i])
  end
  redis.call('DEL', ARGV[1] .. ARGV[i])
end
uncount(KEYS[2], freed)
return removed
"
    )
});

/// KEYS[1] devices; ARGV: service, token.
const REMOVE_DEVICE: &str = r"
local device = redis.call('HGET', KEYS[1], ARGV[1])
if device and cjson.decode(device).token == ARGV[2] then
  redis.call('HDEL', KEYS[1], ARGV[1])
end
return 0
";

/// KEYS[1] push marker; ARGV: now, min interval.
const RELEASE_PUSH: &str = r"
local sent = redis.call('GET', KEYS[1])
if not sent then return 0 end
local left = tonumber(sent) + tonumber(ARGV[2]) - tonumber(ARGV[1])
if left <= 0 then
  redis.call('DEL', KEYS[1])
else
  local ttl = redis.call('TTL', KEYS[1])
  if ttl < 0 or left < ttl then redis.call('EXPIRE', KEYS[1], left) end
end
return 0
";

const SEEN: &str = "mediations:seen";

/// KEYS[1] mediation, KEYS[2] seen set; ARGV: mediation, now.
const TOUCH: &str = r"
if redis.call('EXISTS', KEYS[1]) == 1 then
  redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1])
end
return 0
";

/// KEYS: mediation, recipients, queue, byte counter, devices, push marker,
/// seen set; ARGV: mediation, cutoff, recipient key prefix, body key prefix.
/// Checks again that the mediation is idle, then deletes all it owns.
const REMOVE_MEDIATION: &str = r"
local seen = redis.call('ZSCORE', KEYS[7], ARGV[1])
if seen and tonumber(seen) > tonumber(ARGV[2]) then return 0 end
for _, recipient in ipairs(redis.call('SMEMBERS', KEYS[2])) do
  if redis.call('GET', ARGV[3] .. recipient) == ARGV[1] then
    redis.call('DEL', ARGV[3] .. recipient)
  end
end
for _, entry in ipairs(redis.call('XRANGE', KEYS[3], '-', '+')) do
  redis.call('DEL', ARGV[4] .. entry[1])
end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5], KEYS[6])
redis.call('ZREM', KEYS[7], ARGV[1])
return 1
";

const RELAY_DUE: &str = "relay:due";
const RELAY_ITEMS: &str = "relay:items";
const RELAY_HOSTS: &str = "relay:hosts";
const RELAY_BYTES: &str = "relay:bytes";

/// KEYS[1] due set, KEYS[2] items, KEYS[3] hosts, KEYS[4] bytes; ARGV: id,
/// due, relay JSON, destination, size, max pending, max per destination,
/// max bytes. A new relay is counted in for its destination and its size.
const SCHEDULE_RELAY: &str = r"
if redis.call('HEXISTS', KEYS[2], ARGV[1]) == 0 then
  local to_it = tonumber(redis.call('HGET', KEYS[3], ARGV[4]) or '0')
  local bytes = tonumber(redis.call('GET', KEYS[4]) or '0')
  if redis.call('HLEN', KEYS[2]) >= tonumber(ARGV[6])
     or to_it >= tonumber(ARGV[7])
     or bytes + tonumber(ARGV[5]) > tonumber(ARGV[8]) then
    return 0
  end
  redis.call('HINCRBY', KEYS[3], ARGV[4], 1)
  redis.call('INCRBY', KEYS[4], ARGV[5])
end
redis.call('HSET', KEYS[2], ARGV[1], ARGV[3])
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
return 1
";

/// KEYS as for SCHEDULE_RELAY; ARGV: id, destination, size. Counts the relay
/// out only if it was still there, so finishing it twice is harmless.
const FINISH_RELAY: &str = r"
redis.call('ZREM', KEYS[1], ARGV[1])
if redis.call('HDEL', KEYS[2], ARGV[1]) == 1 then
  if redis.call('HINCRBY', KEYS[3], ARGV[2], -1) <= 0 then
    redis.call('HDEL', KEYS[3], ARGV[2])
  end
  if redis.call('DECRBY', KEYS[4], ARGV[3]) <= 0 then
    redis.call('DEL', KEYS[4])
  end
end
return 1
";

/// KEYS[1] due set, KEYS[2] items; ARGV: now, lease end, limit. Leases the
/// due relays by moving them to the lease end, and returns them.
const DUE_RELAYS: &str = r"
local ids = redis.call('ZRANGE', KEYS[1], '-inf', ARGV[1], 'BYSCORE', 'LIMIT', 0, ARGV[3])
local relays = {}
for _, id in ipairs(ids) do
  local relay = redis.call('HGET', KEYS[2], id)
  if relay then
    redis.call('ZADD', KEYS[1], ARGV[2], id)
    table.insert(relays, relay)
  else
    redis.call('ZREM', KEYS[1], id)
  end
end
return relays
";

pub struct RedisStore {
    conn: ConnectionManager,
}

impl RedisStore {
    /// Connects to `url`. Fails if Redis cannot be reached at start-up.
    /// Connects to `url`, with `password` if given (it replaces any in the
    /// URL). Fails if Redis cannot be reached at start-up. Errors show the URL
    /// without its password.
    pub async fn connect(url: &str, password: Option<&str>) -> Result<Self> {
        let mut parsed = url::Url::parse(url).context("invalid Redis URL")?;
        let _ = parsed.set_password(None);
        let shown = parsed.to_string();
        let url = match password {
            Some(password) => {
                parsed
                    .set_password(Some(password))
                    .map_err(|()| anyhow::anyhow!("Redis URL {shown} cannot carry a password"))?;
                parsed.to_string()
            }
            None => url.to_owned(),
        };
        let client =
            redis::Client::open(url).with_context(|| format!("invalid Redis URL {shown}"))?;
        let conn = ConnectionManager::new(client)
            .await
            .with_context(|| format!("connecting to Redis at {shown}"))?;
        Ok(Self { conn })
    }

    fn conn(&self) -> ConnectionManager {
        self.conn.clone()
    }

    /// Drops expired entries, then returns the queue's entries (without bodies).
    async fn entries(
        &self,
        mediation: &str,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Vec<(String, String, u64)>> {
        let key = queue_key(mediation);
        let mut conn = self.conn();
        let _: i64 = redis::Script::new(&TRIM)
            .key(&key)
            .key(bytes_key(mediation))
            .arg(min_id(now, ttl_secs))
            .invoke_async(&mut conn)
            .await?;
        let reply: StreamRangeReply = conn.xrange_all(&key).await?;
        Ok(reply
            .ids
            .into_iter()
            .map(|entry| {
                let recipient = entry.get::<String>("r").unwrap_or_default();
                let size = entry.get::<u64>("s").unwrap_or_default();
                (entry.id, recipient, size)
            })
            .collect())
    }
}

fn mediation_key(mediation: &str) -> String {
    format!("mediation:{mediation}")
}

fn recipients_key(mediation: &str) -> String {
    format!("mediation:{mediation}:recipients")
}

fn recipient_key(recipient: &str) -> String {
    format!("recipient:{recipient}")
}

fn queue_key(mediation: &str) -> String {
    format!("mediation:{mediation}:queue")
}

fn bytes_key(mediation: &str) -> String {
    format!("mediation:{mediation}:bytes")
}

fn body_prefix(mediation: &str) -> String {
    format!("mediation:{mediation}:msg:")
}

fn devices_key(mediation: &str) -> String {
    format!("push:{mediation}")
}

fn push_sent_key(mediation: &str) -> String {
    format!("push-sent:{mediation}")
}

fn ring_key(mediation: &str) -> String {
    format!("ring:{mediation}")
}

/// Stream id below which entries are older than the TTL.
fn min_id(now: u64, ttl_secs: u64) -> String {
    format!("{}-0", now.saturating_sub(ttl_secs) * 1000)
}

#[async_trait]
impl Store for RedisStore {
    async fn ping(&self) -> Result<()> {
        let _: String = redis::cmd("PING").query_async(&mut self.conn()).await?;
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "redis"
    }

    async fn grant_mediation(&self, mediation: &str, now: u64) -> Result<()> {
        let _: () = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(mediation_key(mediation))
            .arg(now)
            .arg("NX")
            .ignore()
            .zadd(SEEN, mediation, now)
            .ignore()
            .query_async(&mut self.conn())
            .await?;
        Ok(())
    }

    async fn touch_mediation(&self, mediation: &str, now: u64) -> Result<()> {
        let _: i64 = redis::Script::new(TOUCH)
            .key(mediation_key(mediation))
            .key(SEEN)
            .arg(mediation)
            .arg(now)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(())
    }

    async fn remove_idle_mediations(&self, cutoff: u64, limit: usize) -> Result<Vec<String>> {
        let idle: Vec<String> = redis::cmd("ZRANGE")
            .arg(SEEN)
            .arg("-inf")
            .arg(cutoff)
            .arg("BYSCORE")
            .arg("LIMIT")
            .arg(0)
            .arg(limit)
            .query_async(&mut self.conn())
            .await?;
        let mut removed = Vec::with_capacity(idle.len());
        for mediation in idle {
            let gone: i64 = redis::Script::new(REMOVE_MEDIATION)
                .key(mediation_key(&mediation))
                .key(recipients_key(&mediation))
                .key(queue_key(&mediation))
                .key(bytes_key(&mediation))
                .key(devices_key(&mediation))
                .key(push_sent_key(&mediation))
                .key(SEEN)
                .arg(&mediation)
                .arg(cutoff)
                .arg(recipient_key(""))
                .arg(body_prefix(&mediation))
                .invoke_async(&mut self.conn())
                .await?;
            if gone == 1 {
                removed.push(mediation);
            }
        }
        Ok(removed)
    }

    async fn has_mediation(&self, mediation: &str) -> Result<bool> {
        Ok(self.conn().exists(mediation_key(mediation)).await?)
    }

    async fn add_recipient(
        &self,
        mediation: &str,
        recipient: &str,
        max: usize,
    ) -> Result<AddRecipient> {
        let result: String = redis::Script::new(ADD_RECIPIENT)
            .key(recipient_key(recipient))
            .key(recipients_key(mediation))
            .arg(mediation)
            .arg(recipient)
            .arg(max)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(match result.as_str() {
            "added" => AddRecipient::Added,
            "mine" => AddRecipient::AlreadyYours,
            "taken" => AddRecipient::TakenByOther,
            "limit" => AddRecipient::LimitReached,
            other => bail!("unexpected add-recipient result {other}"),
        })
    }

    async fn remove_recipient(&self, mediation: &str, recipient: &str) -> Result<RemoveRecipient> {
        let result: String = redis::Script::new(REMOVE_RECIPIENT)
            .key(recipient_key(recipient))
            .key(recipients_key(mediation))
            .arg(mediation)
            .arg(recipient)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(match result.as_str() {
            "removed" => RemoveRecipient::Removed,
            "none" => RemoveRecipient::NotRegistered,
            "theirs" => RemoveRecipient::NotYours,
            other => bail!("unexpected remove-recipient result {other}"),
        })
    }

    async fn recipients(&self, mediation: &str) -> Result<Vec<String>> {
        let set: std::collections::HashSet<String> =
            self.conn().smembers(recipients_key(mediation)).await?;
        let mut list: Vec<String> = set.into_iter().collect();
        list.sort();
        Ok(list)
    }

    async fn mediation_of(&self, recipient: &str) -> Result<Option<String>> {
        Ok(self.conn().get(recipient_key(recipient)).await?)
    }

    async fn enqueue_all(
        &self,
        mediation: &str,
        recipient: &str,
        messages: &[String],
        now: u64,
        limits: QueueLimits,
    ) -> Result<Option<Vec<String>>> {
        if messages.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let script = redis::Script::new(&ENQUEUE);
        let mut call = script.prepare_invoke();
        call.key(queue_key(mediation))
            .key(bytes_key(mediation))
            .arg(min_id(now, limits.ttl_secs))
            .arg(limits.max_messages)
            .arg(limits.max_bytes)
            .arg(recipient)
            .arg(limits.ttl_secs.max(1))
            .arg(body_prefix(mediation));
        for message in messages {
            call.arg(message);
        }
        Ok(call.invoke_async(&mut self.conn()).await?)
    }

    async fn summary(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<QueueSummary> {
        let mut summary = QueueSummary::default();
        for (id, r, size) in self.entries(mediation, now, ttl_secs).await? {
            if recipient.is_some_and(|want| want != r) {
                continue;
            }
            let received = id_millis(&id) / 1000;
            summary.count += 1;
            summary.total_bytes += size;
            summary.oldest = Some(summary.oldest.map_or(received, |o| o.min(received)));
            summary.newest = Some(summary.newest.map_or(received, |n| n.max(received)));
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
        let entries: Vec<_> = self
            .entries(mediation, now, ttl_secs)
            .await?
            .into_iter()
            .filter(|(_, r, _)| recipient.is_none_or(|want| want == r))
            .take(limit)
            .collect();
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let prefix = body_prefix(mediation);
        let keys: Vec<String> = entries
            .iter()
            .map(|(id, _, _)| format!("{prefix}{id}"))
            .collect();
        let bodies: Vec<Option<String>> = self.conn().mget(&keys).await?;

        let mut queued = Vec::with_capacity(entries.len());
        let mut orphans = Vec::new();
        for ((id, recipient, _), body) in entries.into_iter().zip(bodies) {
            match body {
                Some(message) => queued.push(Queued {
                    received: id_millis(&id) / 1000,
                    id,
                    recipient,
                    message,
                }),
                // The body expired before its entry was trimmed.
                None => orphans.push(id),
            }
        }
        if !orphans.is_empty() {
            self.remove(mediation, &orphans).await?;
        }
        Ok(queued)
    }

    async fn remove(&self, mediation: &str, ids: &[String]) -> Result<usize> {
        let ids: Vec<&String> = ids.iter().filter(|id| is_queue_id(id)).collect();
        if ids.is_empty() {
            return Ok(0);
        }
        Ok(redis::Script::new(&REMOVE)
            .key(queue_key(mediation))
            .key(bytes_key(mediation))
            .arg(body_prefix(mediation))
            .arg(ids)
            .invoke_async(&mut self.conn())
            .await?)
    }

    async fn hit(&self, key: &str, window_secs: u64, now: u64) -> Result<u64> {
        let window_secs = window_secs.max(1);
        let key = format!("rate:{key}:{}", now / window_secs);
        let (hits,): (u64,) = redis::pipe()
            .atomic()
            .incr(&key, 1)
            .expire(&key, i64::try_from(window_secs).unwrap_or(i64::MAX))
            .ignore()
            .query_async(&mut self.conn())
            .await?;
        Ok(hits)
    }

    async fn schedule_relay(
        &self,
        relay: &PendingRelay,
        due: u64,
        limits: RelayLimits,
    ) -> Result<bool> {
        let stored: i64 = redis::Script::new(SCHEDULE_RELAY)
            .key(RELAY_DUE)
            .key(RELAY_ITEMS)
            .key(RELAY_HOSTS)
            .key(RELAY_BYTES)
            .arg(&relay.id)
            .arg(due)
            .arg(serde_json::to_string(relay)?)
            .arg(relay.destination())
            .arg(relay.bytes())
            .arg(limits.pending)
            .arg(limits.per_destination)
            .arg(limits.bytes)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(stored == 1)
    }

    async fn due_relays(
        &self,
        now: u64,
        lease_secs: u64,
        limit: usize,
    ) -> Result<Vec<PendingRelay>> {
        let relays: Vec<String> = redis::Script::new(DUE_RELAYS)
            .key(RELAY_DUE)
            .key(RELAY_ITEMS)
            .arg(now)
            .arg(now + lease_secs)
            .arg(limit)
            .invoke_async(&mut self.conn())
            .await?;
        relays
            .iter()
            .map(|relay| Ok(serde_json::from_str(relay)?))
            .collect()
    }

    async fn finish_relay(&self, relay: &PendingRelay) -> Result<()> {
        let _: i64 = redis::Script::new(FINISH_RELAY)
            .key(RELAY_DUE)
            .key(RELAY_ITEMS)
            .key(RELAY_HOSTS)
            .key(RELAY_BYTES)
            .arg(&relay.id)
            .arg(relay.destination())
            .arg(relay.bytes())
            .invoke_async(&mut self.conn())
            .await?;
        Ok(())
    }

    async fn set_device(
        &self,
        mediation: &str,
        service: Service,
        device: Option<&Device>,
    ) -> Result<()> {
        let key = devices_key(mediation);
        let mut conn = self.conn();
        match device {
            Some(device) => {
                let _: () = conn
                    .hset(key, service.as_str(), serde_json::to_string(device)?)
                    .await?;
            }
            None => {
                let _: () = conn.hdel(key, service.as_str()).await?;
            }
        }
        Ok(())
    }

    async fn devices(&self, mediation: &str) -> Result<Vec<(Service, Device)>> {
        let all: std::collections::HashMap<String, String> =
            self.conn().hgetall(devices_key(mediation)).await?;
        let mut devices = Vec::with_capacity(all.len());
        for (service, device) in all {
            let Some(service) = Service::parse(&service) else {
                continue;
            };
            devices.push((service, serde_json::from_str(&device)?));
        }
        devices.sort_by_key(|(service, _)| *service);
        Ok(devices)
    }

    async fn remove_device(&self, mediation: &str, service: Service, token: &str) -> Result<()> {
        let _: i64 = redis::Script::new(REMOVE_DEVICE)
            .key(devices_key(mediation))
            .arg(service.as_str())
            .arg(token)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(())
    }

    async fn claim_push(&self, mediation: &str, now: u64, hold_secs: u64) -> Result<bool> {
        let reply: Option<String> = redis::cmd("SET")
            .arg(push_sent_key(mediation))
            .arg(now)
            .arg("NX")
            .arg("EX")
            .arg(hold_secs.max(1))
            .query_async(&mut self.conn())
            .await?;
        Ok(reply.is_some())
    }

    async fn release_push(&self, mediation: &str, now: u64, min_interval_secs: u64) -> Result<()> {
        let _: i64 = redis::Script::new(RELEASE_PUSH)
            .key(push_sent_key(mediation))
            .arg(now)
            .arg(min_interval_secs)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(())
    }

    async fn claim_ring(&self, mediation: &str, now: u64, interval_secs: u64) -> Result<bool> {
        // Redis refuses an expiry of 0; no interval means nothing to hold.
        // The key expires on its own, so a removed mediation leaves nothing.
        if interval_secs == 0 {
            return Ok(true);
        }
        let reply: Option<String> = redis::cmd("SET")
            .arg(ring_key(mediation))
            .arg(now)
            .arg("NX")
            .arg("EX")
            .arg(interval_secs)
            .query_async(&mut self.conn())
            .await?;
        Ok(reply.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs against a real Redis when `ALMENA_TEST_REDIS_URL` is set
    /// (e.g. `redis://127.0.0.1:6379` after `task redis`); skipped otherwise.
    #[tokio::test]
    async fn contract() {
        let Ok(url) = std::env::var("ALMENA_TEST_REDIS_URL") else {
            eprintln!("ALMENA_TEST_REDIS_URL not set; skipping the Redis store test");
            return;
        };
        let password = std::env::var("ALMENA_REDIS_PASSWORD")
            .ok()
            .filter(|p| !p.is_empty());
        let store = RedisStore::connect(&url, password.as_deref())
            .await
            .unwrap();
        super::super::contract::run(&store).await;
    }
}
