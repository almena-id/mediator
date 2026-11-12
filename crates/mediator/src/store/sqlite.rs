//! [`Store`] on SQLite: one file, opened by this one process.
//!
//! | Table | Holds |
//! |---|---|
//! | `mediations` | Each mediation and when its wallet was last active |
//! | `recipients` | Recipient DID → the mediation that registered it |
//! | `messages` | The queues: one row per message, `seq` ordering them |
//! | `devices` | Push service → device, per mediation |
//! | `push_sent` | When the last push went, and until when it holds the next |
//! | `relays` | `forward` payloads waiting to be relayed |
//! | `hits` | Rate-limit counters of the current window |
//!
//! A queue id is `<received ms>-<seq>`, the shape Message Pickup clients
//! already hold. Calls run on Tokio's blocking pool, one at a time on one
//! connection: WAL, `synchronous = NORMAL`.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{
    AddRecipient, Mailbox, PendingRelay, QueueLimits, QueueSummary, Queued, RelayLimits,
    RemoveRecipient, Store, Totals, id_millis, is_queue_id,
};
use crate::push::{Device, Service};

/// The schema; `user_version` says which one a file has.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS mediations (
    id TEXT PRIMARY KEY,
    seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mediations_seen ON mediations (seen);
CREATE TABLE IF NOT EXISTS recipients (
    did TEXT PRIMARY KEY,
    mediation TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS recipients_mediation ON recipients (mediation);
CREATE TABLE IF NOT EXISTS messages (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    mediation TEXT NOT NULL,
    recipient TEXT NOT NULL,
    received INTEGER NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_mediation ON messages (mediation, seq);
CREATE TABLE IF NOT EXISTS devices (
    mediation TEXT NOT NULL,
    service TEXT NOT NULL,
    token TEXT NOT NULL,
    platform TEXT,
    PRIMARY KEY (mediation, service)
);
CREATE TABLE IF NOT EXISTS push_sent (
    mediation TEXT PRIMARY KEY,
    sent INTEGER NOT NULL,
    until INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS relays (
    id TEXT PRIMARY KEY,
    due INTEGER NOT NULL,
    uri TEXT NOT NULL,
    destination TEXT NOT NULL,
    message TEXT NOT NULL,
    attempts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS relays_due ON relays (due);
CREATE TABLE IF NOT EXISTS hits (
    key TEXT PRIMARY KEY,
    window INTEGER NOT NULL,
    count INTEGER NOT NULL,
    expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS hits_expires ON hits (expires);
PRAGMA user_version = 1;
";

pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
    /// Tests only: rate-limit counting fails, as a broken store would.
    #[cfg(test)]
    pub(crate) failing_hits: std::sync::atomic::AtomicBool,
}

impl SqliteStore {
    /// Opens (or creates) the database at `path`, and its directory.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        // Push tokens and queued envelopes: the mediator's user only, like
        // its keys. The WAL and shared-memory files take the same mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restricting {}", path.display()))?;
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Self::with(conn)
    }

    /// A database in the process: everything is lost when it goes. Tests
    /// and `ALMENA_DB_PATH=:memory:`.
    pub fn memory() -> Result<Self> {
        Self::with(Connection::open_in_memory()?)
    }

    fn with(conn: Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA).context("creating the schema")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            #[cfg(test)]
            failing_hits: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Runs `f` in a transaction on the blocking pool.
    async fn run<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Transaction<'_>) -> rusqlite::Result<T> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut conn = conn.lock().map_err(|_| anyhow!("store poisoned"))?;
            let tx = conn.transaction()?;
            let out = f(&tx)?;
            tx.commit()?;
            Ok(out)
        })
        .await?
    }
}

/// Drops the mediation's messages older than `ttl_secs`.
fn expire(tx: &Transaction<'_>, mediation: &str, now: u64, ttl_secs: u64) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM messages WHERE mediation = ?1 AND received < ?2",
        params![mediation, now.saturating_sub(ttl_secs)],
    )?;
    Ok(())
}

fn queue_id(received: u64, seq: i64) -> String {
    format!("{}-{seq}", received * 1000)
}

#[async_trait]
impl Store for SqliteStore {
    async fn ping(&self) -> Result<()> {
        self.run(|tx| tx.query_row("SELECT 1", [], |_| Ok(())))
            .await
    }

    async fn grant_mediation(&self, mediation: &str, now: u64, max: u64) -> Result<bool> {
        let mediation = mediation.to_owned();
        self.run(move |tx| {
            let held = tx
                .query_row(
                    "SELECT 1 FROM mediations WHERE id = ?1",
                    [&mediation],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !held && max > 0 {
                let count: u64 =
                    tx.query_row("SELECT count(*) FROM mediations", [], |r| r.get(0))?;
                if count >= max {
                    return Ok(false);
                }
            }
            tx.execute(
                "INSERT INTO mediations (id, seen) VALUES (?1, ?2)
                 ON CONFLICT (id) DO UPDATE SET seen = excluded.seen",
                params![mediation, now],
            )?;
            Ok(true)
        })
        .await
    }

    async fn mediation_count(&self) -> Result<u64> {
        self.run(|tx| tx.query_row("SELECT count(*) FROM mediations", [], |r| r.get(0)))
            .await
    }

    async fn touch_mediation(&self, mediation: &str, now: u64) -> Result<()> {
        let mediation = mediation.to_owned();
        self.run(move |tx| {
            tx.execute(
                "UPDATE mediations SET seen = ?2 WHERE id = ?1",
                params![mediation, now],
            )
            .map(|_| ())
        })
        .await
    }

    async fn remove_idle_mediations(&self, cutoff: u64, limit: usize) -> Result<Vec<String>> {
        self.run(move |tx| {
            let idle: Vec<String> = tx
                .prepare("SELECT id FROM mediations WHERE seen <= ?1 LIMIT ?2")?
                .query_map(params![cutoff, limit as i64], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for mediation in &idle {
                for table in ["recipients", "messages", "devices", "push_sent"] {
                    tx.execute(
                        &format!("DELETE FROM {table} WHERE mediation = ?1"),
                        [mediation],
                    )?;
                }
                tx.execute("DELETE FROM mediations WHERE id = ?1", [mediation])?;
            }
            Ok(idle)
        })
        .await
    }

    async fn remove_mediation(&self, mediation: &str) -> Result<bool> {
        let mediation = mediation.to_owned();
        self.run(move |tx| {
            for table in ["recipients", "messages", "devices", "push_sent"] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE mediation = ?1"),
                    [&mediation],
                )?;
            }
            Ok(tx.execute("DELETE FROM mediations WHERE id = ?1", [&mediation])? > 0)
        })
        .await
    }

    async fn mailboxes(
        &self,
        search: &str,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<Mailbox>, u64)> {
        let search = search.to_owned();
        self.run(move |tx| {
            const MATCHING: &str = "?1 = '' OR instr(m.id, ?1) > 0 OR EXISTS
                (SELECT 1 FROM recipients r WHERE r.mediation = m.id AND instr(r.did, ?1) > 0)";
            let total: u64 = tx.query_row(
                &format!("SELECT count(*) FROM mediations m WHERE {MATCHING}"),
                [&search],
                |r| r.get(0),
            )?;
            let listed = tx
                .prepare(&format!(
                    "SELECT m.id, m.seen,
                        (SELECT count(*) FROM recipients r WHERE r.mediation = m.id),
                        (SELECT count(*) FROM messages q WHERE q.mediation = m.id),
                        (SELECT coalesce(sum(length(CAST(q.message AS BLOB))), 0)
                         FROM messages q WHERE q.mediation = m.id),
                        (SELECT count(*) FROM devices d WHERE d.mediation = m.id)
                     FROM mediations m WHERE {MATCHING}
                     ORDER BY m.seen DESC, m.id LIMIT ?2 OFFSET ?3"
                ))?
                .query_map(params![search, limit as i64, offset as i64], |r| {
                    Ok(Mailbox {
                        id: r.get(0)?,
                        seen: r.get(1)?,
                        dids: r.get(2)?,
                        messages: r.get(3)?,
                        bytes: r.get(4)?,
                        devices: r.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok((listed, total))
        })
        .await
    }

    async fn totals(&self) -> Result<Totals> {
        self.run(|tx| {
            tx.query_row(
                "SELECT (SELECT count(*) FROM mediations), (SELECT count(*) FROM recipients),
                        (SELECT count(*) FROM messages),
                        (SELECT coalesce(sum(length(CAST(message AS BLOB))), 0) FROM messages),
                        (SELECT count(*) FROM devices), (SELECT count(*) FROM relays),
                        (SELECT coalesce(max(n), 0)
                         FROM (SELECT count(*) AS n FROM recipients GROUP BY mediation))",
                [],
                |r| {
                    Ok(Totals {
                        mailboxes: r.get(0)?,
                        dids: r.get(1)?,
                        messages: r.get(2)?,
                        bytes: r.get(3)?,
                        devices: r.get(4)?,
                        relays: r.get(5)?,
                        fullest: r.get(6)?,
                    })
                },
            )
        })
        .await
    }

    async fn has_mediation(&self, mediation: &str) -> Result<bool> {
        let mediation = mediation.to_owned();
        self.run(move |tx| {
            tx.query_row(
                "SELECT 1 FROM mediations WHERE id = ?1",
                [&mediation],
                |_| Ok(()),
            )
            .optional()
            .map(|found| found.is_some())
        })
        .await
    }

    async fn add_recipient(
        &self,
        mediation: &str,
        recipient: &str,
        max: usize,
    ) -> Result<AddRecipient> {
        let (mediation, recipient) = (mediation.to_owned(), recipient.to_owned());
        self.run(move |tx| {
            let owner: Option<String> = tx
                .query_row(
                    "SELECT mediation FROM recipients WHERE did = ?1",
                    [&recipient],
                    |r| r.get(0),
                )
                .optional()?;
            match owner {
                Some(owner) if owner == mediation => return Ok(AddRecipient::AlreadyYours),
                Some(_) => return Ok(AddRecipient::TakenByOther),
                None => {}
            }
            // Another wallet's mediation DID is that wallet's, proof or not.
            let another_mediation = recipient != mediation
                && tx
                    .query_row(
                        "SELECT 1 FROM mediations WHERE id = ?1",
                        [&recipient],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
            if another_mediation {
                return Ok(AddRecipient::TakenByOther);
            }
            // The mediation may have been removed since it was looked up.
            let held = tx
                .query_row(
                    "SELECT 1 FROM mediations WHERE id = ?1",
                    [&mediation],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !held {
                return Ok(AddRecipient::NoMediation);
            }
            let count: usize = tx.query_row(
                "SELECT count(*) FROM recipients WHERE mediation = ?1",
                [&mediation],
                |r| r.get(0),
            )?;
            if count >= max {
                return Ok(AddRecipient::LimitReached);
            }
            tx.execute(
                "INSERT INTO recipients (did, mediation) VALUES (?1, ?2)",
                params![recipient, mediation],
            )?;
            Ok(AddRecipient::Added)
        })
        .await
    }

    async fn remove_recipient(&self, mediation: &str, recipient: &str) -> Result<RemoveRecipient> {
        let (mediation, recipient) = (mediation.to_owned(), recipient.to_owned());
        self.run(move |tx| {
            let owner: Option<String> = tx
                .query_row(
                    "SELECT mediation FROM recipients WHERE did = ?1",
                    [&recipient],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(match owner {
                None => RemoveRecipient::NotRegistered,
                Some(owner) if owner != mediation => RemoveRecipient::NotYours,
                Some(_) => {
                    tx.execute("DELETE FROM recipients WHERE did = ?1", [&recipient])?;
                    RemoveRecipient::Removed
                }
            })
        })
        .await
    }

    async fn recipients(&self, mediation: &str) -> Result<Vec<String>> {
        let mediation = mediation.to_owned();
        self.run(move |tx| {
            tx.prepare("SELECT did FROM recipients WHERE mediation = ?1 ORDER BY did")?
                .query_map([&mediation], |r| r.get(0))?
                .collect()
        })
        .await
    }

    async fn mediation_of(&self, recipient: &str) -> Result<Option<String>> {
        let recipient = recipient.to_owned();
        self.run(move |tx| {
            tx.query_row(
                "SELECT mediation FROM recipients WHERE did = ?1",
                [&recipient],
                |r| r.get(0),
            )
            .optional()
        })
        .await
    }

    async fn enqueue_all(
        &self,
        mediation: &str,
        recipient: &str,
        messages: &[String],
        now: u64,
        limits: QueueLimits,
    ) -> Result<Option<Vec<String>>> {
        let (mediation, recipient) = (mediation.to_owned(), recipient.to_owned());
        let messages = messages.to_vec();
        self.run(move |tx| {
            expire(tx, &mediation, now, limits.ttl_secs)?;
            let (count, bytes): (usize, u64) = tx.query_row(
                "SELECT count(*), coalesce(sum(length(CAST(message AS BLOB))), 0)
                 FROM messages WHERE mediation = ?1",
                [&mediation],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let adding: u64 = messages.iter().map(|m| m.len() as u64).sum();
            if count + messages.len() > limits.max_messages || bytes + adding > limits.max_bytes {
                return Ok(None);
            }
            let mut insert = tx.prepare(
                "INSERT INTO messages (mediation, recipient, received, message)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut ids = Vec::with_capacity(messages.len());
            for message in &messages {
                insert.execute(params![mediation, recipient, now, message])?;
                ids.push(queue_id(now, tx.last_insert_rowid()));
            }
            Ok(Some(ids))
        })
        .await
    }

    async fn summary(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<QueueSummary> {
        let (mediation, recipient) = (mediation.to_owned(), recipient.map(str::to_owned));
        self.run(move |tx| {
            expire(tx, &mediation, now, ttl_secs)?;
            tx.query_row(
                "SELECT count(*), min(received), max(received),
                        coalesce(sum(length(CAST(message AS BLOB))), 0)
                 FROM messages WHERE mediation = ?1 AND (?2 IS NULL OR recipient = ?2)",
                params![mediation, recipient],
                |r| {
                    Ok(QueueSummary {
                        count: r.get(0)?,
                        oldest: r.get(1)?,
                        newest: r.get(2)?,
                        total_bytes: r.get(3)?,
                    })
                },
            )
        })
        .await
    }

    async fn peek(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        limit: usize,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Vec<Queued>> {
        let (mediation, recipient) = (mediation.to_owned(), recipient.map(str::to_owned));
        self.run(move |tx| {
            expire(tx, &mediation, now, ttl_secs)?;
            tx.prepare(
                "SELECT seq, recipient, received, message FROM messages
                 WHERE mediation = ?1 AND (?2 IS NULL OR recipient = ?2)
                 ORDER BY seq LIMIT ?3",
            )?
            .query_map(params![mediation, recipient, limit as i64], |r| {
                let received: u64 = r.get(2)?;
                Ok(Queued {
                    id: queue_id(received, r.get(0)?),
                    recipient: r.get(1)?,
                    received,
                    message: r.get(3)?,
                })
            })?
            .collect()
        })
        .await
    }

    async fn remove(&self, mediation: &str, ids: &[String]) -> Result<usize> {
        let mediation = mediation.to_owned();
        let keys: Vec<(u64, i64)> = ids
            .iter()
            .filter(|id| is_queue_id(id))
            .filter_map(|id| {
                let seq = id.split_once('-')?.1.parse().ok()?;
                Some((id_millis(id) / 1000, seq))
            })
            .collect();
        self.run(move |tx| {
            let mut delete = tx.prepare(
                "DELETE FROM messages WHERE mediation = ?1 AND seq = ?2 AND received = ?3",
            )?;
            let mut removed = 0;
            for (received, seq) in keys {
                removed += delete.execute(params![mediation, seq, received])?;
            }
            Ok(removed)
        })
        .await
    }

    async fn hit(&self, key: &str, window_secs: u64, now: u64) -> Result<u64> {
        #[cfg(test)]
        if self.failing_hits.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(anyhow!("store down"));
        }
        let key = key.to_owned();
        let size = window_secs.max(1);
        let window = now / size;
        let expires = (window + 1) * size;
        self.run(move |tx| {
            tx.execute("DELETE FROM hits WHERE expires <= ?1", [now])?;
            tx.query_row(
                "INSERT INTO hits (key, window, count, expires) VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT (key) DO UPDATE SET
                     count = CASE WHEN window = excluded.window THEN count + 1 ELSE 1 END,
                     window = excluded.window,
                     expires = excluded.expires
                 RETURNING count",
                params![key, window, expires],
                |r| r.get(0),
            )
        })
        .await
    }

    async fn schedule_relay(
        &self,
        relay: &PendingRelay,
        due: u64,
        limits: RelayLimits,
    ) -> Result<bool> {
        let relay = relay.clone();
        let destination = relay.destination();
        self.run(move |tx| {
            let waiting = tx
                .query_row(
                    "SELECT 1 FROM relays WHERE id = ?1",
                    [&relay.id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if waiting && relay.attempts == 0 {
                return Ok(true);
            }
            if !waiting {
                let (pending, bytes, to_it): (usize, u64, usize) = tx.query_row(
                    "SELECT count(*), coalesce(sum(length(CAST(message AS BLOB))), 0),
                            count(*) FILTER (WHERE destination = ?1)
                     FROM relays",
                    [&destination],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                if pending >= limits.pending
                    || to_it >= limits.per_destination
                    || bytes + relay.bytes() > limits.bytes
                {
                    return Ok(false);
                }
            }
            tx.execute(
                "INSERT OR REPLACE INTO relays (id, due, uri, destination, message, attempts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    relay.id,
                    due,
                    relay.uri,
                    destination,
                    relay.message,
                    relay.attempts
                ],
            )?;
            Ok(true)
        })
        .await
    }

    async fn due_relays(
        &self,
        now: u64,
        lease_secs: u64,
        limit: usize,
    ) -> Result<Vec<PendingRelay>> {
        self.run(move |tx| {
            let due: Vec<PendingRelay> = tx
                .prepare(
                    "SELECT id, uri, message, attempts FROM relays
                     WHERE due <= ?1 ORDER BY due LIMIT ?2",
                )?
                .query_map(params![now, limit as i64], |r| {
                    Ok(PendingRelay {
                        id: r.get(0)?,
                        uri: r.get(1)?,
                        message: r.get(2)?,
                        attempts: r.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            let mut lease = tx.prepare("UPDATE relays SET due = ?2 WHERE id = ?1")?;
            for relay in &due {
                lease.execute(params![relay.id, now + lease_secs])?;
            }
            Ok(due)
        })
        .await
    }

    async fn finish_relay(&self, relay: &PendingRelay) -> Result<()> {
        let id = relay.id.clone();
        self.run(move |tx| {
            tx.execute("DELETE FROM relays WHERE id = ?1", [&id])
                .map(|_| ())
        })
        .await
    }

    async fn set_device(
        &self,
        mediation: &str,
        service: Service,
        device: Option<&Device>,
    ) -> Result<()> {
        let (mediation, device) = (mediation.to_owned(), device.cloned());
        self.run(move |tx| {
            match device {
                Some(device) => tx.execute(
                    "INSERT OR REPLACE INTO devices (mediation, service, token, platform)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![mediation, service.as_str(), device.token, device.platform],
                )?,
                None => tx.execute(
                    "DELETE FROM devices WHERE mediation = ?1 AND service = ?2",
                    params![mediation, service.as_str()],
                )?,
            };
            Ok(())
        })
        .await
    }

    async fn devices(&self, mediation: &str) -> Result<Vec<(Service, Device)>> {
        let mediation = mediation.to_owned();
        let rows: Vec<(String, Device)> = self
            .run(move |tx| {
                tx.prepare("SELECT service, token, platform FROM devices WHERE mediation = ?1")?
                    .query_map([&mediation], |r| {
                        Ok((
                            r.get(0)?,
                            Device {
                                token: r.get(1)?,
                                platform: r.get(2)?,
                            },
                        ))
                    })?
                    .collect()
            })
            .await?;
        let mut devices: Vec<_> = rows
            .into_iter()
            .filter_map(|(service, device)| Some((Service::parse(&service)?, device)))
            .collect();
        devices.sort_by_key(|(service, _)| *service);
        Ok(devices)
    }

    async fn remove_device(&self, mediation: &str, service: Service, token: &str) -> Result<()> {
        let (mediation, token) = (mediation.to_owned(), token.to_owned());
        self.run(move |tx| {
            tx.execute(
                "DELETE FROM devices WHERE mediation = ?1 AND service = ?2 AND token = ?3",
                params![mediation, service.as_str(), token],
            )
            .map(|_| ())
        })
        .await
    }

    async fn claim_push(&self, mediation: &str, now: u64, hold_secs: u64) -> Result<bool> {
        let mediation = mediation.to_owned();
        self.run(move |tx| {
            let until: Option<u64> = tx
                .query_row(
                    "SELECT until FROM push_sent WHERE mediation = ?1",
                    [&mediation],
                    |r| r.get(0),
                )
                .optional()?;
            if until.is_some_and(|until| now < until) {
                return Ok(false);
            }
            tx.execute(
                "INSERT OR REPLACE INTO push_sent (mediation, sent, until) VALUES (?1, ?2, ?3)",
                params![mediation, now, now.saturating_add(hold_secs)],
            )?;
            Ok(true)
        })
        .await
    }

    async fn release_push(&self, mediation: &str, now: u64, min_interval_secs: u64) -> Result<()> {
        let mediation = mediation.to_owned();
        self.run(move |tx| {
            let sent: Option<(u64, u64)> = tx
                .query_row(
                    "SELECT sent, until FROM push_sent WHERE mediation = ?1",
                    [&mediation],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((sent, until)) = sent {
                let until = until.min(sent.saturating_add(min_interval_secs));
                if until <= now {
                    tx.execute("DELETE FROM push_sent WHERE mediation = ?1", [&mediation])?;
                } else {
                    tx.execute(
                        "UPDATE push_sent SET until = ?2 WHERE mediation = ?1",
                        params![mediation, until],
                    )?;
                }
            }
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn contract() {
        super::super::contract::run(&SqliteStore::memory().unwrap()).await;
    }

    #[tokio::test]
    async fn expired_messages_disappear() {
        let store = SqliteStore::memory().unwrap();
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

    #[tokio::test]
    async fn what_is_queued_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data/mediator.db");
        let limits = QueueLimits {
            ttl_secs: 3600,
            max_messages: 10,
            max_bytes: 1024,
        };
        let now = super::super::now_for_tests();
        let id = {
            let store = SqliteStore::open(&path).unwrap();
            store.grant_mediation("m", now, 0).await.unwrap();
            store.add_recipient("m", "r", 5).await.unwrap();
            store
                .enqueue("m", "r", "kept", now, limits)
                .await
                .unwrap()
                .unwrap()
        };
        let store = SqliteStore::open(&path).unwrap();
        assert!(store.has_mediation("m").await.unwrap());
        assert_eq!(store.mediation_of("r").await.unwrap().as_deref(), Some("m"));
        let queued = store.peek("m", None, 10, now, 3600).await.unwrap();
        assert_eq!(queued[0].id, id);
        assert_eq!(queued[0].message, "kept");
    }
}
