//! The administration: who runs this mediator and how it was set up, in a
//! SQLite file of its own (`ALMENA_ADMIN_DB_PATH`), apart from the messages.
//!
//! | Table | Holds |
//! |---|---|
//! | `settings` | The site once set up (`public_url`, `access`), the setup code's hash, the domain being proven (`pending_*`) and the secret its proof value comes from (`proof_secret`) |
//! | `admins` | The administrators: the DID each signs in as, and since when |
//! | `sessions` | Signed-in administrators' sessions: the cookie's SHA-256, whose, when last used |
//! | `invitations` | Invitations an administrator made: to be an administrator (one use) or a member (`uses` left), until `expires` |
//! | `members` | Wallets a private mediator took by invitation: the mediation DID, the invitation's label, when |
//!
//! A mediator starts with neither: the onboarding (`setup`) proves its
//! domain, fixes its mode and makes the first administrator. The setup code
//! that opens it is shown once, in the log or by `almena-mediator setup`;
//! only its SHA-256 is kept, and a new one replaces the old.
//!
//! Calls are few and small (a page view, a setup step): they run on the
//! caller's thread, on one connection.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::config::Access;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admins (
    did TEXT PRIMARY KEY,
    added INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    uses INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    created INTEGER NOT NULL,
    created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
    mediation TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    joined INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    seen INTEGER NOT NULL
);
PRAGMA user_version = 1;
";

/// How the mediator was set up: where it is published and who may use it.
/// The mode is fixed for good once written; the URL can move, proven again
/// ([`AdminStore::move_site`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// `https://host[:port]`; the mediator's DID is its `did:web`.
    pub public_url: String,
    pub access: Access,
}

/// A domain the onboarding is proving: the URL asked for, the mode chosen,
/// and the value the DNS record and the HTTPS check must show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub public_url: String,
    pub access: Access,
    pub token: String,
}

/// How long an invitation to be an administrator lasts.
pub const ADMIN_INVITATION_SECS: u64 = 7 * 86_400;

pub struct AdminStore {
    conn: Mutex<Connection>,
}

impl AdminStore {
    /// Opens (or creates) the database at `path`, readable by the
    /// mediator's user only. `:memory:` keeps it in the process (`task dev:memory`).
    pub fn open(path: &Path) -> Result<Self> {
        if path.as_os_str() == ":memory:" {
            return Self::memory();
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restricting {}", path.display()))?;
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::with(conn)
    }

    /// One in the process, for tests.
    pub fn memory() -> Result<Self> {
        Self::with(Connection::open_in_memory()?)
    }

    fn with(conn: Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)
            .context("creating the administration schema")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow!("administration store poisoned"))
    }

    fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
        Ok(conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    fn set(conn: &Connection, key: &str, value: &str) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// The site, once set up.
    pub fn site(&self) -> Result<Option<Site>> {
        let conn = self.conn()?;
        let (Some(public_url), Some(access)) =
            (Self::get(&conn, "public_url")?, Self::get(&conn, "access")?)
        else {
            return Ok(None);
        };
        let access =
            Access::parse(&access).ok_or_else(|| anyhow!("unknown access mode {access}"))?;
        Ok(Some(Site { public_url, access }))
    }

    /// Fixes the site. Refused if it is set up already: neither the URL nor
    /// the mode ever changes.
    pub fn set_site(&self, site: &Site) -> Result<()> {
        let conn = self.conn()?;
        anyhow::ensure!(
            Self::get(&conn, "public_url")?.is_none(),
            "this mediator is set up already"
        );
        let tx = conn.unchecked_transaction()?;
        Self::set(&tx, "public_url", &site.public_url)?;
        Self::set(&tx, "access", site.access.as_str())?;
        for key in ["pending_url", "pending_access", "pending_token"] {
            tx.execute("DELETE FROM settings WHERE key = ?1", [key])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The site to run as. Set up already, the configuration may only repeat
    /// it: the URL and the mode never change. Not set up, `public_url`
    /// (`ALMENA_PUBLIC_URL`) sets it up at once, without the onboarding's
    /// proof — development, tests, a mediator moved here — with `access`, or
    /// public; without it, `None`: the onboarding runs.
    pub fn settle(&self, public_url: Option<&str>, access: Option<Access>) -> Result<Option<Site>> {
        if let Some(mut site) = self.site()? {
            if let Some(url) = public_url.filter(|url| *url != site.public_url) {
                tracing::warn!(from = %site.public_url, to = %url, "the public URL moves to ALMENA_PUBLIC_URL");
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                self.move_site(url, None, now)?;
                site.public_url = url.to_owned();
            }
            if let Some(access) = access {
                anyhow::ensure!(
                    access == site.access,
                    "ALMENA_ACCESS is {}, but this mediator was set up as {}: it cannot change",
                    access.as_str(),
                    site.access.as_str()
                );
            }
            return Ok(Some(site));
        }
        let Some(public_url) = public_url else {
            return Ok(None);
        };
        let site = Site {
            public_url: public_url.to_owned(),
            access: access.unwrap_or(Access::Public),
        };
        self.set_site(&site)?;
        tracing::info!(url = %site.public_url, access = site.access.as_str(), "set up from ALMENA_PUBLIC_URL");
        Ok(Some(site))
    }

    /// Moves the site to another URL, its mode unchanged; whatever was
    /// being proven goes. A wallet signs in with a key it keeps for each
    /// address, so no administrator would be recognised at the new one:
    /// each is turned into an invitation to be one again there (one use,
    /// [`ADMIN_INVITATION_SECS`]), and the administrators and their
    /// sessions go. Returns the invitation of `by`, the one who moved it.
    pub fn move_site(
        &self,
        public_url: &str,
        by: Option<&str>,
        now: u64,
    ) -> Result<Option<String>> {
        let conn = self.conn()?;
        anyhow::ensure!(
            Self::get(&conn, "public_url")?.is_some(),
            "this mediator is not set up yet"
        );
        let admins: Vec<String> = conn
            .prepare("SELECT did FROM admins ORDER BY added, did")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let tx = conn.unchecked_transaction()?;
        Self::set(&tx, "public_url", public_url)?;
        for key in ["pending_url", "pending_access", "pending_token"] {
            tx.execute("DELETE FROM settings WHERE key = ?1", [key])?;
        }
        let mut theirs = None;
        for did in &admins {
            let id = random_hex(16)?;
            let label = if Some(did.as_str()) == by {
                theirs = Some(id.clone());
                "You, at the new address".to_owned()
            } else {
                let tail: String = did
                    .chars()
                    .rev()
                    .take(8)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                format!("Administrator …{tail}, again")
            };
            tx.execute(
                "INSERT INTO invitations (id, kind, label, uses, expires, created, created_by)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
                params![
                    id,
                    InvitationKind::Admin.as_str(),
                    label,
                    now + ADMIN_INVITATION_SECS,
                    now,
                    by.unwrap_or("ALMENA_PUBLIC_URL")
                ],
            )?;
        }
        tx.execute("DELETE FROM admins", [])?;
        tx.execute("DELETE FROM sessions", [])?;
        tx.commit()?;
        Ok(theirs)
    }

    /// Forgets the URL being proven.
    pub fn drop_pending(&self) -> Result<()> {
        let conn = self.conn()?;
        for key in ["pending_url", "pending_access", "pending_token"] {
            conn.execute("DELETE FROM settings WHERE key = ?1", [key])?;
        }
        Ok(())
    }

    /// Starts proving `public_url` (or starts over with another one): the
    /// value the DNS record and the HTTPS check must show is
    /// [`Self::proof_value`] of its host, the same however often it is asked.
    pub fn start_pending(&self, public_url: &str, access: Access) -> Result<Pending> {
        let conn = self.conn()?;
        let pending = Pending {
            public_url: public_url.to_owned(),
            access,
            token: Self::proof_value(&conn, public_url)?,
        };
        let tx = conn.unchecked_transaction()?;
        Self::set(&tx, "pending_url", &pending.public_url)?;
        Self::set(&tx, "pending_access", access.as_str())?;
        Self::set(&tx, "pending_token", &pending.token)?;
        tx.commit()?;
        Ok(pending)
    }

    /// The value that proves `public_url`'s domain is this mediator's: the
    /// HMAC-SHA256 of its host under a secret this mediator made once and
    /// keeps (`proof_secret`), cut to 32 hex digits. **The same for the same
    /// domain, always**: asking again, restarting, or coming back to a URL
    /// tried before keeps the TXT record already published valid. **Only
    /// this mediator can work it out**: from the domain alone nobody can, so
    /// the record still says the domain's owner chose this mediator.
    fn proof_value(conn: &Connection, public_url: &str) -> Result<String> {
        let secret = match Self::get(conn, "proof_secret")? {
            Some(secret) => secret,
            None => {
                let secret = random_hex(32)?;
                Self::set(conn, "proof_secret", &secret)?;
                secret
            }
        };
        let host = url::Url::parse(public_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
            .ok_or_else(|| anyhow!("{public_url} has no host"))?;
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let tag = ring::hmac::sign(&key, host.as_bytes());
        Ok(tag.as_ref()[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    /// The domain being proven, if any.
    pub fn pending(&self) -> Result<Option<Pending>> {
        let conn = self.conn()?;
        let (Some(public_url), Some(access), Some(token)) = (
            Self::get(&conn, "pending_url")?,
            Self::get(&conn, "pending_access")?,
            Self::get(&conn, "pending_token")?,
        ) else {
            return Ok(None);
        };
        let access =
            Access::parse(&access).ok_or_else(|| anyhow!("unknown access mode {access}"))?;
        Ok(Some(Pending {
            public_url,
            access,
            token,
        }))
    }

    /// A new setup code, replacing any earlier one. Only its hash is kept:
    /// the code itself is shown once, to whoever runs the mediator.
    pub fn new_setup_code(&self) -> Result<String> {
        let code = random_hex(16)?;
        let conn = self.conn()?;
        Self::set(&conn, "setup_code", &hash(&code))?;
        Ok(code)
    }

    /// Whether `code` is the current setup code. No code is valid once the
    /// first administrator exists.
    pub fn is_setup_code(&self, code: &str) -> Result<bool> {
        let conn = self.conn()?;
        let admins: u64 = conn.query_row("SELECT count(*) FROM admins", [], |r| r.get(0))?;
        if admins > 0 {
            return Ok(false);
        }
        let Some(stored) = Self::get(&conn, "setup_code")? else {
            return Ok(false);
        };
        // Hashes are compared, not codes: how long the comparison takes
        // says nothing about the code itself.
        Ok(stored == hash(code.trim()))
    }

    /// How many administrators there are.
    pub fn admin_count(&self) -> Result<u64> {
        Ok(self
            .conn()?
            .query_row("SELECT count(*) FROM admins", [], |r| r.get(0))?)
    }

    /// Makes `did` the first administrator, if there is none yet and the
    /// setup code is still there (it goes with it), in one step: two wallets
    /// answering at once cannot both become it. `false` when somebody did.
    pub fn claim(&self, did: &str, now: u64) -> Result<bool> {
        let conn = self.conn()?;
        let tx = conn.unchecked_transaction()?;
        let admins: u64 = tx.query_row("SELECT count(*) FROM admins", [], |r| r.get(0))?;
        if admins > 0 || Self::get(&tx, "setup_code")?.is_none() {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO admins (did, added) VALUES (?1, ?2)",
            params![did, now],
        )?;
        tx.execute("DELETE FROM settings WHERE key = 'setup_code'", [])?;
        tx.commit()?;
        Ok(true)
    }

    /// Makes `did` an administrator; the setup code goes once there is one.
    pub fn add_admin(&self, did: &str, now: u64) -> Result<()> {
        let conn = self.conn()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO admins (did, added) VALUES (?1, ?2)",
            params![did, now],
        )?;
        tx.execute("DELETE FROM settings WHERE key = 'setup_code'", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Whether `did` is an administrator.
    pub fn is_admin(&self, did: &str) -> Result<bool> {
        Ok(self
            .conn()?
            .query_row("SELECT 1 FROM admins WHERE did = ?1", [did], |_| Ok(()))
            .optional()?
            .is_some())
    }
}

/// A session left unused this long ends: the administrator signs in again.
pub const SESSION_IDLE_SECS: u64 = 12 * 3600;

/// An administrator, as the portal lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admin {
    pub did: String,
    /// Epoch seconds.
    pub added: u64,
}

impl AdminStore {
    /// The administrators, oldest first.
    pub fn admins(&self) -> Result<Vec<Admin>> {
        let conn = self.conn()?;
        let mut statement = conn.prepare("SELECT did, added FROM admins ORDER BY added, did")?;
        let admins = statement
            .query_map([], |r| {
                Ok(Admin {
                    did: r.get(0)?,
                    added: r.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(admins)
    }

    /// A new session for the administrator `did`: the token for its cookie.
    /// Only its hash is kept.
    pub fn new_session(&self, did: &str, now: u64) -> Result<String> {
        let token = random_hex(32)?;
        self.conn()?.execute(
            "INSERT INTO sessions (token, did, seen) VALUES (?1, ?2, ?3)",
            params![hash(&token), did, now],
        )?;
        Ok(token)
    }

    /// The administrator a session token belongs to, while it is in use and
    /// they are still an administrator; using it keeps it alive.
    pub fn session(&self, token: &str, now: u64) -> Result<Option<String>> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM sessions WHERE seen < ?1 OR did NOT IN (SELECT did FROM admins)",
            [now.saturating_sub(SESSION_IDLE_SECS)],
        )?;
        let key = hash(token);
        let did: Option<String> = conn
            .query_row("SELECT did FROM sessions WHERE token = ?1", [&key], |r| {
                r.get(0)
            })
            .optional()?;
        if did.is_some() {
            conn.execute(
                "UPDATE sessions SET seen = ?2 WHERE token = ?1",
                params![key, now],
            )?;
        }
        Ok(did)
    }

    /// Ends a session (signing out).
    pub fn end_session(&self, token: &str) -> Result<()> {
        self.conn()?
            .execute("DELETE FROM sessions WHERE token = ?1", [hash(token)])?;
        Ok(())
    }
}

/// What an invitation makes of whoever takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationKind {
    /// An administrator: signs in with the wallet at `/portal/join/{id}`.
    Admin,
    /// A member of a private mediator: its wallet asks for mediation with
    /// the invitation's id as `pthid`.
    Member,
}

impl InvitationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
}

/// An invitation, as the portal lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub id: String,
    pub kind: InvitationKind,
    /// Who it is for, as the administrator wrote it.
    pub label: String,
    /// Uses left.
    pub uses: u32,
    /// Epoch seconds.
    pub expires: u64,
    pub created: u64,
}

/// A wallet a private mediator took by invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Its mediation: the DID its wallet asks for mediation as.
    pub mediation: String,
    /// The label of the invitation it came with.
    pub label: String,
    pub joined: u64,
}

impl AdminStore {
    /// A new invitation of `kind`, made by the administrator `by`.
    pub fn invite(
        &self,
        kind: InvitationKind,
        label: &str,
        uses: u32,
        expires: u64,
        by: &str,
        now: u64,
    ) -> Result<Invitation> {
        let invitation = Invitation {
            id: random_hex(16)?,
            kind,
            label: label.to_owned(),
            uses,
            expires,
            created: now,
        };
        self.conn()?.execute(
            "INSERT INTO invitations (id, kind, label, uses, expires, created, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                invitation.id,
                kind.as_str(),
                invitation.label,
                uses,
                expires,
                now,
                by
            ],
        )?;
        Ok(invitation)
    }

    /// The invitations of `kind` still good at `now`, newest first. Expired
    /// ones are dropped; a spent one stays until then, hidden, so that a use
    /// given back finds it.
    pub fn invitations(&self, kind: InvitationKind, now: u64) -> Result<Vec<Invitation>> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM invitations WHERE expires <= ?1", [now])?;
        let mut statement = conn.prepare(
            "SELECT id, label, uses, expires, created FROM invitations
             WHERE kind = ?1 AND uses > 0 ORDER BY created DESC, id",
        )?;
        let found = statement
            .query_map([kind.as_str()], |r| {
                Ok(Invitation {
                    id: r.get(0)?,
                    kind,
                    label: r.get(1)?,
                    uses: r.get(2)?,
                    expires: r.get(3)?,
                    created: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(found)
    }

    /// The invitation `id` of `kind`, if it is still good at `now`.
    pub fn invitation(
        &self,
        kind: InvitationKind,
        id: &str,
        now: u64,
    ) -> Result<Option<Invitation>> {
        Ok(self
            .invitations(kind, now)?
            .into_iter()
            .find(|invitation| invitation.id == id))
    }

    /// Takes one use of invitation `id` of `kind`: its label, or `None` if it
    /// is not good any more (spent, expired, withdrawn, or never was).
    pub fn use_invitation(
        &self,
        kind: InvitationKind,
        id: &str,
        now: u64,
    ) -> Result<Option<String>> {
        Ok(self
            .conn()?
            .query_row(
                "UPDATE invitations SET uses = uses - 1
                 WHERE id = ?1 AND kind = ?2 AND uses > 0 AND expires > ?3
                 RETURNING label",
                params![id, kind.as_str(), now],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Gives back a use taken by [`AdminStore::use_invitation`] that came to
    /// nothing (the mediator was full).
    pub fn give_back_use(&self, kind: InvitationKind, id: &str) -> Result<()> {
        self.conn()?.execute(
            "UPDATE invitations SET uses = uses + 1 WHERE id = ?1 AND kind = ?2",
            params![id, kind.as_str()],
        )?;
        Ok(())
    }

    /// Withdraws invitation `id`.
    pub fn withdraw(&self, id: &str) -> Result<()> {
        self.conn()?
            .execute("DELETE FROM invitations WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Records the wallet a private mediator took, with its invitation's label.
    pub fn add_member(&self, mediation: &str, label: &str, now: u64) -> Result<()> {
        self.conn()?.execute(
            "INSERT OR REPLACE INTO members (mediation, label, joined) VALUES (?1, ?2, ?3)",
            params![mediation, label, now],
        )?;
        Ok(())
    }

    /// The members, newest first.
    pub fn members(&self) -> Result<Vec<Member>> {
        let conn = self.conn()?;
        let mut statement =
            conn.prepare("SELECT mediation, label, joined FROM members ORDER BY joined DESC")?;
        let found = statement
            .query_map([], |r| {
                Ok(Member {
                    mediation: r.get(0)?,
                    label: r.get(1)?,
                    joined: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(found)
    }

    /// Forgets a member (removed, or its mediation gone).
    pub fn remove_member(&self, mediation: &str) -> Result<()> {
        self.conn()?
            .execute("DELETE FROM members WHERE mediation = ?1", [mediation])?;
        Ok(())
    }

    /// Takes `did` off the administrators, with its sessions.
    pub fn remove_admin(&self, did: &str) -> Result<()> {
        let conn = self.conn()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM admins WHERE did = ?1", [did])?;
        tx.execute("DELETE FROM sessions WHERE did = ?1", [did])?;
        tx.commit()?;
        Ok(())
    }
}

/// `bytes` random bytes, as lowercase hex.
fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| anyhow!("no randomness available"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn hash(code: &str) -> String {
    Sha256::digest(code.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_site_is_fixed_once() {
        let admin = AdminStore::memory().unwrap();
        assert_eq!(admin.site().unwrap(), None);
        let pending = admin
            .start_pending("https://m.example", Access::Private)
            .unwrap();
        assert_eq!(pending.token.len(), 32);
        // The same domain always gets the same value here, whatever the
        // port, the mode or what was tried in between; another domain, or
        // another mediator, another one.
        let again = || {
            admin
                .start_pending("https://M.example:8443", Access::Public)
                .unwrap()
                .token
        };
        admin
            .start_pending("https://other.example", Access::Private)
            .unwrap();
        assert_eq!(again(), pending.token);
        assert_ne!(
            admin
                .start_pending("https://other.example", Access::Private)
                .unwrap()
                .token,
            pending.token
        );
        assert_ne!(
            AdminStore::memory()
                .unwrap()
                .start_pending("https://m.example", Access::Private)
                .unwrap()
                .token,
            pending.token
        );
        let pending = admin
            .start_pending("https://m.example", Access::Private)
            .unwrap();
        assert_eq!(admin.pending().unwrap(), Some(pending));
        let site = Site {
            public_url: "https://m.example".into(),
            access: Access::Private,
        };
        admin.set_site(&site).unwrap();
        assert_eq!(admin.site().unwrap(), Some(site.clone()));
        assert_eq!(admin.pending().unwrap(), None);
        assert!(admin.set_site(&site).is_err());

        // The URL moves, proven again; the mode stays.
        admin
            .start_pending("https://n.example", Access::Private)
            .unwrap();
        admin.drop_pending().unwrap();
        assert_eq!(admin.pending().unwrap(), None);
        admin
            .start_pending("https://n.example", Access::Private)
            .unwrap();
        admin.add_admin("did:key:z6Mk-mover", 1).unwrap();
        admin.add_admin("did:key:z6Mk-other1", 2).unwrap();
        let session = admin.new_session("did:key:z6Mk-mover", 3).unwrap();
        let theirs = admin
            .move_site("https://n.example", Some("did:key:z6Mk-mover"), 10)
            .unwrap()
            .unwrap();
        // Nobody is recognised at the new address: each gets an invitation.
        assert_eq!(admin.admin_count().unwrap(), 0);
        assert_eq!(admin.session(&session, 10).unwrap(), None);
        let invitations = admin.invitations(InvitationKind::Admin, 10).unwrap();
        assert_eq!(invitations.len(), 2);
        assert!(
            invitations
                .iter()
                .any(|i| i.id == theirs && i.label == "You, at the new address")
        );
        assert!(
            invitations
                .iter()
                .any(|i| i.label == "Administrator …k-other1, again")
        );
        assert_eq!(
            admin.site().unwrap(),
            Some(Site {
                public_url: "https://n.example".into(),
                access: Access::Private,
            })
        );
        assert_eq!(admin.pending().unwrap(), None);
        assert!(
            AdminStore::memory()
                .unwrap()
                .move_site("https://n.example", None, 10)
                .is_err()
        );
    }

    #[test]
    fn the_configuration_sets_up_once_and_then_moves_it_but_not_its_mode() {
        let admin = AdminStore::memory().unwrap();
        // Nothing configured: the onboarding runs.
        assert_eq!(admin.settle(None, Some(Access::Private)).unwrap(), None);
        let site = admin
            .settle(Some("https://m.example"), Some(Access::Private))
            .unwrap()
            .unwrap();
        assert_eq!(site.access, Access::Private);
        // Then the configuration may leave it out, repeat it or move the
        // URL, but not change the mode.
        assert_eq!(admin.settle(None, None).unwrap(), Some(site.clone()));
        assert_eq!(
            admin
                .settle(Some("https://m.example"), Some(Access::Private))
                .unwrap(),
            Some(site)
        );
        assert_eq!(
            admin
                .settle(Some("https://other.example"), None)
                .unwrap()
                .unwrap()
                .public_url,
            "https://other.example"
        );
        assert_eq!(
            admin.site().unwrap().unwrap().public_url,
            "https://other.example"
        );
        assert!(admin.settle(None, Some(Access::Public)).is_err());
        // Without a mode, a URL sets it up public.
        let other = AdminStore::memory().unwrap();
        assert_eq!(
            other
                .settle(Some("https://m.example"), None)
                .unwrap()
                .unwrap()
                .access,
            Access::Public
        );
    }

    #[test]
    fn the_setup_code_opens_until_there_is_an_administrator() {
        let admin = AdminStore::memory().unwrap();
        assert!(!admin.is_setup_code("anything").unwrap());
        let old = admin.new_setup_code().unwrap();
        let code = admin.new_setup_code().unwrap();
        assert!(!admin.is_setup_code(&old).unwrap());
        assert!(admin.is_setup_code(&code).unwrap());
        assert!(admin.is_setup_code(&format!(" {code} ")).unwrap());

        admin.add_admin("did:key:z6Mk-admin", 1).unwrap();
        assert!(admin.is_admin("did:key:z6Mk-admin").unwrap());
        assert!(!admin.is_admin("did:key:z6Mk-other").unwrap());
        assert_eq!(admin.admin_count().unwrap(), 1);
        assert!(!admin.is_setup_code(&code).unwrap());
    }

    #[test]
    fn only_one_wallet_claims_the_mediator_and_only_with_a_code() {
        let admin = AdminStore::memory().unwrap();
        // No code (a move from the portal leaves none): nobody claims it.
        assert!(!admin.claim("did:key:z6Mk-early", 1).unwrap());
        admin.new_setup_code().unwrap();
        assert!(admin.claim("did:key:z6Mk-first", 2).unwrap());
        assert!(!admin.claim("did:key:z6Mk-second", 3).unwrap());
        assert_eq!(admin.admin_count().unwrap(), 1);
        assert!(admin.is_admin("did:key:z6Mk-first").unwrap());
    }

    #[test]
    fn sessions_last_while_used_and_only_for_administrators() {
        let admin = AdminStore::memory().unwrap();
        admin.add_admin("did:key:z6Mk-a", 100).unwrap();
        admin.add_admin("did:key:z6Mk-b", 200).unwrap();
        assert_eq!(
            admin
                .admins()
                .unwrap()
                .iter()
                .map(|a| a.did.as_str())
                .collect::<Vec<_>>(),
            ["did:key:z6Mk-a", "did:key:z6Mk-b"]
        );
        let token = admin.new_session("did:key:z6Mk-a", 1_000).unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(admin.session("forged", 1_000).unwrap(), None);
        // Used within the idle time, it lasts; each use counts.
        let later = 1_000 + SESSION_IDLE_SECS - 1;
        assert_eq!(
            admin.session(&token, later).unwrap().as_deref(),
            Some("did:key:z6Mk-a")
        );
        assert!(
            admin
                .session(&token, later + SESSION_IDLE_SECS - 1)
                .unwrap()
                .is_some()
        );
        // Left unused, it ends.
        assert_eq!(admin.session(&token, later * 3).unwrap(), None);
        // Signing out ends it at once.
        let token = admin.new_session("did:key:z6Mk-b", 1_000).unwrap();
        admin.end_session(&token).unwrap();
        assert_eq!(admin.session(&token, 1_000).unwrap(), None);
        // A session of someone who is no longer an administrator is no good.
        let stranger = admin.new_session("did:key:z6Mk-gone", 1_000).unwrap();
        assert_eq!(admin.session(&stranger, 1_000).unwrap(), None);
    }

    #[test]
    fn invitations_are_used_up_expire_and_can_be_withdrawn() {
        let admin = AdminStore::memory().unwrap();
        let three = admin
            .invite(InvitationKind::Member, "Family", 3, 1_000, "did:key:a", 100)
            .unwrap();
        let other = admin
            .invite(InvitationKind::Admin, "Bea", 1, 1_000, "did:key:a", 200)
            .unwrap();
        assert_eq!(
            admin.invitations(InvitationKind::Member, 100).unwrap(),
            std::slice::from_ref(&three)
        );
        // Not of the kind asked for.
        assert_eq!(
            admin
                .use_invitation(InvitationKind::Member, &other.id, 150)
                .unwrap(),
            None
        );
        for _ in 0..3 {
            assert_eq!(
                admin
                    .use_invitation(InvitationKind::Member, &three.id, 150)
                    .unwrap()
                    .as_deref(),
                Some("Family")
            );
        }
        assert_eq!(
            admin
                .use_invitation(InvitationKind::Member, &three.id, 150)
                .unwrap(),
            None
        );
        assert!(
            admin
                .invitations(InvitationKind::Member, 150)
                .unwrap()
                .is_empty()
        );
        // A use given back is there again.
        admin
            .give_back_use(InvitationKind::Member, &three.id)
            .unwrap();
        assert_eq!(
            admin
                .invitation(InvitationKind::Member, &three.id, 150)
                .unwrap()
                .map(|i| i.uses),
            Some(1)
        );
        // Expired.
        assert_eq!(
            admin
                .use_invitation(InvitationKind::Admin, &other.id, 1_000)
                .unwrap(),
            None
        );
        // Withdrawn.
        let gone = admin
            .invite(InvitationKind::Member, "x", 1, 5_000, "did:key:a", 300)
            .unwrap();
        admin.withdraw(&gone.id).unwrap();
        assert_eq!(
            admin
                .use_invitation(InvitationKind::Member, &gone.id, 400)
                .unwrap(),
            None
        );
    }

    #[test]
    fn members_and_administrators_come_and_go() {
        let admin = AdminStore::memory().unwrap();
        admin.add_member("did:peer:2.one", "Ana", 10).unwrap();
        admin.add_member("did:peer:2.two", "Bea", 20).unwrap();
        assert_eq!(
            admin
                .members()
                .unwrap()
                .iter()
                .map(|m| m.label.as_str())
                .collect::<Vec<_>>(),
            ["Bea", "Ana"]
        );
        admin.remove_member("did:peer:2.one").unwrap();
        assert_eq!(admin.members().unwrap().len(), 1);

        admin.add_admin("did:key:a", 1).unwrap();
        admin.add_admin("did:key:b", 2).unwrap();
        let token = admin.new_session("did:key:b", 5).unwrap();
        admin.remove_admin("did:key:b").unwrap();
        assert!(!admin.is_admin("did:key:b").unwrap());
        assert_eq!(admin.session(&token, 5).unwrap(), None);
    }

    #[test]
    fn the_file_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data/admin.db");
        let code = {
            let admin = AdminStore::open(&path).unwrap();
            admin
                .set_site(&Site {
                    public_url: "https://m.example".into(),
                    access: Access::Public,
                })
                .unwrap();
            admin.new_setup_code().unwrap()
        };
        let admin = AdminStore::open(&path).unwrap();
        assert_eq!(admin.site().unwrap().unwrap().access, Access::Public);
        assert!(admin.is_setup_code(&code).unwrap());
    }
}
