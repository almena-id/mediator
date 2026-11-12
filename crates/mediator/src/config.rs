use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};

use crate::push::ApnsConfig;

/// Runtime configuration, read from `ALMENA_*` environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Address the HTTP server binds to (`ALMENA_HOST`, `ALMENA_PORT`).
    pub bind: SocketAddr,
    /// Address of the Prometheus metrics listener (`ALMENA_METRICS_ADDR`,
    /// e.g. `127.0.0.1:9090`); unset: no metrics. Keep it off the public proxy.
    pub metrics_addr: Option<SocketAddr>,
    /// Log output format (`ALMENA_LOG_FORMAT`: `pretty` or `json`).
    pub log_format: LogFormat,
    /// Public origin of the mediator, `scheme://host[:port]` without path
    /// (`ALMENA_PUBLIC_URL`). The mediator's DID is the `did:web` of this origin
    /// and its DIDComm endpoint is `<origin>/didcomm`. Normally unset: the
    /// onboarding asks for it and proves it (`setup`). Set, it skips that
    /// proof — for development, tests and a mediator already set up.
    pub public_url: Option<String>,
    /// Who may hold a mailbox (`ALMENA_ACCESS`: `public` or `private`), with
    /// `ALMENA_PUBLIC_URL`; otherwise the onboarding asks. Fixed once set.
    pub access: Option<Access>,
    /// SQLite database of the administration — the site, the administrators,
    /// the setup code (`ALMENA_ADMIN_DB_PATH`); apart from the messages.
    pub admin_db_path: PathBuf,
    /// JSON file holding the mediator's private keys (`ALMENA_KEYS_PATH`);
    /// created with fresh keys on first start.
    pub keys_path: PathBuf,
    /// SQLite database holding mediations, queues, devices and relays
    /// (`ALMENA_DB_PATH`); created on first start. `:memory:` keeps
    /// everything in the process instead: development only.
    pub db_path: String,
    /// Largest DIDComm envelope accepted, in bytes (`ALMENA_MAX_MESSAGE_BYTES`).
    pub max_message_bytes: usize,
    /// Undelivered messages are dropped after this many seconds (`ALMENA_QUEUE_TTL`).
    pub queue_ttl_secs: u64,
    /// Queued messages per mediation (`ALMENA_QUEUE_MAX_MESSAGES`).
    pub queue_max_messages: usize,
    /// Bytes of queued messages per mediation (`ALMENA_QUEUE_MAX_BYTES`).
    pub queue_max_bytes: u64,
    /// Recipient DIDs per mediation (`ALMENA_MAX_RECIPIENT_DIDS`).
    pub max_recipient_dids: usize,
    /// Mediations the mediator holds at once; a new one past it is denied.
    /// 0 = no limit (`ALMENA_MAX_MEDIATIONS`).
    pub max_mediations: u64,
    /// WebSockets open at once, from every client (`ALMENA_MAX_SOCKETS`).
    pub max_sockets: usize,
    /// A mediation whose wallet sends nothing for this many seconds is removed
    /// with everything it owns; 0 keeps them forever (`ALMENA_MEDIATION_TTL`).
    pub mediation_ttl_secs: u64,
    /// Registering someone else's DID needs a possession proof
    /// (`ALMENA_RECIPIENT_PROOF`: `required` or `off`).
    pub recipient_proof: bool,
    /// `POST /didcomm` requests per minute per client IP; 0 turns the limit
    /// off (`ALMENA_RATE_LIMIT`).
    pub rate_limit: u64,
    /// What to do when the store cannot count a request against the rate
    /// limit (`ALMENA_RATE_LIMIT_ON_ERROR`: `closed`, the default, refuses it
    /// with `503`; `open` lets it through).
    pub rate_limit_on_error: OnError,
    /// Header holding the client IP when the mediator runs behind a reverse
    /// proxy, e.g. `x-forwarded-for` (`ALMENA_CLIENT_IP_HEADER`). Its last
    /// value is used: the one the proxy added. Unset: the peer address.
    pub client_ip_header: Option<String>,
    /// Peers whose client IP header is believed (`ALMENA_TRUSTED_PROXIES`,
    /// comma-separated CIDRs); from anyone else the peer address counts.
    /// Default: loopback and the private ranges, where a proxy in front of
    /// the mediator on the same machine or container network connects from.
    pub trusted_proxies: Vec<IpNet>,
    /// Relays to one destination host per minute; 0 turns the limit off
    /// (`ALMENA_RELAY_RATE_LIMIT`).
    pub relay_rate_limit: u64,
    /// Relay `forward`s for recipients mediated elsewhere to their mediator, and
    /// resolve other mediators' `did:web` over HTTPS (`ALMENA_FEDERATION`).
    pub federation: bool,
    /// Let outbound requests use plain HTTP and private addresses — local
    /// multi-mediator testing only (`ALMENA_OUTBOUND_ALLOW_INSECURE`).
    pub outbound_allow_insecure: bool,
    /// Push wake-ups (`ALMENA_PUSH_*`, `ALMENA_FCM_*`, `ALMENA_APNS_*`).
    pub push: PushConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushConfig {
    /// `ALMENA_PUSH_MODE`: `off` or `direct` (the mediator calls FCM and
    /// APNs with the wallet app's credentials).
    pub mode: PushMode,
    /// Least seconds between two pushes to one mediation
    /// (`ALMENA_PUSH_MIN_INTERVAL`).
    pub min_interval_secs: u64,
    /// Google service account key file of the wallet app's Firebase project
    /// (`ALMENA_FCM_SERVICE_ACCOUNT`).
    pub fcm_service_account: Option<PathBuf>,
    /// `ALMENA_APNS_KEY_PATH`, `ALMENA_APNS_KEY_ID`, `ALMENA_APNS_TEAM_ID`,
    /// `ALMENA_APNS_TOPIC` and `ALMENA_APNS_SANDBOX`.
    pub apns: Option<ApnsConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushMode {
    Off,
    Direct,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            mode: PushMode::Off,
            min_interval_secs: 60,
            fcm_service_account: None,
            apns: None,
        }
    }
}

/// Whether a check that cannot be made lets the request through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    Open,
    Closed,
}

/// An IP network in CIDR notation (`10.0.0.0/8`, `::1/128`); a bare address
/// is the network of that address alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Whether `ip` is in this network. An IPv4-mapped IPv6 address counts
    /// as the IPv4 address it maps.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for IpNet {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };
        let addr: IpAddr = addr
            .parse()
            .with_context(|| format!("invalid address in {value}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse()
                .ok()
                .filter(|p| *p <= max)
                .with_context(|| format!("invalid prefix length in {value}"))?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }
}

/// Loopback and the private ranges (RFC 1918, unique local): where a
/// reverse proxy in front of the mediator connects from.
pub const DEFAULT_TRUSTED_PROXIES: &str =
    "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7";

fn ip_nets(key: &str, value: &str) -> Result<Vec<IpNet>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.parse().with_context(|| format!("invalid {key}: {v}")))
        .collect()
}

/// Who may hold a mailbox at this mediator. Chosen once, when it is set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Any wallet that asks.
    Public,
    /// Only the wallets an administrator invites.
    Private,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "private" => Some(Self::Private),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            metrics_addr: None,
            log_format: LogFormat::Pretty,
            public_url: None,
            access: None,
            admin_db_path: PathBuf::from("data/admin.db"),
            keys_path: PathBuf::from("data/keys.json"),
            db_path: "data/mediator.db".to_owned(),
            max_message_bytes: 1024 * 1024,
            queue_ttl_secs: 30 * 24 * 3600,
            queue_max_messages: 1_000,
            queue_max_bytes: 10 * 1024 * 1024,
            max_recipient_dids: 1000,
            max_mediations: 10_000,
            max_sockets: 5_000,
            recipient_proof: true,
            mediation_ttl_secs: 90 * 24 * 3600,
            rate_limit: 60,
            rate_limit_on_error: OnError::Closed,
            client_ip_header: None,
            // A constant, which `trusted_proxies_are_networks` parses.
            trusted_proxies: ip_nets("ALMENA_TRUSTED_PROXIES", DEFAULT_TRUSTED_PROXIES)
                .unwrap_or_default(),
            relay_rate_limit: 600,
            federation: true,
            outbound_allow_insecure: false,
            push: PushConfig::default(),
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Builds the configuration from any key lookup, so tests don't have to
    /// touch the process environment.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let default = Self::default();

        let host = match lookup("ALMENA_HOST") {
            Some(v) => v
                .parse()
                .with_context(|| format!("invalid ALMENA_HOST: {v}"))?,
            None => default.bind.ip(),
        };
        let port = match lookup("ALMENA_PORT") {
            Some(v) => v
                .parse()
                .with_context(|| format!("invalid ALMENA_PORT: {v}"))?,
            None => default.bind.port(),
        };
        let log_format = match lookup("ALMENA_LOG_FORMAT").as_deref() {
            None | Some("pretty") => LogFormat::Pretty,
            Some("json") => LogFormat::Json,
            Some(other) => {
                anyhow::bail!("invalid ALMENA_LOG_FORMAT: {other} (expected pretty or json)")
            }
        };

        let public_url = match lookup("ALMENA_PUBLIC_URL").filter(|v| !v.trim().is_empty()) {
            Some(url) => {
                let url = url.trim().trim_end_matches('/').to_owned();
                almena_didcomm::did::web::did_from_origin(&url)
                    .with_context(|| format!("invalid ALMENA_PUBLIC_URL: {url}"))?;
                Some(url)
            }
            None => None,
        };
        let access = match lookup("ALMENA_ACCESS").as_deref().map(str::trim) {
            None | Some("") => None,
            Some(value) => Some(Access::parse(value).with_context(|| {
                format!("invalid ALMENA_ACCESS: {value} (expected public or private)")
            })?),
        };
        let client_ip_header = match lookup("ALMENA_CLIENT_IP_HEADER") {
            Some(v) if v.trim().is_empty() => None,
            Some(v) => {
                let name = v.trim().to_ascii_lowercase();
                axum::http::HeaderName::from_str(&name)
                    .with_context(|| format!("invalid ALMENA_CLIENT_IP_HEADER: {v}"))?;
                Some(name)
            }
            None => None,
        };

        let config = Self {
            bind: SocketAddr::new(host, port),
            metrics_addr: match lookup("ALMENA_METRICS_ADDR").filter(|v| !v.trim().is_empty()) {
                Some(v) => Some(
                    v.trim()
                        .parse()
                        .with_context(|| format!("invalid ALMENA_METRICS_ADDR: {v}"))?,
                ),
                None => None,
            },
            log_format,
            public_url,
            access,
            admin_db_path: lookup("ALMENA_ADMIN_DB_PATH")
                .filter(|p| !p.trim().is_empty())
                .map_or(default.admin_db_path, PathBuf::from),
            keys_path: lookup("ALMENA_KEYS_PATH").map_or(default.keys_path, PathBuf::from),
            db_path: lookup("ALMENA_DB_PATH")
                .filter(|p| !p.trim().is_empty())
                .unwrap_or(default.db_path),
            max_message_bytes: positive(
                &lookup,
                "ALMENA_MAX_MESSAGE_BYTES",
                default.max_message_bytes,
            )?,
            queue_ttl_secs: positive(&lookup, "ALMENA_QUEUE_TTL", default.queue_ttl_secs)?,
            queue_max_messages: positive(
                &lookup,
                "ALMENA_QUEUE_MAX_MESSAGES",
                default.queue_max_messages,
            )?,
            queue_max_bytes: positive(&lookup, "ALMENA_QUEUE_MAX_BYTES", default.queue_max_bytes)?,
            max_recipient_dids: positive(
                &lookup,
                "ALMENA_MAX_RECIPIENT_DIDS",
                default.max_recipient_dids,
            )?,
            max_mediations: match lookup("ALMENA_MAX_MEDIATIONS") {
                Some(v) => v
                    .parse()
                    .with_context(|| format!("invalid ALMENA_MAX_MEDIATIONS: {v}"))?,
                None => default.max_mediations,
            },
            max_sockets: positive(&lookup, "ALMENA_MAX_SOCKETS", default.max_sockets)?,
            mediation_ttl_secs: match lookup("ALMENA_MEDIATION_TTL") {
                Some(v) => v
                    .parse()
                    .with_context(|| format!("invalid ALMENA_MEDIATION_TTL: {v}"))?,
                None => default.mediation_ttl_secs,
            },
            recipient_proof: match lookup("ALMENA_RECIPIENT_PROOF").as_deref().map(str::trim) {
                None | Some("required") => true,
                Some("off") => false,
                Some(other) => anyhow::bail!(
                    "invalid ALMENA_RECIPIENT_PROOF: {other} (expected required or off)"
                ),
            },
            rate_limit: match lookup("ALMENA_RATE_LIMIT") {
                Some(v) => v
                    .parse()
                    .with_context(|| format!("invalid ALMENA_RATE_LIMIT: {v}"))?,
                None => default.rate_limit,
            },
            rate_limit_on_error: match lookup("ALMENA_RATE_LIMIT_ON_ERROR")
                .as_deref()
                .map(str::trim)
            {
                None => default.rate_limit_on_error,
                Some("closed") => OnError::Closed,
                Some("open") => OnError::Open,
                Some(other) => anyhow::bail!(
                    "invalid ALMENA_RATE_LIMIT_ON_ERROR: {other} (expected closed or open)"
                ),
            },
            client_ip_header,
            trusted_proxies: match lookup("ALMENA_TRUSTED_PROXIES") {
                Some(v) => ip_nets("ALMENA_TRUSTED_PROXIES", &v)?,
                None => default.trusted_proxies,
            },
            relay_rate_limit: match lookup("ALMENA_RELAY_RATE_LIMIT") {
                Some(v) => v
                    .parse()
                    .with_context(|| format!("invalid ALMENA_RELAY_RATE_LIMIT: {v}"))?,
                None => default.relay_rate_limit,
            },
            federation: boolean(&lookup, "ALMENA_FEDERATION", default.federation)?,
            outbound_allow_insecure: boolean(
                &lookup,
                "ALMENA_OUTBOUND_ALLOW_INSECURE",
                default.outbound_allow_insecure,
            )?,
            push: push(&lookup, default.push)?,
        };
        anyhow::ensure!(
            config.queue_max_bytes >= config.max_message_bytes as u64,
            "ALMENA_QUEUE_MAX_BYTES ({}) is below ALMENA_MAX_MESSAGE_BYTES ({}): no message would fit",
            config.queue_max_bytes,
            config.max_message_bytes
        );
        Ok(config)
    }
}

fn push(lookup: &impl Fn(&str) -> Option<String>, default: PushConfig) -> Result<PushConfig> {
    let mode = match lookup("ALMENA_PUSH_MODE").as_deref().map(str::trim) {
        None | Some("off") => PushMode::Off,
        Some("direct") => PushMode::Direct,
        Some(other) => anyhow::bail!("invalid ALMENA_PUSH_MODE: {other} (expected off or direct)"),
    };
    let set = |key: &str| lookup(key).filter(|v| !v.trim().is_empty());
    let apns_keys = [
        "ALMENA_APNS_KEY_PATH",
        "ALMENA_APNS_KEY_ID",
        "ALMENA_APNS_TEAM_ID",
        "ALMENA_APNS_TOPIC",
    ];
    let apns = match apns_keys.map(set) {
        [Some(key_path), Some(key_id), Some(team_id), Some(topic)] => Some(ApnsConfig {
            key_path: PathBuf::from(key_path),
            key_id,
            team_id,
            topic,
            sandbox: boolean(lookup, "ALMENA_APNS_SANDBOX", false)?,
        }),
        [None, None, None, None] => None,
        _ => anyhow::bail!("APNs needs all of {}", apns_keys.join(", ")),
    };
    let push = PushConfig {
        mode,
        min_interval_secs: match lookup("ALMENA_PUSH_MIN_INTERVAL") {
            Some(v) => v
                .parse()
                .with_context(|| format!("invalid ALMENA_PUSH_MIN_INTERVAL: {v}"))?,
            None => default.min_interval_secs,
        },
        fcm_service_account: set("ALMENA_FCM_SERVICE_ACCOUNT").map(PathBuf::from),
        apns,
    };
    if push.mode == PushMode::Direct && push.fcm_service_account.is_none() && push.apns.is_none() {
        anyhow::bail!(
            "ALMENA_PUSH_MODE=direct needs ALMENA_FCM_SERVICE_ACCOUNT or the ALMENA_APNS_* settings"
        );
    }
    Ok(push)
}

/// `true`/`false` (also `1`/`0`), or `default` when unset.
fn boolean(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: bool) -> Result<bool> {
    match lookup(key).as_deref().map(str::trim) {
        None => Ok(default),
        Some("true" | "1") => Ok(true),
        Some("false" | "0") => Ok(false),
        Some(other) => anyhow::bail!("invalid {key}: {other} (expected true or false)"),
    }
}

/// A number above zero, or `default` when unset.
fn positive<T>(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: T) -> Result<T>
where
    T: FromStr + PartialOrd + Default,
{
    match lookup(key) {
        Some(v) => v
            .parse()
            .ok()
            .filter(|n: &T| *n > T::default())
            .with_context(|| format!("invalid {key}: {v} (expected a number above zero)")),
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn defaults_when_unset() {
        assert_eq!(Config::from_lookup(lookup(&[])).unwrap(), Config::default());
    }

    #[test]
    fn reads_overrides() {
        let config = Config::from_lookup(lookup(&[
            ("ALMENA_HOST", "127.0.0.1"),
            ("ALMENA_PORT", "9000"),
            ("ALMENA_METRICS_ADDR", "127.0.0.1:9090"),
            ("ALMENA_LOG_FORMAT", "json"),
            ("ALMENA_PUBLIC_URL", "https://mediator.example.com/"),
            ("ALMENA_KEYS_PATH", "/data/keys.json"),
            ("ALMENA_DB_PATH", "/data/mediator.db"),
            ("ALMENA_ADMIN_DB_PATH", "/data/admin.db"),
            ("ALMENA_ACCESS", "private"),
            ("ALMENA_MAX_MESSAGE_BYTES", "2048"),
            ("ALMENA_QUEUE_TTL", "60"),
            ("ALMENA_QUEUE_MAX_MESSAGES", "5"),
            ("ALMENA_QUEUE_MAX_BYTES", "4096"),
            ("ALMENA_MAX_RECIPIENT_DIDS", "7"),
            ("ALMENA_MAX_MEDIATIONS", "0"),
            ("ALMENA_MAX_SOCKETS", "200"),
            ("ALMENA_RECIPIENT_PROOF", "off"),
            ("ALMENA_MEDIATION_TTL", "0"),
            ("ALMENA_RATE_LIMIT", "0"),
            ("ALMENA_CLIENT_IP_HEADER", "X-Forwarded-For"),
            ("ALMENA_TRUSTED_PROXIES", "203.0.113.0/24, 2001:db8::1"),
            ("ALMENA_RATE_LIMIT_ON_ERROR", "open"),
            ("ALMENA_RELAY_RATE_LIMIT", "0"),
            ("ALMENA_FEDERATION", "false"),
            ("ALMENA_OUTBOUND_ALLOW_INSECURE", "1"),
        ]))
        .unwrap();
        assert_eq!(config.bind, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.metrics_addr, Some("127.0.0.1:9090".parse().unwrap()));
        assert_eq!(config.log_format, LogFormat::Json);
        assert_eq!(
            config.public_url.as_deref(),
            Some("https://mediator.example.com")
        );
        assert_eq!(config.access, Some(Access::Private));
        assert_eq!(config.admin_db_path, PathBuf::from("/data/admin.db"));
        assert_eq!(config.keys_path, PathBuf::from("/data/keys.json"));
        assert_eq!(config.db_path, "/data/mediator.db");
        assert_eq!(config.max_message_bytes, 2048);
        assert_eq!(config.queue_ttl_secs, 60);
        assert_eq!(config.queue_max_messages, 5);
        assert_eq!(config.queue_max_bytes, 4096);
        assert_eq!(config.max_recipient_dids, 7);
        assert_eq!(config.max_mediations, 0);
        assert_eq!(config.max_sockets, 200);
        assert!(!config.recipient_proof);
        assert_eq!(config.mediation_ttl_secs, 0);
        assert_eq!(config.rate_limit, 0);
        assert_eq!(config.client_ip_header.as_deref(), Some("x-forwarded-for"));
        assert_eq!(
            config.trusted_proxies,
            [
                "203.0.113.0/24".parse().unwrap(),
                "2001:db8::1/128".parse().unwrap()
            ]
        );
        assert_eq!(config.rate_limit_on_error, OnError::Open);
        assert_eq!(config.relay_rate_limit, 0);
        assert!(!config.federation);
        assert!(config.outbound_allow_insecure);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(Config::from_lookup(lookup(&[("ALMENA_PORT", "nope")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_LOG_FORMAT", "xml")])).is_err());
        assert!(
            Config::from_lookup(lookup(&[("ALMENA_PUBLIC_URL", "https://x.org/mediator")]))
                .is_err()
        );
        assert!(Config::from_lookup(lookup(&[("ALMENA_MAX_MESSAGE_BYTES", "0")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_ACCESS", "members")])).is_err());
        // Unset: the onboarding asks for both.
        let unset = Config::from_lookup(lookup(&[])).unwrap();
        assert_eq!((unset.public_url, unset.access), (None, None));
        assert!(Config::from_lookup(lookup(&[("ALMENA_QUEUE_TTL", "-1")])).is_err());
        // A queue smaller than one message.
        assert!(Config::from_lookup(lookup(&[("ALMENA_QUEUE_MAX_BYTES", "1000")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_CLIENT_IP_HEADER", "bad header")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_MAX_SOCKETS", "0")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_MAX_MEDIATIONS", "-1")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_TRUSTED_PROXIES", "10.0.0.0/33")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_TRUSTED_PROXIES", "proxy")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_RATE_LIMIT_ON_ERROR", "maybe")])).is_err());
    }

    #[test]
    fn trusted_proxies_are_networks() {
        let nets = ip_nets("ALMENA_TRUSTED_PROXIES", DEFAULT_TRUSTED_PROXIES).unwrap();
        let trusted = |ip: &str| nets.iter().any(|n| n.contains(ip.parse().unwrap()));
        for ip in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "172.18.0.5",
            "192.168.1.1",
            "fd12::1",
        ] {
            assert!(trusted(ip), "{ip}");
        }
        // Mapped addresses count as the IPv4 they carry.
        assert!(trusted("::ffff:172.18.0.5"));
        for ip in ["203.0.113.9", "172.32.0.1", "2001:db8::1", "::ffff:8.8.8.8"] {
            assert!(!trusted(ip), "{ip}");
        }
        let all: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        assert!(!all.contains("2001:db8::1".parse().unwrap()));
        // An empty setting trusts nobody.
        let none = Config::from_lookup(lookup(&[("ALMENA_TRUSTED_PROXIES", "")])).unwrap();
        assert!(none.trusted_proxies.is_empty());
    }

    #[test]
    fn reads_push_settings() {
        let config = Config::from_lookup(lookup(&[
            ("ALMENA_PUSH_MODE", "direct"),
            ("ALMENA_PUSH_MIN_INTERVAL", "30"),
            ("ALMENA_FCM_SERVICE_ACCOUNT", "/secrets/fcm.json"),
            ("ALMENA_APNS_KEY_PATH", "/secrets/apns.p8"),
            ("ALMENA_APNS_KEY_ID", "KEY1234567"),
            ("ALMENA_APNS_TEAM_ID", "TEAM123456"),
            ("ALMENA_APNS_TOPIC", "id.almena.wallet"),
            ("ALMENA_APNS_SANDBOX", "true"),
        ]))
        .unwrap();
        assert_eq!(config.push.mode, PushMode::Direct);
        assert_eq!(config.push.min_interval_secs, 30);
        assert_eq!(
            config.push.fcm_service_account,
            Some(PathBuf::from("/secrets/fcm.json"))
        );
        let apns = config.push.apns.unwrap();
        assert_eq!(apns.topic, "id.almena.wallet");
        assert!(apns.sandbox);
    }

    #[test]
    fn rejects_incomplete_push_settings() {
        assert!(Config::from_lookup(lookup(&[("ALMENA_PUSH_MODE", "gateway")])).is_err());
        // Direct mode with no credentials at all.
        assert!(Config::from_lookup(lookup(&[("ALMENA_PUSH_MODE", "direct")])).is_err());
        // Half an APNs configuration.
        assert!(
            Config::from_lookup(lookup(&[
                ("ALMENA_PUSH_MODE", "direct"),
                ("ALMENA_APNS_KEY_PATH", "/secrets/apns.p8"),
            ]))
            .is_err()
        );
    }
}
