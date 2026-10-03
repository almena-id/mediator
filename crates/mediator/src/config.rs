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
    /// and its DIDComm endpoint is `<origin>/didcomm`.
    pub public_url: String,
    /// JSON file holding the mediator's private keys (`ALMENA_KEYS_PATH`);
    /// created with fresh keys on first start.
    pub keys_path: PathBuf,
    /// Redis connection URL (`ALMENA_REDIS_URL`). `memory://` keeps
    /// everything in the process instead: development only.
    pub redis_url: String,
    /// Redis password (`ALMENA_REDIS_PASSWORD`); unset or empty: none.
    pub redis_password: Option<Secret>,
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
    /// A mediation whose wallet sends nothing for this many seconds is removed
    /// with everything it owns; 0 keeps them forever (`ALMENA_MEDIATION_TTL`).
    pub mediation_ttl_secs: u64,
    /// Registering someone else's DID needs a possession proof
    /// (`ALMENA_RECIPIENT_PROOF`: `required` or `off`).
    pub recipient_proof: bool,
    /// `POST /didcomm` requests per minute per client IP; 0 turns the limit
    /// off (`ALMENA_RATE_LIMIT`).
    pub rate_limit: u64,
    /// Header holding the client IP when the mediator runs behind a reverse
    /// proxy, e.g. `x-forwarded-for` (`ALMENA_CLIENT_IP_HEADER`). Its last
    /// value is used: the one the proxy added. Unset: the peer address.
    pub client_ip_header: Option<String>,
    /// Relay `forward`s for recipients mediated elsewhere to their mediator, and
    /// resolve other mediators' `did:web` over HTTPS (`ALMENA_FEDERATION`).
    pub federation: bool,
    /// Let outbound requests use plain HTTP and private addresses — local
    /// multi-mediator testing only (`ALMENA_OUTBOUND_ALLOW_INSECURE`).
    pub outbound_allow_insecure: bool,
    /// Push wake-ups (`ALMENA_PUSH_*`, `ALMENA_FCM_*`, `ALMENA_APNS_*`).
    pub push: PushConfig,
    /// TURN credentials for wallets' calls (`ALMENA_TURN_*`); `None`: off.
    pub turn: Option<TurnConfig>,
}

/// The TURN server run beside the mediator (SPEC.md §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnConfig {
    /// `turn:`/`turns:` URIs given to wallets, comma-separated
    /// (`ALMENA_TURN_URLS`).
    pub urls: Vec<String>,
    /// Secret shared with the TURN server, coturn's `static-auth-secret`
    /// (`ALMENA_TURN_SECRET`).
    pub secret: Secret,
    /// Seconds the credentials are valid (`ALMENA_TURN_TTL`).
    pub ttl_secs: u64,
}

/// A value kept out of logs: `Debug` prints `<redacted>`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushConfig {
    /// `ALMENA_PUSH_MODE`: `off` or `direct` (the mediator calls FCM and
    /// APNs with the wallet app's credentials).
    pub mode: PushMode,
    /// Least seconds between two pushes to one mediation
    /// (`ALMENA_PUSH_MIN_INTERVAL`).
    pub min_interval_secs: u64,
    /// Least seconds between two call rings to one mediation
    /// (`ALMENA_PUSH_RING_INTERVAL`).
    pub ring_interval_secs: u64,
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
            ring_interval_secs: 5,
            fcm_service_account: None,
            apns: None,
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
            public_url: "http://localhost:8080".to_owned(),
            keys_path: PathBuf::from("data/keys.json"),
            redis_url: "redis://localhost:6379".to_owned(),
            redis_password: None,
            max_message_bytes: 1024 * 1024,
            queue_ttl_secs: 30 * 24 * 3600,
            queue_max_messages: 10_000,
            queue_max_bytes: 100 * 1024 * 1024,
            max_recipient_dids: 100,
            recipient_proof: true,
            mediation_ttl_secs: 90 * 24 * 3600,
            rate_limit: 60,
            client_ip_header: None,
            federation: true,
            outbound_allow_insecure: false,
            push: PushConfig::default(),
            turn: None,
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

        let public_url = lookup("ALMENA_PUBLIC_URL").unwrap_or(default.public_url);
        let public_url = public_url.trim_end_matches('/').to_owned();
        almena_didcomm::did::web::did_from_origin(&public_url)
            .with_context(|| format!("invalid ALMENA_PUBLIC_URL: {public_url}"))?;
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
            keys_path: lookup("ALMENA_KEYS_PATH").map_or(default.keys_path, PathBuf::from),
            redis_url: lookup("ALMENA_REDIS_URL").unwrap_or(default.redis_url),
            redis_password: lookup("ALMENA_REDIS_PASSWORD")
                .filter(|p| !p.is_empty())
                .map(Secret),
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
            client_ip_header,
            federation: boolean(&lookup, "ALMENA_FEDERATION", default.federation)?,
            outbound_allow_insecure: boolean(
                &lookup,
                "ALMENA_OUTBOUND_ALLOW_INSECURE",
                default.outbound_allow_insecure,
            )?,
            push: push(&lookup, default.push)?,
            turn: turn(&lookup)?,
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
        ring_interval_secs: match lookup("ALMENA_PUSH_RING_INTERVAL") {
            Some(v) => v
                .parse()
                .with_context(|| format!("invalid ALMENA_PUSH_RING_INTERVAL: {v}"))?,
            None => default.ring_interval_secs,
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

/// Credentials last a day by default, the TURN REST API's suggestion: coturn
/// checks them again on every refresh, so they must outlast the longest call.
const TURN_TTL: u64 = 24 * 3600;

fn turn(lookup: &impl Fn(&str) -> Option<String>) -> Result<Option<TurnConfig>> {
    let set = |key: &str| lookup(key).filter(|v| !v.trim().is_empty());
    let (urls, secret) = match (set("ALMENA_TURN_URLS"), set("ALMENA_TURN_SECRET")) {
        (None, None) => return Ok(None),
        (Some(urls), Some(secret)) => (urls, secret),
        (Some(_), None) => anyhow::bail!(
            "ALMENA_TURN_URLS is set but ALMENA_TURN_SECRET is empty: generate one with \
             `openssl rand -hex 32`, set it in .env for both the mediator and coturn, or \
             empty ALMENA_TURN_URLS to turn TURN off"
        ),
        (None, Some(_)) => anyhow::bail!(
            "ALMENA_TURN_SECRET is set but ALMENA_TURN_URLS is empty: list the turn: URIs \
             wallets reach coturn at, or empty ALMENA_TURN_SECRET to turn TURN off"
        ),
    };
    let urls: Vec<String> = urls
        .split(',')
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_owned)
        .collect();
    for url in &urls {
        anyhow::ensure!(
            (url.starts_with("turn:") || url.starts_with("turns:"))
                && !url.contains(char::is_whitespace),
            "invalid ALMENA_TURN_URLS entry: {url} (expected turn: or turns: URIs)"
        );
    }
    anyhow::ensure!(!urls.is_empty(), "ALMENA_TURN_URLS lists no URI");
    Ok(Some(TurnConfig {
        urls,
        secret: Secret(secret),
        ttl_secs: positive(lookup, "ALMENA_TURN_TTL", TURN_TTL)?,
    }))
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
            ("ALMENA_REDIS_URL", "redis://redis:6379"),
            ("ALMENA_REDIS_PASSWORD", "s3cret"),
            ("ALMENA_MAX_MESSAGE_BYTES", "2048"),
            ("ALMENA_QUEUE_TTL", "60"),
            ("ALMENA_QUEUE_MAX_MESSAGES", "5"),
            ("ALMENA_QUEUE_MAX_BYTES", "4096"),
            ("ALMENA_MAX_RECIPIENT_DIDS", "7"),
            ("ALMENA_RECIPIENT_PROOF", "off"),
            ("ALMENA_MEDIATION_TTL", "0"),
            ("ALMENA_RATE_LIMIT", "0"),
            ("ALMENA_CLIENT_IP_HEADER", "X-Forwarded-For"),
            ("ALMENA_FEDERATION", "false"),
            ("ALMENA_OUTBOUND_ALLOW_INSECURE", "1"),
        ]))
        .unwrap();
        assert_eq!(config.bind, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.metrics_addr, Some("127.0.0.1:9090".parse().unwrap()));
        assert_eq!(config.log_format, LogFormat::Json);
        assert_eq!(config.public_url, "https://mediator.example.com");
        assert_eq!(config.keys_path, PathBuf::from("/data/keys.json"));
        assert_eq!(config.redis_url, "redis://redis:6379");
        assert_eq!(config.redis_password, Some(Secret("s3cret".into())));
        assert!(!format!("{config:?}").contains("s3cret"));
        assert_eq!(config.max_message_bytes, 2048);
        assert_eq!(config.queue_ttl_secs, 60);
        assert_eq!(config.queue_max_messages, 5);
        assert_eq!(config.queue_max_bytes, 4096);
        assert_eq!(config.max_recipient_dids, 7);
        assert!(!config.recipient_proof);
        assert_eq!(config.mediation_ttl_secs, 0);
        assert_eq!(config.rate_limit, 0);
        assert_eq!(config.client_ip_header.as_deref(), Some("x-forwarded-for"));
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
        assert!(Config::from_lookup(lookup(&[("ALMENA_QUEUE_TTL", "-1")])).is_err());
        // A queue smaller than one message.
        assert!(Config::from_lookup(lookup(&[("ALMENA_QUEUE_MAX_BYTES", "1000")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_CLIENT_IP_HEADER", "bad header")])).is_err());
    }

    #[test]
    fn reads_push_settings() {
        let config = Config::from_lookup(lookup(&[
            ("ALMENA_PUSH_MODE", "direct"),
            ("ALMENA_PUSH_MIN_INTERVAL", "30"),
            ("ALMENA_PUSH_RING_INTERVAL", "10"),
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
        assert_eq!(config.push.ring_interval_secs, 10);
        assert_eq!(
            config.push.fcm_service_account,
            Some(PathBuf::from("/secrets/fcm.json"))
        );
        let apns = config.push.apns.unwrap();
        assert_eq!(apns.topic, "id.almena.wallet");
        assert!(apns.sandbox);
    }

    #[test]
    fn reads_turn_settings() {
        let config = Config::from_lookup(lookup(&[
            (
                "ALMENA_TURN_URLS",
                "turn:t.example.com:3478?transport=udp, turn:t.example.com:3478?transport=tcp",
            ),
            ("ALMENA_TURN_SECRET", "sh4red"),
            ("ALMENA_TURN_TTL", "600"),
        ]))
        .unwrap();
        let turn = config.turn.as_ref().unwrap();
        assert_eq!(
            turn.urls,
            [
                "turn:t.example.com:3478?transport=udp",
                "turn:t.example.com:3478?transport=tcp"
            ]
        );
        assert_eq!(turn.ttl_secs, 600);
        assert!(!format!("{config:?}").contains("sh4red"));
        let default_ttl = Config::from_lookup(lookup(&[
            ("ALMENA_TURN_URLS", "turns:t.example.com"),
            ("ALMENA_TURN_SECRET", "s"),
        ]))
        .unwrap();
        assert_eq!(default_ttl.turn.unwrap().ttl_secs, TURN_TTL);
    }

    #[test]
    fn rejects_bad_turn_settings() {
        let bad = |pairs: &[(&str, &str)]| Config::from_lookup(lookup(pairs)).is_err();
        assert!(bad(&[("ALMENA_TURN_URLS", "turn:t.example.com")]));
        assert!(bad(&[("ALMENA_TURN_SECRET", "s")]));
        assert!(bad(&[
            ("ALMENA_TURN_URLS", "stun:t.example.com"),
            ("ALMENA_TURN_SECRET", "s")
        ]));
        assert!(bad(&[
            ("ALMENA_TURN_URLS", " , "),
            ("ALMENA_TURN_SECRET", "s")
        ]));
        assert!(bad(&[
            ("ALMENA_TURN_URLS", "turn:t.example.com"),
            ("ALMENA_TURN_SECRET", "s"),
            ("ALMENA_TURN_TTL", "0")
        ]));
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
