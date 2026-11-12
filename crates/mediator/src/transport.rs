//! Outbound traffic to other mediators: fetching `did:web` documents and
//! `did:webvh` logs, and posting DIDComm messages.
//!
//! Every URL here comes from a DID document, i.e. from strangers, so the HTTP
//! client guards against SSRF: HTTPS only, no IP-literal hosts, and a DNS
//! resolver that drops private, loopback and link-local addresses — checked
//! at connect time, so DNS rebinding cannot slip past it. Redirects are
//! followed only when temporary (`307`), as the spec asks, and only to a URL
//! that passes the same checks. Documents are read up to
//! [`MAX_DOCUMENT_BYTES`].
//! `ALMENA_OUTBOUND_ALLOW_INSECURE` lifts all of this for local testing.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use almena_didcomm::did::web::document_url;
use almena_didcomm::did::{DidDocument, DidResolver, webvh};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::OnceCell;

/// What the mediator needs from the network.
#[async_trait]
pub trait Transport: Send + Sync {
    /// GETs a JSON document (a `did:web` DID document).
    async fn get_json(&self, url: &str) -> Result<serde_json::Value>;
    /// GETs a text document (a `did:webvh` log).
    async fn get_text(&self, url: &str) -> Result<String>;
    /// POSTs one DIDComm encrypted message; fails unless the answer is 2xx.
    async fn post_didcomm(&self, url: &str, message: &str) -> Result<()>;
}

/// The most a fetched DID document or `did:webvh` log may weigh.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// [`Transport`] over HTTPS.
pub struct HttpTransport {
    client: reqwest::Client,
    allow_insecure: bool,
}

impl HttpTransport {
    pub fn new(allow_insecure: bool) -> Result<Self> {
        // reqwest is built without a default crypto provider; rustls uses ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
        // A redirect target comes from the stranger too: held to the same
        // rules as the first URL (the DNS resolver alone does not see
        // IP-literal hosts).
        let redirect = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.status() != reqwest::StatusCode::TEMPORARY_REDIRECT
                || attempt.previous().len() >= 3
            {
                attempt.stop()
            } else if let Err(err) = guard(attempt.url(), allow_insecure) {
                attempt.error(err.to_string())
            } else {
                attempt.follow()
            }
        });
        let mut builder = reqwest::Client::builder()
            .user_agent(format!("almena-mediator/{}", crate::VERSION))
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .redirect(redirect);
        if !allow_insecure {
            builder = builder.https_only(true).dns_resolver(PublicOnlyResolver);
        }
        Ok(Self {
            client: builder.build().context("building the HTTP client")?,
            allow_insecure,
        })
    }

    fn check(&self, url: &str) -> Result<reqwest::Url> {
        let url = reqwest::Url::parse(url).with_context(|| format!("invalid URL {url}"))?;
        guard(&url, self.allow_insecure)?;
        Ok(url)
    }

    /// GETs `url`, its body read up to [`MAX_DOCUMENT_BYTES`].
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        let url = self.check(url)?;
        let mut response = self
            .client
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_DOCUMENT_BYTES as u64)
        {
            bail!("{url} is larger than {MAX_DOCUMENT_BYTES} bytes");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .with_context(|| format!("reading {url}"))?
        {
            ensure!(
                body.len() + chunk.len() <= MAX_DOCUMENT_BYTES,
                "{url} is larger than {MAX_DOCUMENT_BYTES} bytes"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

/// The rules every outbound URL is held to (SPEC.md §6.8): `https` and a
/// domain name, unless `allow_insecure`.
fn guard(url: &reqwest::Url, allow_insecure: bool) -> Result<()> {
    if allow_insecure {
        ensure!(
            matches!(url.scheme(), "https" | "http"),
            "unsupported scheme in {url}"
        );
        return Ok(());
    }
    ensure!(
        url.scheme() == "https",
        "only https URLs are allowed: {url}"
    );
    match url.host() {
        Some(url::Host::Domain(_)) => Ok(()),
        Some(_) => bail!("IP-literal hosts are not allowed: {url}"),
        None => bail!("URL without host: {url}"),
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn get_json(&self, url: &str) -> Result<serde_json::Value> {
        let body = self.get(url).await?;
        serde_json::from_slice(&body).with_context(|| format!("reading JSON from {url}"))
    }

    async fn get_text(&self, url: &str) -> Result<String> {
        let body = self.get(url).await?;
        String::from_utf8(body).with_context(|| format!("{url} is not UTF-8"))
    }

    async fn post_didcomm(&self, url: &str, message: &str) -> Result<()> {
        let url = self.check(url)?;
        let response = self
            .client
            .post(url.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/didcomm-encrypted+json",
            )
            .body(message.to_owned())
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "{url} answered {}",
            response.status()
        );
        Ok(())
    }
}

/// Resolves names like the system does, keeping only public addresses.
pub(crate) struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| is_public(addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} has no public address").into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Whether `ip` is a globally routable unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || a >= 240 // reserved (240.0.0.0/4)
                || (a == 100 && (64..128).contains(&b)) // carrier-grade NAT
                || (a == 192 && b == 0 && v4.octets()[2] == 0) // IETF protocol assignments
                || (a == 198 && (18..20).contains(&b))) // benchmarking
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            let first = segments[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || segments[..6] == [0; 6] // IPv4-compatible (::a.b.c.d, deprecated)
                || segments[..4] == [0x0100, 0, 0, 0] // discard-only (100::/64)
                || (first & 0xfe00) == 0xfc00 // unique local
                || (first & 0xffc0) == 0xfe80 // link local
                || (first & 0xffc0) == 0xfec0 // site local (deprecated)
                || first == 0x2001 && segments[1] == 0 // Teredo: tunnels to any IPv4
                || first == 0x2001 && v6.segments()[1] == 0x0db8 // documentation
                || first == 0x2002 // 6to4: tunnels to any IPv4, private ones too
                || v6.segments()[..2] == [0x64, 0xff9b]) // NAT64 (64:ff9b::/96, 64:ff9b:1::/48)
        }
    }
}

/// Resolves `did:web` DIDs (their `did.json`) and `did:webvh` DIDs (their
/// log, walked from the first entry: [`webvh::resolve`]) over a
/// [`Transport`], caching documents for a few minutes. The Almena registry's
/// issuers, verifiers and tenants are `did:webvh`: they authcrypt to the
/// mediator and are registered as recipients under that DID.
///
/// The cache keeps the [`WebResolver::CAPACITY`] DIDs used most recently;
/// requests that miss on the same DID at the same time share one fetch.
pub struct WebResolver {
    transport: Arc<dyn Transport>,
    cache: Mutex<Cache>,
    /// Fetches under way, by DID: whoever misses on one waits for it.
    fetching: Mutex<HashMap<String, Arc<OnceCell<Resolved>>>>,
}

/// A DID's document, or why it could not be had.
type Resolved = almena_didcomm::Result<DidDocument>;

/// What each DID resolved to, or why it did not, and when; the least
/// recently used goes first when it is full.
#[derive(Default)]
struct Cache {
    entries: HashMap<String, Cached>,
    /// Bumped on every use: an entry's `used` orders it.
    clock: u64,
}

struct Cached {
    result: Resolved,
    at: Instant,
    used: u64,
}

impl Cached {
    fn fresh(&self) -> bool {
        let ttl = if self.result.is_ok() {
            WebResolver::TTL
        } else {
            WebResolver::FAILURE_TTL
        };
        self.at.elapsed() < ttl
    }
}

impl Cache {
    fn get(&mut self, did: &str) -> Option<Resolved> {
        self.clock += 1;
        let clock = self.clock;
        let entry = self.entries.get_mut(did)?;
        if !entry.fresh() {
            self.entries.remove(did);
            return None;
        }
        entry.used = clock;
        Some(entry.result.clone())
    }

    /// Keeps `result` for `did`; when full, expired entries go first, then
    /// the one used longest ago.
    fn put(&mut self, did: &str, result: Resolved, capacity: usize) {
        if !self.entries.contains_key(did) && self.entries.len() >= capacity {
            self.entries.retain(|_, entry| entry.fresh());
            if self.entries.len() >= capacity
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.used)
                    .map(|(did, _)| did.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.clock += 1;
        self.entries.insert(
            did.to_owned(),
            Cached {
                result,
                at: Instant::now(),
                used: self.clock,
            },
        );
    }
}

/// Removes a fetch from [`WebResolver::fetching`] when dropped, if it is
/// still the one there and nobody else is waiting for it (the map's clone and
/// this one's are all that is left).
struct Unregister<'a> {
    fetching: &'a Mutex<HashMap<String, Arc<OnceCell<Resolved>>>>,
    did: &'a str,
    cell: &'a Arc<OnceCell<Resolved>>,
}

impl Drop for Unregister<'_> {
    fn drop(&mut self) {
        if let Ok(mut fetching) = self.fetching.lock()
            && fetching
                .get(self.did)
                .is_some_and(|current| Arc::ptr_eq(current, self.cell))
            && (self.cell.initialized() || Arc::strong_count(self.cell) <= 2)
        {
            fetching.remove(self.did);
        }
    }
}

impl WebResolver {
    const TTL: Duration = Duration::from_secs(300);
    /// A DID that failed is not fetched again for this long: a message
    /// naming the same unreachable DID many times costs one fetch.
    const FAILURE_TTL: Duration = Duration::from_secs(60);
    const CAPACITY: usize = 1_000;

    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            cache: Mutex::new(Cache::default()),
            fetching: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, did: &str) -> Option<Resolved> {
        self.cache.lock().ok()?.get(did)
    }

    /// Fetches `did` once however many ask at the same time, and caches
    /// what came of it.
    async fn fetch_shared(&self, did: &str, web: bool) -> Resolved {
        let cell = match self.fetching.lock() {
            Ok(mut fetching) => Arc::clone(fetching.entry(did.to_owned()).or_default()),
            // A poisoned map only loses the sharing.
            Err(_) => Arc::new(OnceCell::new()),
        };
        // Taken off the map however this ends — also when whoever asked goes
        // away mid-fetch and this future is dropped, or the map would keep
        // one entry per DID a stranger made up.
        let _unregister = Unregister {
            fetching: &self.fetching,
            did,
            cell: &cell,
        };
        cell.get_or_init(|| async {
            let result = self.fetch(did, web).await;
            if let Ok(mut cache) = self.cache.lock() {
                cache.put(did, result.clone(), Self::CAPACITY);
            }
            result
        })
        .await
        .clone()
    }

    async fn fetch(&self, did: &str, web: bool) -> almena_didcomm::Result<DidDocument> {
        use almena_didcomm::Error;
        let fetched = |err: anyhow::Error| Error::Resolver(format!("{did}: {err:#}"));
        let (url, doc) = if web {
            let url = document_url(did)?;
            let json = self.transport.get_json(&url).await.map_err(fetched)?;
            let doc = DidDocument::from_json(&json)?;
            (url, doc)
        } else {
            let url = webvh::log_url(did)?;
            let log = self.transport.get_text(&url).await.map_err(fetched)?;
            (url, webvh::resolve(&log, did)?)
        };
        if doc.id != did {
            return Err(Error::Resolver(format!(
                "{url} holds the document of {}",
                doc.id
            )));
        }
        Ok(doc)
    }
}

#[async_trait]
impl DidResolver for WebResolver {
    async fn resolve(&self, did: &str) -> almena_didcomm::Result<DidDocument> {
        use almena_didcomm::Error;
        let web = did.starts_with("did:web:");
        if !web && !did.starts_with("did:webvh:") {
            return Err(Error::DidNotFound(did.to_owned()));
        }
        match self.cached(did) {
            Some(cached) => cached,
            None => self.fetch_shared(did, web).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_pass() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "192.0.0.170",
            "240.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::1",
            "::7f00:1",
            "::a00:1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "fec0::1",
            "100::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn urls_are_checked() {
        let strict = HttpTransport::new(false).unwrap();
        assert!(strict.check("https://mediator.example.com/didcomm").is_ok());
        assert!(strict.check("http://mediator.example.com/didcomm").is_err());
        assert!(strict.check("https://169.254.169.254/latest").is_err());
        assert!(strict.check("https://[::1]/x").is_err());
        assert!(guard(&"https://10.0.0.5/x".parse().unwrap(), false).is_err());
        assert!(guard(&"https://did.example/x".parse().unwrap(), false).is_ok());
        let insecure = HttpTransport::new(true).unwrap();
        assert!(insecure.check("http://localhost:8080/didcomm").is_ok());
        assert!(insecure.check("ftp://localhost/x").is_err());
    }

    #[tokio::test]
    async fn the_resolver_refuses_private_names() {
        use std::str::FromStr;
        let err = PublicOnlyResolver
            .resolve(Name::from_str("localhost").unwrap())
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("no public address"));
    }

    /// Serves one `did:webvh` log, a log the registry wrote, and counts reads.
    struct Registry(std::sync::atomic::AtomicUsize);

    const REGISTRY_LOG: &str = include_str!("../../didcomm/tests/webvh/registry-did.jsonl");
    const REGISTRY_DID: &str =
        "did:webvh:QmQi5rPBEy17S5sNgnpM8dFZdSdqrbt3JF4t2G1bDP9kn1:almena.id:ids:idn_club";

    #[async_trait]
    impl Transport for Registry {
        async fn get_json(&self, url: &str) -> Result<serde_json::Value> {
            bail!("not found: {url}")
        }

        async fn get_text(&self, url: &str) -> Result<String> {
            ensure!(
                url == "https://almena.id/ids/idn_club/did.jsonl",
                "not found: {url}"
            );
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Long enough for concurrent misses to overlap.
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(REGISTRY_LOG.to_owned())
        }

        async fn post_didcomm(&self, url: &str, _: &str) -> Result<()> {
            bail!("not found: {url}")
        }
    }

    #[tokio::test]
    async fn registry_dids_resolve_by_walking_their_log() {
        let registry = Arc::new(Registry(0.into()));
        let resolver = WebResolver::new(registry.clone());
        let doc = resolver.resolve(REGISTRY_DID).await.unwrap();
        assert_eq!(doc.id, REGISTRY_DID);
        resolver.resolve(REGISTRY_DID).await.unwrap();
        assert_eq!(registry.0.load(std::sync::atomic::Ordering::SeqCst), 1);

        // A DID whose SCID the log does not hash to; one with no log.
        let forged = REGISTRY_DID.replace("QmQi5", "QmQi6");
        assert!(resolver.resolve(&forged).await.is_err());
        let missing =
            "did:webvh:QmQi5rPBEy17S5sNgnpM8dFZdSdqrbt3JF4t2G1bDP9kn1:almena.id:ids:idn_x";
        assert!(resolver.resolve(missing).await.is_err());
        // A failure is remembered too: asking again fetches nothing.
        let fetches = registry.0.load(std::sync::atomic::Ordering::SeqCst);
        assert!(resolver.resolve(&forged).await.is_err());
        assert_eq!(
            registry.0.load(std::sync::atomic::Ordering::SeqCst),
            fetches
        );
        assert!(matches!(
            resolver.resolve("did:example:1").await,
            Err(almena_didcomm::Error::DidNotFound(_))
        ));
    }

    #[tokio::test]
    async fn a_fetch_given_up_leaves_nothing_behind() {
        let resolver = WebResolver::new(Arc::new(Registry(0.into())));
        // Whoever asked goes away before the log arrives.
        let gave_up =
            tokio::time::timeout(Duration::from_millis(5), resolver.resolve(REGISTRY_DID)).await;
        assert!(gave_up.is_err());
        assert!(resolver.fetching.lock().unwrap().is_empty());
        resolver.resolve(REGISTRY_DID).await.unwrap();
        assert!(resolver.fetching.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn concurrent_misses_on_one_did_share_a_fetch() {
        let registry = Arc::new(Registry(0.into()));
        let resolver = WebResolver::new(registry.clone());
        let all =
            futures_util::future::join_all((0..8).map(|_| resolver.resolve(REGISTRY_DID))).await;
        assert!(
            all.iter()
                .all(|doc| doc.as_ref().unwrap().id == REGISTRY_DID)
        );
        assert_eq!(registry.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(resolver.fetching.lock().unwrap().is_empty());
    }

    #[test]
    fn the_cache_drops_the_least_recently_used() {
        let failed = || Err(almena_didcomm::Error::Resolver("down".into()));
        let mut cache = Cache::default();
        cache.put("did:web:a", failed(), 2);
        cache.put("did:web:b", failed(), 2);
        // `a` used last: `b` is the one to go.
        assert!(cache.get("did:web:a").is_some());
        cache.put("did:web:c", failed(), 2);
        assert!(cache.get("did:web:b").is_none());
        assert!(cache.get("did:web:a").is_some());
        assert!(cache.get("did:web:c").is_some());
        // Replacing an entry evicts nothing.
        cache.put("did:web:c", failed(), 2);
        assert_eq!(cache.entries.len(), 2);
    }
}
