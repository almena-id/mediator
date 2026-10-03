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
struct PublicOnlyResolver;

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
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00 // unique local
                || (first & 0xffc0) == 0xfe80 // link local
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
pub struct WebResolver {
    transport: Arc<dyn Transport>,
    /// What each DID resolved to, or why it did not, and when.
    cache: Mutex<HashMap<String, (Resolved, Instant)>>,
}

/// A DID's document, or why it could not be had.
type Resolved = Result<DidDocument, String>;

impl WebResolver {
    const TTL: Duration = Duration::from_secs(300);
    /// A DID that failed is not fetched again for this long: a message
    /// naming the same unreachable DID many times costs one fetch.
    const FAILURE_TTL: Duration = Duration::from_secs(60);
    const CAPACITY: usize = 1_000;

    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, did: &str) -> Option<Resolved> {
        let cache = self.cache.lock().ok()?;
        let (result, at) = cache.get(did)?;
        let ttl = if result.is_ok() {
            Self::TTL
        } else {
            Self::FAILURE_TTL
        };
        (at.elapsed() < ttl).then(|| result.clone())
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
        if let Some(cached) = self.cached(did) {
            return cached.map_err(Error::Resolver);
        }
        let result = self.fetch(did, web).await;
        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() >= Self::CAPACITY {
                cache.clear();
            }
            let kept = result
                .as_ref()
                .map(Clone::clone)
                .map_err(ToString::to_string);
            cache.insert(did.to_owned(), (kept, Instant::now()));
        }
        result
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
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
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
}
