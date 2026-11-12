//! Push wake-ups (SPEC.md §6.4).
//!
//! When a message is queued for a mediation that has no live WebSocket
//! session, the devices the wallet registered get a push that carries
//! nothing but "something is waiting" (`{"type": "almena.wake"}`); the app
//! then connects and picks up. At most one push goes out per mediation until
//! the wallet picks up, and never two closer than the minimum interval.
//!
//! The mediator calls FCM and APNs itself (`ALMENA_PUSH_MODE=direct`), with
//! the credentials of the wallet app: only mediators run by the app's
//! publisher can do this.

mod apns;
mod fcm;
mod jwt;

use std::time::Duration;

use almena_didcomm::message::now;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use self::apns::{Apns, ApnsConfig};
pub use self::fcm::Fcm;
use crate::metrics::{METRICS, Push};
use crate::store::Store;

/// The `type` of every push payload, and the tag that collapses one
/// notification into the next.
pub const WAKE: &str = "almena.wake";

/// The keys of the notification's title and text in the wallet app's own
/// strings (Android string resources, iOS `Localizable.strings`), so the device
/// says it in its own language and the mediator never writes a word of it.
/// Nothing in the notification is about the message: no sender, no recipient
/// DID, no count.
pub const TITLE_KEY: &str = "almena_wake_title";
pub const BODY_KEY: &str = "almena_wake_body";

/// A push service a device token belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Service {
    Fcm,
    Apns,
}

impl Service {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fcm => "fcm",
            Self::Apns => "apns",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "fcm" => Some(Self::Fcm),
            "apns" => Some(Self::Apns),
            _ => None,
        }
    }
}

/// A device registered for wake-ups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub token: String,
    /// `device_platform` of the FCM protocol (e.g. `android`); none for APNs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

/// What a push service said about one push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    Delivered,
    /// The token is no longer valid; it should be forgotten.
    InvalidToken,
}

/// Sends wake-ups.
#[async_trait]
pub trait Pusher: Send + Sync {
    /// The push protocols this pusher can send through.
    fn services(&self) -> &[Service];
    /// Sends one wake-up to `token`.
    async fn wake(&self, service: Service, token: &str) -> Result<Sent>;
}

/// [`Pusher`] that calls FCM and APNs directly.
pub struct DirectPusher {
    fcm: Option<Fcm>,
    apns: Option<Apns>,
    services: Vec<Service>,
}

impl DirectPusher {
    pub fn new(fcm: Option<Fcm>, apns: Option<Apns>) -> Self {
        let services = [
            fcm.as_ref().map(|_| Service::Fcm),
            apns.as_ref().map(|_| Service::Apns),
        ]
        .into_iter()
        .flatten()
        .collect();
        Self {
            fcm,
            apns,
            services,
        }
    }
}

#[async_trait]
impl Pusher for DirectPusher {
    fn services(&self) -> &[Service] {
        &self.services
    }

    async fn wake(&self, service: Service, token: &str) -> Result<Sent> {
        match (service, &self.fcm, &self.apns) {
            (Service::Fcm, Some(fcm), _) => fcm.wake(token).await,
            (Service::Apns, _, Some(apns)) => apns.wake(token).await,
            _ => anyhow::bail!("{} is not configured", service.as_str()),
        }
    }
}

/// Counts and logs what `service` said about one push to `device`, and
/// forgets the token when it is no longer valid. `true` if it was delivered.
async fn settle(
    store: &dyn Store,
    mediation: &str,
    service: Service,
    device: &Device,
    sent: Result<Sent>,
) -> Result<bool> {
    let count = |push| METRICS.push(service, push);
    let service_name = service.as_str();
    match sent {
        Ok(Sent::Delivered) => {
            tracing::debug!(%mediation, service = service_name, "push sent");
            count(Push::Delivered);
            Ok(true)
        }
        Ok(Sent::InvalidToken) => {
            count(Push::InvalidToken);
            tracing::info!(%mediation, service = service_name, "push token rejected, removed");
            store
                .remove_device(mediation, service, &device.token)
                .await?;
            Ok(false)
        }
        Err(err) => {
            count(Push::Failed);
            tracing::warn!(%mediation, service = service_name, error = %format!("{err:#}"), "push failed");
            Ok(false)
        }
    }
}

/// Wakes `mediation`'s devices unless a push already went out since the
/// wallet last picked up. The marker of a sent push lasts at most
/// `hold_secs`; when no device was reached it is let go after
/// `retry_secs`, so one failed send does not silence the wallet until it
/// picks up. Tokens the service rejects are forgotten.
pub async fn wake(
    store: &dyn Store,
    pusher: &dyn Pusher,
    mediation: &str,
    hold_secs: u64,
    retry_secs: u64,
) -> Result<()> {
    let devices = offered(store, pusher, mediation).await?;
    if devices.is_empty() || !store.claim_push(mediation, now(), hold_secs).await? {
        return Ok(());
    }
    let mut reached = false;
    for (service, device) in devices {
        let sent = pusher.wake(service, &device.token).await;
        reached |= settle(store, mediation, service, &device, sent).await?;
    }
    if !reached {
        store.release_push(mediation, now(), retry_secs).await?;
    }
    Ok(())
}

/// The mediation's devices whose push protocol `pusher` can send through.
async fn offered(
    store: &dyn Store,
    pusher: &dyn Pusher,
    mediation: &str,
) -> Result<Vec<(Service, Device)>> {
    Ok(store
        .devices(mediation)
        .await?
        .into_iter()
        .filter(|(service, _)| pusher.services().contains(service))
        .collect())
}

/// HTTP client for FCM and APNs (HTTP/2 is negotiated with APNs).
fn http_client() -> Result<reqwest::Client> {
    // reqwest is built without a default crypto provider; rustls uses ring.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(format!("almena-mediator/{}", crate::VERSION))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .context("building the push HTTP client")
}

/// DER of the PKCS#8 private key in a PEM file's text.
fn pkcs8_der(pem: &str) -> Result<Vec<u8>> {
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use rustls_pki_types::pem::PemObject;
    let key = PrivatePkcs8KeyDer::from_pem_slice(pem.as_bytes())
        .context("expected a PKCS#8 private key (-----BEGIN PRIVATE KEY-----)")?;
    Ok(key.secret_pkcs8_der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A pusher whose service is down until told otherwise.
    struct Down(AtomicBool);

    #[async_trait]
    impl Pusher for Down {
        fn services(&self) -> &[Service] {
            &[Service::Fcm]
        }

        async fn wake(&self, _: Service, _: &str) -> Result<Sent> {
            if self.0.load(Ordering::SeqCst) {
                anyhow::bail!("FCM answered 503")
            }
            Ok(Sent::Delivered)
        }
    }

    #[tokio::test]
    async fn a_failed_push_does_not_silence_the_wallet() {
        let store = SqliteStore::memory().unwrap();
        let device = Device {
            token: "token".into(),
            platform: Some("android".into()),
        };
        store
            .set_device("did:m", Service::Fcm, Some(&device))
            .await
            .unwrap();
        let pusher = Down(true.into());
        wake(&store, &pusher, "did:m", 3600, 0).await.unwrap();
        // Nothing reached the device: the next message may wake it again.
        assert!(store.claim_push("did:m", now(), 3600).await.unwrap());
        store.release_push("did:m", now(), 0).await.unwrap();

        pusher.0.store(false, Ordering::SeqCst);
        wake(&store, &pusher, "did:m", 3600, 0).await.unwrap();
        // Delivered: no more until the wallet picks up.
        assert!(!store.claim_push("did:m", now(), 3600).await.unwrap());
    }
}
