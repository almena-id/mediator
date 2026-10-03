//! Push wake-ups (SPEC.md §6.4).
//!
//! When a message is queued for a mediation that has no live WebSocket
//! session, the devices the wallet registered get a push that carries
//! nothing but "something is waiting" (`{"type": "almena.wake"}`); the app
//! then connects and picks up. At most one push goes out per mediation until
//! the wallet picks up, and never two closer than the minimum interval.
//!
//! A message whose `forward` says it is a call (`urgency: call`) rings the
//! phone instead (`{"type": "almena.call"}`): a VoIP push on iOS, which
//! hands the call to CallKit, and a high-priority data message on Android,
//! from which the app shows its own full-screen call screen. Neither says
//! who calls. Rings ignore the wake-up hold, since a call cannot wait for
//! the wallet to pick up, and go at most once per ring interval.
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

/// The `type` of a call push, and the tag that collapses one into the next.
pub const CALL: &str = "almena.call";

/// How long a call push is worth delivering: a call offer is dropped by the
/// caller after this long, so a phone that comes online later must not ring.
pub const CALL_TTL_SECS: u64 = 60;

/// A push service a device token belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Service {
    Fcm,
    Apns,
    /// A PushKit token of the same iOS app, for calls only: iOS ends an app
    /// that receives a VoIP push and does not report a call, so wake-ups
    /// never go to it.
    ApnsVoip,
}

impl Service {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fcm => "fcm",
            Self::Apns => "apns",
            Self::ApnsVoip => "apns-voip",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "fcm" => Some(Self::Fcm),
            "apns" => Some(Self::Apns),
            "apns-voip" => Some(Self::ApnsVoip),
            _ => None,
        }
    }

    /// The push protocol, and push credentials, the service belongs to: a
    /// VoIP token is registered with the APNs protocol and pushed with the
    /// APNs key.
    pub fn protocol(self) -> Self {
        match self {
            Self::ApnsVoip => Self::Apns,
            other => other,
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

/// Sends wake-ups and call pushes.
#[async_trait]
pub trait Pusher: Send + Sync {
    /// The push protocols this pusher can send through (never
    /// [`Service::ApnsVoip`], which comes with [`Service::Apns`]).
    fn services(&self) -> &[Service];
    /// Sends one wake-up to `token`.
    async fn wake(&self, service: Service, token: &str) -> Result<Sent>;
    /// Rings `token` for an incoming call: [`Service::Fcm`] or
    /// [`Service::ApnsVoip`].
    async fn ring(&self, service: Service, token: &str) -> Result<Sent>;
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
            (Service::ApnsVoip, ..) => anyhow::bail!("VoIP tokens are only rung"),
            _ => anyhow::bail!("{} is not configured", service.as_str()),
        }
    }

    async fn ring(&self, service: Service, token: &str) -> Result<Sent> {
        match (service, &self.fcm, &self.apns) {
            (Service::Fcm, Some(fcm), _) => fcm.ring(token).await,
            (Service::ApnsVoip, _, Some(apns)) => apns.ring(token).await,
            (Service::Apns, ..) => anyhow::bail!("APNs alert tokens are only woken"),
            _ => anyhow::bail!("{} is not configured", service.as_str()),
        }
    }
}

/// What a push was for, in logs and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Wake,
    Ring,
}

/// Counts and logs what `service` said about one push to `device`, and
/// forgets the token when it is no longer valid. `true` if it was delivered.
async fn settle(
    store: &dyn Store,
    mediation: &str,
    service: Service,
    device: &Device,
    kind: Kind,
    sent: Result<Sent>,
) -> Result<bool> {
    let count = |push| match kind {
        Kind::Wake => METRICS.push(service, push),
        Kind::Ring => METRICS.ring(service, push),
    };
    let service_name = service.as_str();
    match sent {
        Ok(Sent::Delivered) => {
            tracing::debug!(%mediation, service = service_name, ?kind, "push sent");
            count(Push::Delivered);
            Ok(true)
        }
        Ok(Sent::InvalidToken) => {
            count(Push::InvalidToken);
            tracing::info!(%mediation, service = service_name, ?kind, "push token rejected, removed");
            store
                .remove_device(mediation, service, &device.token)
                .await?;
            Ok(false)
        }
        Err(err) => {
            count(Push::Failed);
            tracing::warn!(%mediation, service = service_name, ?kind, error = %format!("{err:#}"), "push failed");
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
    let devices: Vec<_> = offered(store, pusher, mediation)
        .await?
        .into_iter()
        .filter(|(service, _)| *service != Service::ApnsVoip)
        .collect();
    if devices.is_empty() || !store.claim_push(mediation, now(), hold_secs).await? {
        return Ok(());
    }
    let mut reached = false;
    for (service, device) in devices {
        let sent = pusher.wake(service, &device.token).await;
        reached |= settle(store, mediation, service, &device, Kind::Wake, sent).await?;
    }
    if !reached {
        store.release_push(mediation, now(), retry_secs).await?;
    }
    Ok(())
}

/// Rings `mediation`'s devices for an incoming call, at most once per
/// `interval_secs` (a caller retrying its offer must not make the phone
/// ring twice). The wake-up hold does not apply: a wake-up that went out
/// earlier says nothing about a call. An iOS wallet that registered no VoIP
/// token (an older app) gets the ordinary wake-up instead, so it still
/// learns that something is waiting. Tokens the service rejects are
/// forgotten.
pub async fn ring(
    store: &dyn Store,
    pusher: &dyn Pusher,
    mediation: &str,
    interval_secs: u64,
) -> Result<()> {
    let mut devices = offered(store, pusher, mediation).await?;
    if devices
        .iter()
        .any(|(service, _)| *service == Service::ApnsVoip)
    {
        devices.retain(|(service, _)| *service != Service::Apns);
    }
    if devices.is_empty() || !store.claim_ring(mediation, now(), interval_secs).await? {
        return Ok(());
    }
    for (service, device) in devices {
        let sent = match service {
            Service::Apns => pusher.wake(service, &device.token).await,
            Service::Fcm | Service::ApnsVoip => pusher.ring(service, &device.token).await,
        };
        settle(store, mediation, service, &device, Kind::Ring, sent).await?;
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
        .filter(|(service, _)| pusher.services().contains(&service.protocol()))
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
    use crate::store::MemoryStore;
    use crate::testing::{Pushed, RecordingPusher};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::mpsc::UnboundedReceiver;

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

        async fn ring(&self, service: Service, token: &str) -> Result<Sent> {
            self.wake(service, token).await
        }
    }

    #[tokio::test]
    async fn a_failed_push_does_not_silence_the_wallet() {
        let store = MemoryStore::new();
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

    async fn register(store: &MemoryStore, devices: &[(Service, &str)]) {
        for (service, token) in devices {
            let device = Device {
                token: (*token).into(),
                platform: (*service == Service::Fcm).then(|| "android".into()),
            };
            store
                .set_device("did:m", *service, Some(&device))
                .await
                .unwrap();
        }
    }

    /// Everything the pusher was asked to send, in order.
    fn drain(sent: &mut UnboundedReceiver<(Pushed, Service, String)>) -> Vec<(Pushed, Service)> {
        std::iter::from_fn(|| sent.try_recv().ok())
            .map(|(pushed, service, _)| (pushed, service))
            .collect()
    }

    #[tokio::test]
    async fn a_call_rings_once_per_interval_whatever_the_wake_up_hold() {
        let store = MemoryStore::new();
        register(
            &store,
            &[(Service::Fcm, "phone"), (Service::ApnsVoip, "ab12")],
        )
        .await;
        let (pusher, mut sent) = RecordingPusher::new(&[Service::Fcm, Service::Apns]);
        // A wake-up went out and the wallet has not picked up since.
        assert!(store.claim_push("did:m", now(), 3600).await.unwrap());

        ring(&store, pusher.as_ref(), "did:m", 3600).await.unwrap();
        assert_eq!(
            drain(&mut sent),
            [
                (Pushed::Ring, Service::Fcm),
                (Pushed::Ring, Service::ApnsVoip)
            ]
        );
        // The caller offers again within the interval: no second ring.
        ring(&store, pusher.as_ref(), "did:m", 3600).await.unwrap();
        assert!(drain(&mut sent).is_empty());
        // A wake-up never goes to the VoIP token.
        store.release_push("did:m", now(), 0).await.unwrap();
        wake(&store, pusher.as_ref(), "did:m", 3600, 0)
            .await
            .unwrap();
        assert_eq!(drain(&mut sent), [(Pushed::Wake, Service::Fcm)]);
    }

    #[tokio::test]
    async fn an_iphone_without_a_voip_token_gets_the_wake_up() {
        let store = MemoryStore::new();
        register(&store, &[(Service::Apns, "ab12")]).await;
        let (pusher, mut sent) = RecordingPusher::new(&[Service::Apns]);
        ring(&store, pusher.as_ref(), "did:m", 0).await.unwrap();
        assert_eq!(drain(&mut sent), [(Pushed::Wake, Service::Apns)]);

        // With one, the VoIP push replaces it.
        register(&store, &[(Service::ApnsVoip, "cd34")]).await;
        ring(&store, pusher.as_ref(), "did:m", 0).await.unwrap();
        assert_eq!(drain(&mut sent), [(Pushed::Ring, Service::ApnsVoip)]);

        // Without the APNs credentials, nothing rings at all.
        let (fcm_only, mut sent) = RecordingPusher::new(&[Service::Fcm]);
        ring(&store, fcm_only.as_ref(), "did:m", 0).await.unwrap();
        assert!(drain(&mut sent).is_empty());
    }

    #[tokio::test]
    async fn a_rejected_voip_token_is_forgotten() {
        let store = MemoryStore::new();
        register(
            &store,
            &[(Service::Apns, "ab12"), (Service::ApnsVoip, "dead")],
        )
        .await;
        let (pusher, _sent) = RecordingPusher::new(&[Service::Apns]);
        ring(&store, pusher.as_ref(), "did:m", 0).await.unwrap();
        assert_eq!(
            store.devices("did:m").await.unwrap(),
            [(
                Service::Apns,
                Device {
                    token: "ab12".into(),
                    platform: None
                }
            )]
        );
    }
}
