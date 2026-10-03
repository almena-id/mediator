//! Apple Push Notification service, token-based (a `.p8` key).
//!
//! Every request carries a JWT signed with the key (ES256), reused for 50
//! minutes as Apple asks (no more than one new token every 20 minutes, none
//! older than an hour). The wake-up is an alert whose words are keys into the
//! app's own strings, delivered at priority 10 and collapsed into the one
//! before it. The call push is a PushKit (VoIP) push to the app's VoIP token,
//! on the bundle id's `.voip` topic: iOS launches the app, which reports the
//! call to CallKit and the phone rings.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use almena_didcomm::message::now;
use anyhow::{Context, Result, anyhow, bail};
use reqwest::StatusCode;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde_json::{Value, json};

use super::{BODY_KEY, CALL, CALL_TTL_SECS, Sent, TITLE_KEY, WAKE, jwt};

const PRODUCTION_URL: &str = "https://api.push.apple.com";
const SANDBOX_URL: &str = "https://api.sandbox.push.apple.com";
const JWT_LIFETIME: Duration = Duration::from_secs(50 * 60);

/// The APNs settings (`ALMENA_APNS_*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApnsConfig {
    /// The `.p8` signing key.
    pub key_path: std::path::PathBuf,
    pub key_id: String,
    pub team_id: String,
    /// The wallet app's bundle id.
    pub topic: String,
    /// Development builds of the app get tokens for the sandbox.
    pub sandbox: bool,
}

pub struct Apns {
    client: reqwest::Client,
    url: String,
    topic: String,
    team_id: String,
    key_id: String,
    key: EcdsaKeyPair,
    rng: SystemRandom,
    /// Provider token and when to stop using it.
    jwt: Mutex<Option<(String, Instant)>>,
}

impl Apns {
    pub fn new(config: &ApnsConfig) -> Result<Self> {
        let pem = std::fs::read_to_string(&config.key_path)
            .with_context(|| format!("reading APNs key {}", config.key_path.display()))?;
        let url = if config.sandbox {
            SANDBOX_URL
        } else {
            PRODUCTION_URL
        };
        Self::with_key(&pem, config, url)
            .with_context(|| format!("APNs key {}", config.key_path.display()))
    }

    fn with_key(pem: &str, config: &ApnsConfig, url: &str) -> Result<Self> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &super::pkcs8_der(pem)?,
            &rng,
        )
        .map_err(|err| anyhow!("invalid P-256 private key: {err}"))?;
        Ok(Self {
            client: super::http_client()?,
            url: url.to_owned(),
            topic: config.topic.clone(),
            team_id: config.team_id.clone(),
            key_id: config.key_id.clone(),
            key,
            rng,
            jwt: Mutex::new(None),
        })
    }

    /// `token` is hex (checked when it was registered), so it is safe in the path.
    pub async fn wake(&self, token: &str) -> Result<Sent> {
        let request = self
            .client
            .post(format!("{}/3/device/{token}", self.url))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-collapse-id", WAKE)
            .json(&payload());
        self.send(request).await
    }

    /// Rings a VoIP `token` (hex, like [`Apns::wake`]'s). A VoIP push needs
    /// no `aps`; it expires with the call offer, so a phone that comes back
    /// later does not ring for a call that is over.
    pub async fn ring(&self, token: &str) -> Result<Sent> {
        let request = self
            .client
            .post(format!("{}/3/device/{token}", self.url))
            .header("apns-topic", format!("{}.voip", self.topic))
            .header("apns-push-type", "voip")
            .header("apns-priority", "10")
            .header("apns-expiration", (now() + CALL_TTL_SECS).to_string())
            .json(&json!({"type": CALL}));
        self.send(request).await
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Sent> {
        let response = request.bearer_auth(self.provider_token()?).send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(Sent::Delivered);
        }
        let error: Value = response.json().await.unwrap_or_default();
        let reason = error["reason"].as_str().unwrap_or_default();
        match (status, reason) {
            (StatusCode::GONE, _)
            | (StatusCode::BAD_REQUEST, "BadDeviceToken" | "DeviceTokenNotForTopic") => {
                Ok(Sent::InvalidToken)
            }
            (StatusCode::FORBIDDEN, "ExpiredProviderToken" | "InvalidProviderToken") => {
                self.forget_provider_token();
                bail!("APNs refused the provider token: {reason}")
            }
            _ => bail!("APNs answered {status}: {reason}"),
        }
    }

    fn provider_token(&self) -> Result<String> {
        if let Ok(jwt) = self.jwt.lock()
            && let Some((token, until)) = jwt.as_ref()
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        let token = jwt::encode(
            &json!({"alg": "ES256", "kid": self.key_id}),
            &json!({"iss": self.team_id, "iat": now()}),
            |input| {
                Ok(self
                    .key
                    .sign(&self.rng, input)
                    .map_err(|_| anyhow!("ECDSA signing failed"))?
                    .as_ref()
                    .to_vec())
            },
        )?;
        if let Ok(mut jwt) = self.jwt.lock() {
            *jwt = Some((token.clone(), Instant::now() + JWT_LIFETIME));
        }
        Ok(token)
    }

    fn forget_provider_token(&self) {
        if let Ok(mut jwt) = self.jwt.lock() {
            *jwt = None;
        }
    }
}

/// The notification: a title and a text by key, the default sound, all in one
/// thread.
fn payload() -> Value {
    json!({
        "aps": {
            "alert": {"title-loc-key": TITLE_KEY, "loc-key": BODY_KEY},
            "sound": "default",
            "thread-id": WAKE,
        },
        "type": WAKE,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::{Path as UrlPath, State};
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::{Json, Router};
    use ring::signature::{ECDSA_P256_SHA256_FIXED, KeyPair, UnparsedPublicKey};

    use super::*;

    const KEY: &str = include_str!("testdata/apns-test-key.p8");

    #[derive(Default)]
    struct Apple {
        requests: AtomicUsize,
        public_key: Mutex<Vec<u8>>,
        tokens_seen: Mutex<Vec<String>>,
    }

    async fn fake_apple(apple: Arc<Apple>) -> String {
        let app = Router::new()
            .route(
                "/3/device/{token}",
                post(
                    |State(a): State<Arc<Apple>>,
                     UrlPath(token): UrlPath<String>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        a.requests.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(headers["apns-priority"], "10");
                        if headers["apns-push-type"] == "voip" {
                            assert_eq!(headers["apns-topic"], "id.almena.wallet.voip");
                            let expiration: u64 = headers["apns-expiration"]
                                .to_str()
                                .unwrap()
                                .parse()
                                .unwrap();
                            assert!(expiration > now() && expiration <= now() + 60);
                            assert!(!headers.contains_key("apns-collapse-id"));
                            assert_eq!(body, json!({"type": CALL}));
                        } else {
                            assert_eq!(headers["apns-topic"], "id.almena.wallet");
                            assert_eq!(headers["apns-push-type"], "alert");
                            assert_eq!(headers["apns-collapse-id"], WAKE);
                            assert_eq!(body, payload());
                            assert_eq!(body["aps"]["alert"]["loc-key"], BODY_KEY);
                        }
                        let bearer = headers["authorization"].to_str().unwrap();
                        let jwt = bearer.strip_prefix("Bearer ").unwrap();
                        let (input, header, claims, signature) = jwt::decode(jwt);
                        assert_eq!(header, json!({"alg": "ES256", "kid": "KEY1234567"}));
                        assert_eq!(claims["iss"], "TEAM123456");
                        let public_key = a.public_key.lock().unwrap().clone();
                        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
                            .verify(input.as_bytes(), &signature)
                            .unwrap();
                        a.tokens_seen.lock().unwrap().push(jwt.to_owned());
                        match token.as_str() {
                            "aa11" => (StatusCode::OK, Json(json!({}))),
                            "bb22" => (StatusCode::GONE, Json(json!({"reason": "Unregistered"}))),
                            "cc33" => (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"reason": "BadDeviceToken"})),
                            ),
                            _ => (
                                StatusCode::TOO_MANY_REQUESTS,
                                Json(json!({"reason": "TooManyRequests"})),
                            ),
                        }
                    },
                ),
            )
            .with_state(apple);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, app).into_future());
        url
    }

    #[tokio::test]
    async fn wakes_and_rings_with_a_reused_provider_token_and_spots_dead_tokens() {
        let apple = Arc::new(Apple::default());
        let url = fake_apple(Arc::clone(&apple)).await;
        let config = ApnsConfig {
            key_path: "unused.p8".into(),
            key_id: "KEY1234567".into(),
            team_id: "TEAM123456".into(),
            topic: "id.almena.wallet".into(),
            sandbox: true,
        };
        let apns = Apns::with_key(KEY, &config, &url).unwrap();
        *apple.public_key.lock().unwrap() = apns.key.public_key().as_ref().to_vec();

        assert_eq!(apns.wake("aa11").await.unwrap(), Sent::Delivered);
        assert_eq!(apns.wake("bb22").await.unwrap(), Sent::InvalidToken);
        assert_eq!(apns.wake("cc33").await.unwrap(), Sent::InvalidToken);
        assert!(apns.wake("dd44").await.is_err());
        assert_eq!(apns.ring("aa11").await.unwrap(), Sent::Delivered);
        assert_eq!(apns.ring("bb22").await.unwrap(), Sent::InvalidToken);
        assert_eq!(apple.requests.load(Ordering::SeqCst), 6);
        let seen = apple.tokens_seen.lock().unwrap();
        assert!(
            seen.iter().all(|t| *t == seen[0]),
            "one provider token reused"
        );
    }

    #[test]
    fn rejects_a_key_that_is_not_p256() {
        let config = ApnsConfig {
            key_path: "unused.p8".into(),
            key_id: "k".into(),
            team_id: "t".into(),
            topic: "b".into(),
            sandbox: false,
        };
        assert!(
            Apns::with_key(
                include_str!("testdata/fcm-test-key.pem"),
                &config,
                SANDBOX_URL
            )
            .is_err()
        );
    }
}
