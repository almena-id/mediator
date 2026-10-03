//! Firebase Cloud Messaging, HTTP v1 API.
//!
//! Authenticates with the wallet app's service account: a JWT signed with
//! its RSA key is exchanged for an OAuth 2 access token, cached until shortly
//! before it expires. The wake-up is a high-priority notification whose words
//! are keys into the app's string resources, tagged so that a second one
//! replaces the first. The call push is a high-priority data message with no
//! notification at all: the app wakes and shows its own full-screen call
//! screen, which a notification the system draws could not do.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use almena_didcomm::message::now;
use anyhow::{Context, Result, anyhow, bail, ensure};
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{BODY_KEY, CALL, CALL_TTL_SECS, Sent, TITLE_KEY, WAKE, jwt};

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const FCM_URL: &str = "https://fcm.googleapis.com";

/// The fields of a Google service account key file that are used here.
#[derive(Deserialize)]
struct ServiceAccount {
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    token_uri: String,
}

pub struct Fcm {
    client: reqwest::Client,
    send_url: String,
    token_uri: String,
    client_email: String,
    key_id: String,
    key: RsaKeyPair,
    /// Access token and when to stop using it.
    access: Mutex<Option<(String, Instant)>>,
}

impl Fcm {
    /// Reads the service account key file (`ALMENA_FCM_SERVICE_ACCOUNT`).
    pub fn from_file(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("reading FCM service account {}", path.display()))?;
        Self::new(&json, FCM_URL).with_context(|| format!("FCM service account {}", path.display()))
    }

    fn new(service_account: &str, fcm_url: &str) -> Result<Self> {
        let account: ServiceAccount =
            serde_json::from_str(service_account).context("not a service account key file")?;
        let key = RsaKeyPair::from_pkcs8(&super::pkcs8_der(&account.private_key)?)
            .map_err(|err| anyhow!("invalid RSA private key: {err}"))?;
        Ok(Self {
            client: super::http_client()?,
            send_url: format!("{fcm_url}/v1/projects/{}/messages:send", account.project_id),
            token_uri: account.token_uri,
            client_email: account.client_email,
            key_id: account.private_key_id,
            key,
            access: Mutex::new(None),
        })
    }

    pub async fn wake(&self, token: &str) -> Result<Sent> {
        self.send(json!({
            "token": token,
            "data": {"type": WAKE},
            "android": {
                "priority": "high",
                "collapse_key": WAKE,
                "notification": {
                    "title_loc_key": TITLE_KEY,
                    "body_loc_key": BODY_KEY,
                    "tag": WAKE,
                },
            },
        }))
        .await
    }

    /// Data only: a `notification` would be drawn by the system while the
    /// app is in the background, and the app could not ring.
    pub async fn ring(&self, token: &str) -> Result<Sent> {
        self.send(json!({
            "token": token,
            "data": {"type": CALL},
            "android": {
                "priority": "high",
                "ttl": format!("{CALL_TTL_SECS}s"),
                "collapse_key": CALL,
            },
        }))
        .await
    }

    async fn send(&self, message: Value) -> Result<Sent> {
        let access = self.access_token().await?;
        let response = self
            .client
            .post(&self.send_url)
            .bearer_auth(access)
            .json(&json!({ "message": message }))
            .send()
            .await?;
        let status = response.status();
        if status.is_success() {
            return Ok(Sent::Delivered);
        }
        if status == StatusCode::UNAUTHORIZED {
            self.forget_access_token();
        }
        let error: Value = response.json().await.unwrap_or_default();
        if is_invalid_token(&error) {
            return Ok(Sent::InvalidToken);
        }
        bail!(
            "FCM answered {status}: {}",
            error["error"]["message"].as_str().unwrap_or_default()
        )
    }

    async fn access_token(&self) -> Result<String> {
        if let Ok(access) = self.access.lock()
            && let Some((token, until)) = access.as_ref()
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        let iat = now();
        let assertion = jwt::encode(
            &json!({"alg": "RS256", "typ": "JWT", "kid": self.key_id}),
            &json!({
                "iss": self.client_email,
                "scope": SCOPE,
                "aud": self.token_uri,
                "iat": iat,
                "exp": iat + 3600,
            }),
            |input| {
                let mut signature = vec![0; self.key.public().modulus_len()];
                self.key
                    .sign(
                        &RSA_PKCS1_SHA256,
                        &SystemRandom::new(),
                        input,
                        &mut signature,
                    )
                    .map_err(|_| anyhow!("RSA signing failed"))?;
                Ok(signature)
            },
        )?;
        // The assertion is base64url and dots: nothing to escape.
        let response = self
            .client
            .post(&self.token_uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
            ))
            .send()
            .await?;
        let status = response.status();
        ensure!(
            status.is_success(),
            "OAuth token endpoint answered {status}"
        );

        #[derive(Deserialize)]
        struct Token {
            access_token: String,
            expires_in: u64,
        }
        let token: Token = response
            .json()
            .await
            .context("reading the OAuth access token")?;
        let until = Instant::now() + Duration::from_secs(token.expires_in.saturating_sub(60));
        if let Ok(mut access) = self.access.lock() {
            *access = Some((token.access_token.clone(), until));
        }
        Ok(token.access_token)
    }

    fn forget_access_token(&self) {
        if let Ok(mut access) = self.access.lock() {
            *access = None;
        }
    }
}

/// FCM's way of saying the token is gone or was never valid: `UNREGISTERED`,
/// or `INVALID_ARGUMENT` about the token itself. `INVALID_ARGUMENT` alone also
/// covers a payload FCM refuses, and a bug there must not wipe every token.
fn is_invalid_token(error: &Value) -> bool {
    let Some(details) = error["error"]["details"].as_array() else {
        return false;
    };
    let code = |wanted: &str| {
        details
            .iter()
            .any(|detail| detail["errorCode"].as_str() == Some(wanted))
    };
    let about_the_token = details.iter().any(|detail| {
        detail["fieldViolations"]
            .as_array()
            .is_some_and(|violations| {
                violations
                    .iter()
                    .any(|v| v["field"].as_str() == Some("message.token"))
            })
    }) || error["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("registration token"));
    code("UNREGISTERED") || (code("INVALID_ARGUMENT") && about_the_token)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::{Json, Router};
    use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    use super::*;

    const KEY: &str = include_str!("testdata/fcm-test-key.pem");

    #[test]
    fn only_errors_about_the_token_drop_it() {
        let error = |code: &str, message: &str, extra: Value| {
            json!({"error": {"status": "INVALID_ARGUMENT", "message": message, "details": [
                {"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": code},
                extra,
            ]}})
        };
        assert!(is_invalid_token(&error("UNREGISTERED", "", json!({}))));
        assert!(is_invalid_token(&error(
            "INVALID_ARGUMENT",
            "The registration token is not a valid FCM registration token",
            json!({})
        )));
        assert!(is_invalid_token(&error(
            "INVALID_ARGUMENT",
            "Request contains an invalid argument.",
            json!({"@type": "type.googleapis.com/google.rpc.BadRequest",
                   "fieldViolations": [{"field": "message.token", "description": "Invalid registration token"}]})
        )));
        // The payload, not the token.
        assert!(!is_invalid_token(&error(
            "INVALID_ARGUMENT",
            "Invalid value at 'message.android.priority'",
            json!({"@type": "type.googleapis.com/google.rpc.BadRequest",
                   "fieldViolations": [{"field": "message.android.priority"}]})
        )));
        assert!(!is_invalid_token(
            &json!({"error": {"status": "UNAVAILABLE"}})
        ));
    }

    #[derive(Default)]
    struct Google {
        token_requests: AtomicUsize,
        public_key: Mutex<Vec<u8>>,
    }

    /// A fake OAuth endpoint and FCM send API on a local port.
    async fn fake_google(google: Arc<Google>) -> String {
        let app = Router::new()
            .route(
                "/token",
                post(|State(g): State<Arc<Google>>, body: String| async move {
                    g.token_requests.fetch_add(1, Ordering::SeqCst);
                    let assertion = body.split("assertion=").nth(1).unwrap();
                    let (input, header, claims, signature) = jwt::decode(assertion);
                    assert_eq!(header["alg"], "RS256");
                    assert_eq!(header["kid"], "key-1");
                    assert_eq!(claims["iss"], "wallet@example.iam.gserviceaccount.com");
                    assert_eq!(claims["scope"], SCOPE);
                    let public_key = g.public_key.lock().unwrap().clone();
                    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key)
                        .verify(input.as_bytes(), &signature)
                        .unwrap();
                    Json(json!({"access_token": "at-1", "expires_in": 3600}))
                }),
            )
            .route(
                "/v1/projects/almena-wallet/messages:send",
                post(|headers: HeaderMap, Json(body): Json<Value>| async move {
                    assert_eq!(headers["authorization"], "Bearer at-1");
                    let message = &body["message"];
                    assert_eq!(message["android"]["priority"], "high");
                    if message["data"]["type"] == CALL {
                        assert_eq!(message["data"], json!({"type": CALL}));
                        assert_eq!(
                            message["android"],
                            json!({"priority": "high", "ttl": "60s", "collapse_key": CALL})
                        );
                        assert!(message.get("notification").is_none());
                    } else {
                        assert_eq!(message["data"], json!({"type": WAKE}));
                        assert_eq!(message["android"]["notification"]["body_loc_key"], BODY_KEY);
                    }
                    match message["token"].as_str().unwrap() {
                        "good" => (StatusCode::OK, Json(json!({"name": "projects/x/messages/1"}))),
                        "gone" => (
                            StatusCode::NOT_FOUND,
                            Json(json!({"error": {"code": 404, "message": "Requested entity was not found.", "details": [
                                {"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": "UNREGISTERED"}
                            ]}})),
                        ),
                        _ => (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({"error": {"code": 503, "message": "try later"}})),
                        ),
                    }
                }),
            )
            .with_state(google);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, app).into_future());
        url
    }

    #[tokio::test]
    async fn wakes_and_rings_with_a_cached_access_token_and_spots_dead_tokens() {
        let google = Arc::new(Google::default());
        let url = fake_google(Arc::clone(&google)).await;
        let account = json!({
            "type": "service_account",
            "project_id": "almena-wallet",
            "private_key_id": "key-1",
            "private_key": KEY,
            "client_email": "wallet@example.iam.gserviceaccount.com",
            "token_uri": format!("{url}/token"),
        });
        let fcm = Fcm::new(&account.to_string(), &url).unwrap();
        *google.public_key.lock().unwrap() = fcm.key.public().as_ref().to_vec();

        assert_eq!(fcm.wake("good").await.unwrap(), Sent::Delivered);
        assert_eq!(fcm.wake("gone").await.unwrap(), Sent::InvalidToken);
        assert!(fcm.wake("flaky").await.is_err());
        assert_eq!(fcm.ring("good").await.unwrap(), Sent::Delivered);
        assert_eq!(fcm.ring("gone").await.unwrap(), Sent::InvalidToken);
        assert_eq!(google.token_requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rejects_a_file_that_is_not_a_service_account() {
        assert!(Fcm::new(r#"{"project_id": "x"}"#, FCM_URL).is_err());
    }
}
