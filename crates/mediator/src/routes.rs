use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::{Json, Router, routing::get};
use serde::Serialize;
use tower_http::trace::TraceLayer;
use utoipa::openapi::OpenApi as OpenApiDoc;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_scalar::{Scalar, Servable};

use crate::dispatch::{Mediator, Outcome, ReceiveError};
use crate::store::Store;
use crate::{home, oob};

/// Where the interactive API reference and the raw OpenAPI document are served.
pub const DOCS_PATH: &str = "/docs";
pub const OPENAPI_PATH: &str = "/openapi.json";

/// Media type of DIDComm encrypted messages, the only kind `/didcomm` takes.
const ENCRYPTED: &str = "application/didcomm-encrypted+json";

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Almena mediator",
        description = "HTTP endpoints published by an Almena Network mediator (DIDComm Messaging v2.0)."
    ),
    tags(
        (name = "didcomm", description = "DIDComm Messaging transport and the mediator's DID"),
        (name = "operations", description = "Service health and metadata")
    )
)]
struct ApiDoc;

/// Shared state of the HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    pub mediator: Arc<Mediator>,
    pub store: Arc<dyn Store>,
    /// `POST /didcomm` requests per minute per client IP; 0 = no limit.
    pub rate_limit: u64,
    /// Header with the client IP set by a reverse proxy (see `Config`).
    pub client_ip_header: Option<HeaderName>,
    /// The mediator's public origin (`ALMENA_PUBLIC_URL`).
    pub public_url: String,
}

/// The mediator's HTTP router. Every endpoint is registered through
/// [`OpenApiRouter`], so it shows up in the OpenAPI document served at
/// [`OPENAPI_PATH`] and in the reference page at [`DOCS_PATH`].
pub fn router(state: AppState) -> Router {
    let max_body = state.mediator.limits().max_message_bytes;
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(home_page))
        .routes(routes!(icon))
        .routes(routes!(font))
        .routes(routes!(receive))
        .routes(routes!(websocket))
        .routes(routes!(did_document))
        .routes(routes!(invitation))
        .routes(routes!(invitation_page))
        .routes(routes!(health))
        .with_state(state)
        .split_for_parts();
    router
        .merge(docs(api))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(TraceLayer::new_for_http())
}

/// Home page
///
/// What a browser shows at the mediator's root: the
/// status, version and DID that `/health` also reports, and the mediation
/// invitation as a QR code for the wallet.
#[utoipa::path(
    get,
    path = "/",
    tag = "operations",
    responses((status = 200, description = "HTML page", content_type = "text/html"))
)]
async fn home_page(State(state): State<AppState>) -> Html<String> {
    let healthy = state.store.ping().await.is_ok();
    let identity = state.mediator.identity();
    let invitation = oob::invitation(identity);
    let url = oob::invitation_url(&state.public_url, &invitation);
    Html(home::page(
        healthy,
        crate::VERSION,
        &identity.did,
        &url,
        &oob::wallet_url(&invitation),
    ))
}

/// Icon
///
/// The mediator's icon, the favicon of its pages.
#[utoipa::path(
    get,
    path = "/icon.png",
    tag = "operations",
    responses((status = 200, description = "PNG image", content_type = "image/png"))
)]
async fn icon() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        home::ICON,
    )
}

/// Font
///
/// One of the typefaces the mediator's pages use (WOFF2, SIL Open Font
/// License), served by the mediator itself so a page never calls a third party.
#[utoipa::path(
    get,
    path = "/fonts/{name}",
    tag = "operations",
    params(("name" = String, Path, description = "Font file, e.g. `inter.woff2`")),
    responses(
        (status = 200, description = "WOFF2 font", content_type = "font/woff2"),
        (status = 404, description = "No such font")
    )
)]
async fn font(Path(name): Path<String>) -> Response {
    match home::font(&name) {
        Some(bytes) => (
            [
                (header::CONTENT_TYPE, "font/woff2"),
                (header::CACHE_CONTROL, "public, max-age=86400"),
            ],
            bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn docs(api: OpenApiDoc) -> Router {
    let json = Json(api.clone());
    Router::new()
        .route(OPENAPI_PATH, get(move || async move { json }))
        .merge(Scalar::with_url(DOCS_PATH, api).title("Almena mediator API"))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    #[schema(example = "the message could not be unpacked")]
    pub error: String,
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

/// Receive a DIDComm message
///
/// Takes one DIDComm encrypted message addressed to this mediator. Messages the
/// mediator answers (Trust Ping, Discover Features, or a problem report) are
/// answered in the response body only if the message carries the
/// `return_route: "all"` header; otherwise the response is `202` with no body.
#[utoipa::path(
    post,
    path = "/didcomm",
    tag = "didcomm",
    request_body(
        content = Object,
        content_type = "application/didcomm-encrypted+json",
        description = "A DIDComm encrypted message (JWE, general JSON serialization)"
    ),
    responses(
        (status = 200, description = "Accepted; the reply travels back in the body",
            content_type = "application/didcomm-encrypted+json", body = Object),
        (status = 202, description = "Accepted; no reply on this connection"),
        (status = 400, description = "Not a DIDComm message this mediator can open", body = ErrorBody),
        (status = 404, description = "A `forward` for a recipient DID this mediator does not mediate", body = ErrorBody),
        (status = 413, description = "Larger than the mediator accepts (see `max_receive_bytes` in Discover Features)"),
        (status = 415, description = "Content-Type is not `application/didcomm-encrypted+json`", body = ErrorBody),
        (status = 429, description = "Too many requests from this client IP; retry after the `Retry-After` seconds"),
        (status = 503, description = "Storage unavailable; retry later", body = ErrorBody),
        (status = 507, description = "The forward's recipient queue is full", body = ErrorBody)
    )
)]
async fn receive(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = rate_limited(&state, &headers, connect.map(|c| c.0.0)).await {
        return response;
    }
    if !is_media_type(&headers, ENCRYPTED) {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("Content-Type must be {ENCRYPTED}"),
        );
    }
    let Ok(body) = std::str::from_utf8(&body) else {
        return error(StatusCode::BAD_REQUEST, "the body is not UTF-8");
    };
    match state.mediator.receive(body, None).await {
        Ok(Outcome::Accepted) => StatusCode::ACCEPTED.into_response(),
        Ok(Outcome::Reply(reply)) => (
            [(header::CONTENT_TYPE, HeaderValue::from_static(ENCRYPTED))],
            reply,
        )
            .into_response(),
        Err(ReceiveError::Unpack(err)) => {
            tracing::debug!(error = %err, "rejected envelope");
            error(StatusCode::BAD_REQUEST, client_message(&err))
        }
        Err(err @ ReceiveError::BadForward(_)) => error(StatusCode::BAD_REQUEST, err.to_string()),
        Err(err @ ReceiveError::UnknownRecipient) => error(StatusCode::NOT_FOUND, err.to_string()),
        Err(err @ ReceiveError::QueueFull) => {
            error(StatusCode::INSUFFICIENT_STORAGE, err.to_string())
        }
        Err(ReceiveError::Store(err)) => {
            tracing::error!(error = %format!("{err:#}"), "storage failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage unavailable, retry later",
            )
        }
    }
}

const RATE_WINDOW_SECS: u64 = 60;

/// `429` once the client IP went over the per-minute limit. Storage errors
/// let the request through: better unlimited than unavailable.
async fn rate_limited(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<Response> {
    let ip = client_ip(headers, state.client_ip_header.as_ref(), peer);
    over_limit(state, ip).await.then(too_many_requests)
}

fn too_many_requests() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, HeaderValue::from(RATE_WINDOW_SECS))],
    )
        .into_response()
}

/// Counts one DIDComm message from `ip` and says whether it is over the
/// limit. HTTP requests and WebSocket messages share the budget.
async fn over_limit(state: &AppState, ip: Option<IpAddr>) -> bool {
    let (Some(ip), true) = (ip, state.rate_limit > 0) else {
        return false;
    };
    match state
        .store
        .hit(
            &format!("didcomm:{ip}"),
            RATE_WINDOW_SECS,
            almena_didcomm::message::now(),
        )
        .await
    {
        Ok(hits) if hits > state.rate_limit => {
            crate::metrics::METRICS.rate_limited();
            true
        }
        Ok(_) => false,
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "rate limit check failed");
            false
        }
    }
}

/// DIDComm over WebSocket
///
/// Upgrades to a WebSocket that carries one DIDComm encrypted message per
/// frame (text or binary), in both directions. `return_route` is implied:
/// replies come back on the socket. After a Message Pickup
/// `live-delivery-change` with `live_delivery: true`, new messages for the
/// sender's mediation are pushed as `delivery` messages as they arrive; they
/// stay queued until acknowledged with `messages-received`.
#[utoipa::path(
    get,
    path = "/ws",
    tag = "didcomm",
    responses(
        (status = 101, description = "Switching to the WebSocket protocol"),
        (status = 429, description = "Too many requests from this client IP")
    )
)]
async fn websocket(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let ip = client_ip(
        &headers,
        state.client_ip_header.as_ref(),
        connect.map(|c| c.0.0),
    );
    if over_limit(&state, ip).await {
        return too_many_requests();
    }
    let max = state.mediator.limits().max_message_bytes;
    upgrade
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| websocket_session(socket, state, ip))
}

async fn websocket_session(mut socket: WebSocket, state: AppState, ip: Option<IpAddr>) {
    let mediator = Arc::clone(&state.mediator);
    let (mut session, mut pushes) = mediator.open_session();
    loop {
        tokio::select! {
            frame = socket.recv() => {
                let text = match frame {
                    Some(Ok(WsMessage::Text(text))) => text.to_string(),
                    Some(Ok(WsMessage::Binary(bytes))) => match String::from_utf8(bytes.to_vec()) {
                        Ok(text) => text,
                        Err(_) => continue,
                    },
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                    Some(Ok(WsMessage::Close(_)) | Err(_)) | None => break,
                };
                if over_limit(&state, ip).await {
                    // 1008: policy violation.
                    let _ = socket
                        .send(WsMessage::Close(Some(axum::extract::ws::CloseFrame {
                            code: 1008,
                            reason: "rate limit".into(),
                        })))
                        .await;
                    break;
                }
                match mediator.receive(&text, Some(&mut session)).await {
                    Ok(Outcome::Reply(reply)) => {
                        if socket.send(WsMessage::Text(reply.into())).await.is_err() {
                            break;
                        }
                    }
                    Ok(Outcome::Accepted) => {}
                    Err(err) => tracing::debug!(error = %err, "websocket message rejected"),
                }
            }
            Some(queued) = pushes.recv() => {
                if let Some(delivery) = mediator.live_delivery(&session, queued).await
                    && socket.send(WsMessage::Text(delivery.into())).await.is_err()
                {
                    break;
                }
            }
        }
    }
    mediator.close_session(&mut session);
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationBody {
    /// The Out-of-Band 2.0 invitation (a DIDComm plaintext message).
    #[schema(value_type = Object)]
    pub invitation: serde_json::Value,
    /// The invitation as a URL (`<origin>/oob?_oob=…`), for links and QR codes.
    #[schema(example = "https://mediator.example.com/oob?_oob=eyJ0eXBlIjoi…")]
    pub url: String,
}

/// Mediation invitation
///
/// The mediator's Out-of-Band 2.0 invitation (`goal_code: request-mediate`),
/// and the same invitation as a URL for a link or QR code. A wallet resolves
/// the mediator's DID from it and sends `mediate-request`. The invitation does
/// not change between requests or restarts.
#[utoipa::path(
    get,
    path = "/oob/invitation",
    tag = "didcomm",
    responses((status = 200, description = "The invitation", body = InvitationBody))
)]
async fn invitation(State(state): State<AppState>) -> Json<InvitationBody> {
    let invitation = oob::invitation(state.mediator.identity());
    let url = oob::invitation_url(&state.public_url, &invitation);
    Json(InvitationBody {
        invitation: serde_json::to_value(&invitation).unwrap_or_default(),
        url,
    })
}

/// Invitation page
///
/// What a browser shows for the invitation URL (`/oob?_oob=…`): how to use
/// it with the wallet.
#[utoipa::path(
    get,
    path = "/oob",
    tag = "didcomm",
    responses((status = 200, description = "HTML page", content_type = "text/html"))
)]
async fn invitation_page(State(state): State<AppState>) -> Html<String> {
    let identity = state.mediator.identity();
    let wallet_url = oob::wallet_url(&oob::invitation(identity));
    Html(oob::page(&identity.did, &wallet_url))
}

/// The client IP: the last address in the configured proxy header (the one
/// our proxy added), else the TCP peer.
fn client_ip(
    headers: &HeaderMap,
    header: Option<&HeaderName>,
    peer: Option<SocketAddr>,
) -> Option<IpAddr> {
    match header {
        Some(name) => headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|v| v.trim().parse().ok())
            .next_back(),
        None => peer.map(|p| p.ip()),
    }
}

/// What a sender learns about a rejected envelope: enough to fix its own
/// mistakes, nothing about the mediator's keys or internals.
fn client_message(err: &almena_didcomm::Error) -> &'static str {
    use almena_didcomm::Error;
    match err {
        Error::SecretNotFound(_) => "the message is not encrypted for this mediator",
        Error::DidNotFound(_) | Error::DidUrlNotFound(_) => {
            "the sender's DID or key could not be resolved"
        }
        Error::Crypto(_) => "the message could not be decrypted or verified",
        Error::Inconsistent(_) => "the message's envelopes and headers do not agree",
        Error::Unsupported(_) => "the message uses an unsupported algorithm or DID method",
        _ => "the message is not a valid DIDComm message",
    }
}

/// Whether Content-Type is `expected`, ignoring case and parameters.
fn is_media_type(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(expected))
}

/// The mediator's DID document
///
/// The `did:web` document of this mediator: its keys and its DIDComm endpoint.
#[utoipa::path(
    get,
    path = "/.well-known/did.json",
    tag = "didcomm",
    responses((status = 200, description = "DID document", body = Object))
)]
async fn did_document(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.mediator.identity().document.to_json())
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Health {
    /// `ok`, or `degraded` when a dependency is down.
    #[schema(example = "ok")]
    pub status: &'static str,
    #[schema(example = "almena-mediator")]
    pub service: &'static str,
    #[schema(example = "0.1.0")]
    pub version: &'static str,
    /// The mediator's DID.
    #[schema(example = "did:web:mediator.example.com")]
    pub did: String,
    /// `ok` or `unavailable`.
    #[schema(example = "ok")]
    pub storage: &'static str,
    /// `redis`, or `memory` in development.
    #[schema(example = "redis")]
    pub storage_kind: &'static str,
}

/// Health check
///
/// Answers `200` while the service and its storage (Redis) are up, `503`
/// when storage is unreachable. The container healthcheck calls it.
#[utoipa::path(
    get,
    path = "/health",
    tag = "operations",
    responses(
        (status = 200, description = "The mediator is up", body = Health),
        (status = 503, description = "Storage is unreachable", body = Health)
    )
)]
async fn health(State(state): State<AppState>) -> (StatusCode, Json<Health>) {
    let healthy = state.store.ping().await.is_ok();
    let body = Health {
        status: if healthy { "ok" } else { "degraded" },
        service: env!("CARGO_PKG_NAME"),
        version: crate::VERSION,
        did: state.mediator.identity().did.clone(),
        storage: if healthy { "ok" } else { "unavailable" },
        storage_kind: state.store.kind(),
    };
    let status = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body))
}

#[cfg(test)]
mod tests {
    use almena_didcomm::{Curve, Message};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;
    use crate::store::MemoryStore;
    use crate::testing::{LIMITS, Wallet, mediator_on};

    const MAX: usize = LIMITS.max_message_bytes;

    fn state() -> AppState {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        AppState {
            mediator: Arc::new(mediator_on(Arc::clone(&store))),
            store,
            rate_limit: 0,
            client_ip_header: None,
            public_url: "https://mediator.example.com".into(),
        }
    }

    async fn get(state: AppState, path: &str) -> (StatusCode, Vec<u8>) {
        let response = router(state)
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        (
            status,
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    async fn post(state: AppState, content_type: &str, body: impl Into<Body>) -> Response {
        router(state)
            .oneshot(
                Request::post("/didcomm")
                    .header(header::CONTENT_TYPE, content_type)
                    .body(body.into())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn health_reports_ok_and_the_did() {
        let (status, body) = get(state(), "/health").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["service"], "almena-mediator");
        assert_eq!(json["did"], "did:web:mediator.example.com");
        assert_eq!(json["storage"], "ok");
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        assert_eq!(get(state(), "/nope").await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn did_document_is_served_at_the_well_known_path() {
        let (status, body) = get(state(), "/.well-known/did.json").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], "did:web:mediator.example.com");
        assert_eq!(
            json["service"][0]["serviceEndpoint"][0]["uri"],
            "https://mediator.example.com/didcomm"
        );
    }

    #[tokio::test]
    async fn ping_over_http_with_return_route_is_answered_in_the_body() {
        let state = state();
        let wallet = Wallet::new(Curve::X25519);
        let identity = state.mediator.identity();
        let ping = Message::new("https://didcomm.org/trust-ping/2.0/ping", json!({}))
            .from(&wallet.did)
            .header("return_route", json!("all"));
        let packed = wallet.send(identity, ping.clone(), false).await;

        let response = post(state.clone(), ENCRYPTED, packed).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], ENCRYPTED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let reply = wallet
            .open(identity, std::str::from_utf8(&body).unwrap())
            .await;
        assert_eq!(reply.thid.as_deref(), Some(ping.id.as_str()));
    }

    #[tokio::test]
    async fn ping_without_return_route_is_202() {
        let state = state();
        let wallet = Wallet::new(Curve::X25519);
        let ping =
            Message::new("https://didcomm.org/trust-ping/2.0/ping", json!({})).from(&wallet.did);
        let packed = wallet.send(state.mediator.identity(), ping, false).await;
        assert_eq!(
            post(state, ENCRYPTED, packed).await.status(),
            StatusCode::ACCEPTED
        );
    }

    #[tokio::test]
    async fn content_type_parameters_are_ignored() {
        let state = state();
        let wallet = Wallet::new(Curve::X25519);
        let ping =
            Message::new("https://didcomm.org/trust-ping/2.0/ping", json!({})).from(&wallet.did);
        let packed = wallet.send(state.mediator.identity(), ping, false).await;
        let content_type = "Application/DIDComm-Encrypted+JSON; charset=utf-8";
        assert_eq!(
            post(state, content_type, packed).await.status(),
            StatusCode::ACCEPTED
        );
    }

    #[tokio::test]
    async fn other_media_types_are_415() {
        let response = post(state(), "application/json", "{}").await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn garbage_is_400() {
        let response = post(state(), ENCRYPTED, "not json").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oversized_messages_are_413() {
        let response = post(state(), ENCRYPTED, vec![b' '; MAX + 1]).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn openapi_lists_the_published_endpoints() {
        let (status, body) = get(state(), OPENAPI_PATH).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["info"]["title"], "Almena mediator");
        for path in ["/health", "/didcomm", "/.well-known/did.json"] {
            assert!(json["paths"][path].is_object(), "{path} missing");
        }
    }

    #[tokio::test]
    async fn docs_page_is_served() {
        let (status, body) = get(state(), DOCS_PATH).await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8(body).unwrap().contains("/didcomm"));
    }

    #[tokio::test]
    async fn requests_over_the_rate_limit_get_429() {
        let mut state = state();
        state.rate_limit = 2;
        state.client_ip_header = Some(HeaderName::from_static("x-forwarded-for"));
        let send = |ip: &'static str| {
            let state = state.clone();
            async move {
                router(state)
                    .oneshot(
                        Request::post("/didcomm")
                            .header(header::CONTENT_TYPE, "application/json")
                            .header("x-forwarded-for", format!("198.51.100.1, {ip}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap()
                    .status()
            }
        };
        assert_eq!(
            send("203.0.113.9").await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            send("203.0.113.9").await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(send("203.0.113.9").await, StatusCode::TOO_MANY_REQUESTS);
        // Another client is counted apart.
        assert_eq!(
            send("203.0.113.10").await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn client_ip_prefers_the_proxy_header() {
        let mut headers = HeaderMap::new();
        headers.append(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 192.0.2.7"),
        );
        let name = HeaderName::from_static("x-forwarded-for");
        let peer = Some("127.0.0.1:5000".parse().unwrap());
        assert_eq!(
            client_ip(&headers, Some(&name), peer),
            Some("192.0.2.7".parse().unwrap())
        );
        assert_eq!(
            client_ip(&headers, None, peer),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(client_ip(&HeaderMap::new(), Some(&name), peer), None);
    }

    #[tokio::test]
    async fn forward_to_an_unknown_recipient_is_404() {
        let state = state();
        let identity = state.mediator.identity();
        let bob = Wallet::mediated_by(&identity.did);
        let alice = Wallet::new(Curve::X25519);
        let packed = Message::new("https://example.com/chat/1.0/msg", json!({}))
            .from(&alice.did)
            .to([bob.did.as_str()])
            .pack_encrypted(
                &bob.did,
                Some(&alice.did),
                None,
                &Wallet::resolver(identity),
                &alice.secrets,
                almena_didcomm::PackOptions::default(),
            )
            .await
            .unwrap();
        assert!(packed.forwarded);
        let response = post(state, ENCRYPTED, packed.message).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invitation_names_the_mediator_and_encodes_itself_in_the_url() {
        let (status, body) = get(state(), "/oob/invitation").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["invitation"]["type"],
            "https://didcomm.org/out-of-band/2.0/invitation"
        );
        assert_eq!(json["invitation"]["from"], "did:web:mediator.example.com");
        assert_eq!(json["invitation"]["body"]["goal_code"], "request-mediate");
        assert!(
            json["url"]
                .as_str()
                .unwrap()
                .starts_with("https://mediator.example.com/oob?_oob=")
        );
    }

    #[tokio::test]
    async fn home_page_shows_the_name_and_its_icon_is_served() {
        let (status, body) = get(state(), "/").await;
        assert_eq!(status, StatusCode::OK);
        let html = String::from_utf8(body).unwrap();
        assert!(html.contains("Almena Mediator"));
        assert!(html.contains("Operational"));
        assert!(html.contains("did:web:mediator.example.com"));
        assert!(html.contains("almena://oob?_oob="));
        let (status, body) = get(state(), home::ICON_PATH).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with(b"\x89PNG"));
        let (status, body) = get(state(), "/fonts/inter.woff2").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with(b"wOF2"));
        let (status, _) = get(state(), "/fonts/missing.woff2").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invitation_page_is_html() {
        let (status, body) = get(state(), "/oob?_oob=abc").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            String::from_utf8(body)
                .unwrap()
                .contains("did:web:mediator.example.com")
        );
    }

    /// A real server, a real WebSocket client: live mode pushes a message the
    /// moment it is queued, and it is acknowledged over the socket.
    #[tokio::test]
    async fn websocket_live_delivery() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as Frame;

        let state = state();
        let mediator = Arc::clone(&state.mediator);
        let identity = mediator.identity();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, app).await });

        let bob = Wallet::mediated_by(&identity.did);
        let alice = Wallet::new(Curve::X25519);
        bob.request(
            &mediator,
            "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
            json!({}),
        )
        .await;
        bob.request(
            &mediator,
            "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
            json!({"updates": [{"recipient_did": bob.did, "action": "add"}]}),
        )
        .await;

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
            .await
            .unwrap();
        async fn next_text(
            ws: &mut (
                     impl StreamExt<Item = Result<Frame, tokio_tungstenite::tungstenite::Error>> + Unpin
                 ),
        ) -> String {
            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
                    .await
                    .unwrap()
                {
                    Some(Ok(Frame::Text(text))) => return text.to_string(),
                    Some(Ok(_)) => continue,
                    other => panic!("socket ended: {other:?}"),
                }
            }
        }

        // No return_route header: on a WebSocket it is implied.
        let live_on = Message::new(
            "https://didcomm.org/messagepickup/3.0/live-delivery-change",
            json!({"live_delivery": true}),
        )
        .from(&bob.did);
        ws.send(Frame::Text(bob.send(identity, live_on, false).await.into()))
            .await
            .unwrap();
        let status = bob.open(identity, &next_text(&mut ws).await).await;
        assert_eq!(status.body["live_delivery"], true);

        // Alice's message reaches the mediator (over HTTP here) and is pushed at once.
        let packed = Message::new(
            "https://example.com/chat/1.0/message",
            json!({"text": "live!"}),
        )
        .from(&alice.did)
        .to([bob.did.as_str()])
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &Wallet::resolver(identity),
            &alice.secrets,
            almena_didcomm::PackOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            post(state.clone(), ENCRYPTED, packed.message)
                .await
                .status(),
            StatusCode::ACCEPTED
        );

        let delivery = bob.open(identity, &next_text(&mut ws).await).await;
        assert_eq!(
            delivery.type_,
            "https://didcomm.org/messagepickup/3.0/delivery"
        );
        let attachment = &delivery.attachments.unwrap()[0];
        let inner = String::from_utf8(
            almena_didcomm::b64::decode(attachment.data.base64.as_deref().unwrap()).unwrap(),
        )
        .unwrap();
        let (message, _) =
            almena_didcomm::unpack(&inner, &Wallet::resolver(identity), &bob.secrets)
                .await
                .unwrap();
        assert_eq!(message.body["text"], "live!");

        // Still queued until acknowledged.
        let ack = Message::new(
            "https://didcomm.org/messagepickup/3.0/messages-received",
            json!({"message_id_list": [attachment.id]}),
        )
        .from(&bob.did);
        ws.send(Frame::Text(bob.send(identity, ack, false).await.into()))
            .await
            .unwrap();
        let after = bob.open(identity, &next_text(&mut ws).await).await;
        assert_eq!(after.body["message_count"], 0);
        assert_eq!(after.body["live_delivery"], true);
    }
}
