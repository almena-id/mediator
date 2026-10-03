//! Operational metrics in the Prometheus text format, served on their own
//! address (`ALMENA_METRICS_ADDR`) so they never go out through the public
//! proxy. Counters only count: no DIDs, nothing per mediation.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;

use crate::push::Service;

/// The process's metrics.
pub static METRICS: Metrics = Metrics::new();

/// Where a DIDComm message came in.
#[derive(Debug, Clone, Copy)]
pub enum Transport {
    Http,
    WebSocket,
}

/// What became of a DIDComm message.
#[derive(Debug, Clone, Copy)]
pub enum MessageOutcome {
    Accepted,
    Reply,
    Rejected,
}

/// What became of a `forward` payload.
#[derive(Debug, Clone, Copy)]
pub enum Forward {
    /// Queued for a recipient mediated here.
    Queued,
    /// Relayed to another mediator on the first attempt.
    Relayed,
    /// First relay attempt failed; stored for retries.
    RelayScheduled,
    /// First relay attempt failed and could not be stored.
    RelayDropped,
    /// Refused: malformed, unknown recipient, or queue full.
    Refused,
}

/// What became of a relay retry.
#[derive(Debug, Clone, Copy)]
pub enum Retry {
    Delivered,
    Rescheduled,
    Abandoned,
}

/// What became of a push.
#[derive(Debug, Clone, Copy)]
pub enum Push {
    Delivered,
    InvalidToken,
    Failed,
}

const TRANSPORTS: [(Transport, &str); 2] = [
    (Transport::Http, "http"),
    (Transport::WebSocket, "websocket"),
];
const OUTCOMES: [(MessageOutcome, &str); 3] = [
    (MessageOutcome::Accepted, "accepted"),
    (MessageOutcome::Reply, "reply"),
    (MessageOutcome::Rejected, "rejected"),
];
const FORWARDS: [(Forward, &str); 5] = [
    (Forward::Queued, "queued"),
    (Forward::Relayed, "relayed"),
    (Forward::RelayScheduled, "relay_scheduled"),
    (Forward::RelayDropped, "relay_dropped"),
    (Forward::Refused, "refused"),
];
const RETRIES: [(Retry, &str); 3] = [
    (Retry::Delivered, "delivered"),
    (Retry::Rescheduled, "rescheduled"),
    (Retry::Abandoned, "abandoned"),
];
/// Wake-ups never go to VoIP tokens; rings go to all three.
const WAKE_SERVICES: [Service; 2] = [Service::Fcm, Service::Apns];
const RING_SERVICES: [Service; 3] = [Service::Fcm, Service::Apns, Service::ApnsVoip];
const PUSHES: [(Push, &str); 3] = [
    (Push::Delivered, "delivered"),
    (Push::InvalidToken, "invalid_token"),
    (Push::Failed, "failed"),
];

/// Upper bounds (seconds) of the buckets of `almena_didcomm_message_seconds`.
const SECONDS_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

pub struct Metrics {
    messages: [[AtomicU64; 3]; 2],
    /// Messages handled at or under each bucket's bound, then all of them.
    message_seconds: [AtomicU64; 12],
    message_micros: AtomicU64,
    store_errors: AtomicU64,
    acknowledged: AtomicU64,
    websockets: AtomicI64,
    rate_limited: AtomicU64,
    forwards: [AtomicU64; 5],
    relay_retries: [AtomicU64; 3],
    pushes: [[AtomicU64; 3]; 3],
    rings: [[AtomicU64; 3]; 3],
    live_sessions: AtomicI64,
    mediations_granted: AtomicU64,
    mediations_removed: AtomicU64,
    turn_credentials: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub const fn new() -> Self {
        Self {
            messages: [
                [const { AtomicU64::new(0) }; 3],
                [const { AtomicU64::new(0) }; 3],
            ],
            message_seconds: [const { AtomicU64::new(0) }; 12],
            message_micros: AtomicU64::new(0),
            store_errors: AtomicU64::new(0),
            acknowledged: AtomicU64::new(0),
            websockets: AtomicI64::new(0),
            rate_limited: AtomicU64::new(0),
            forwards: [const { AtomicU64::new(0) }; 5],
            relay_retries: [const { AtomicU64::new(0) }; 3],
            pushes: [const { [const { AtomicU64::new(0) }; 3] }; 3],
            rings: [const { [const { AtomicU64::new(0) }; 3] }; 3],
            live_sessions: AtomicI64::new(0),
            mediations_granted: AtomicU64::new(0),
            mediations_removed: AtomicU64::new(0),
            turn_credentials: AtomicU64::new(0),
        }
    }

    pub fn message(&self, transport: Transport, outcome: MessageOutcome) {
        inc(&self.messages[transport as usize][outcome as usize], 1);
    }

    /// How long a DIDComm message took to handle, from envelope to answer.
    pub fn message_took(&self, took: Duration) {
        let seconds = took.as_secs_f64();
        let bucket = SECONDS_BUCKETS
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(SECONDS_BUCKETS.len());
        for counter in &self.message_seconds[bucket..] {
            inc(counter, 1);
        }
        inc(
            &self.message_micros,
            u64::try_from(took.as_micros()).unwrap_or(u64::MAX),
        );
    }

    /// The store failed under a request or a background task.
    pub fn store_error(&self) {
        inc(&self.store_errors, 1);
    }

    /// Messages the wallets acknowledged (`messages-received`), so removed.
    pub fn acknowledged(&self, count: u64) {
        inc(&self.acknowledged, count);
    }

    pub fn rate_limited(&self) {
        inc(&self.rate_limited, 1);
    }

    pub fn forward(&self, forward: Forward, count: u64) {
        inc(&self.forwards[forward as usize], count);
    }

    pub fn relay_retry(&self, retry: Retry) {
        inc(&self.relay_retries[retry as usize], 1);
    }

    /// A wake-up went to one device.
    pub fn push(&self, service: Service, push: Push) {
        inc(&self.pushes[service as usize][push as usize], 1);
    }

    /// A call push went to one device (the wake-up an iPhone without a VoIP
    /// token gets instead counts here, under `apns`).
    pub fn ring(&self, service: Service, push: Push) {
        inc(&self.rings[service as usize][push as usize], 1);
    }

    pub fn websocket_opened(&self) {
        self.websockets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn websocket_closed(&self) {
        self.websockets.fetch_sub(1, Ordering::Relaxed);
    }

    /// A WebSocket turned live mode on (Message Pickup `live-delivery-change`).
    pub fn live_session_opened(&self) {
        self.live_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn live_session_closed(&self) {
        self.live_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn mediation_granted(&self) {
        inc(&self.mediations_granted, 1);
    }

    pub fn mediations_removed(&self, count: u64) {
        inc(&self.mediations_removed, count);
    }

    pub fn turn_credentials(&self) {
        inc(&self.turn_credentials, 1);
    }

    /// The Prometheus text exposition format (version 0.0.4).
    pub fn render(&self) -> String {
        let mut out = String::new();
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);

        family(
            &mut out,
            "almena_mediator_info",
            "gauge",
            "The running mediator.",
        );
        let _ = writeln!(
            out,
            "almena_mediator_info{{version=\"{}\"}} 1",
            crate::VERSION
        );

        family(
            &mut out,
            "almena_didcomm_messages_total",
            "counter",
            "DIDComm messages received, by transport and outcome.",
        );
        for (t, transport) in TRANSPORTS {
            for (o, outcome) in OUTCOMES {
                let _ = writeln!(
                    out,
                    "almena_didcomm_messages_total{{transport=\"{transport}\",outcome=\"{outcome}\"}} {}",
                    get(&self.messages[t as usize][o as usize])
                );
            }
        }

        family(
            &mut out,
            "almena_didcomm_message_seconds",
            "histogram",
            "Time to handle a DIDComm message, from envelope to answer.",
        );
        for (bucket, bound) in SECONDS_BUCKETS.iter().enumerate() {
            let _ = writeln!(
                out,
                "almena_didcomm_message_seconds_bucket{{le=\"{bound}\"}} {}",
                get(&self.message_seconds[bucket])
            );
        }
        let count = get(&self.message_seconds[SECONDS_BUCKETS.len()]);
        let _ = writeln!(
            out,
            "almena_didcomm_message_seconds_bucket{{le=\"+Inf\"}} {count}"
        );
        let _ = writeln!(
            out,
            "almena_didcomm_message_seconds_sum {}",
            get(&self.message_micros) as f64 / 1e6
        );
        let _ = writeln!(out, "almena_didcomm_message_seconds_count {count}");

        family(
            &mut out,
            "almena_store_errors_total",
            "counter",
            "Store (Redis) operations that failed.",
        );
        let _ = writeln!(out, "almena_store_errors_total {}", get(&self.store_errors));

        family(
            &mut out,
            "almena_messages_acknowledged_total",
            "counter",
            "Queued messages acknowledged by their wallets (messages-received).",
        );
        let _ = writeln!(
            out,
            "almena_messages_acknowledged_total {}",
            get(&self.acknowledged)
        );

        family(
            &mut out,
            "almena_rate_limited_total",
            "counter",
            "Requests and WebSocket messages refused by the per-IP rate limit.",
        );
        let _ = writeln!(out, "almena_rate_limited_total {}", get(&self.rate_limited));

        family(
            &mut out,
            "almena_forwards_total",
            "counter",
            "Forwarded payloads, by what became of them.",
        );
        for (f, result) in FORWARDS {
            let _ = writeln!(
                out,
                "almena_forwards_total{{result=\"{result}\"}} {}",
                get(&self.forwards[f as usize])
            );
        }

        family(
            &mut out,
            "almena_relay_retries_total",
            "counter",
            "Retries of relays to other mediators, by result.",
        );
        for (r, result) in RETRIES {
            let _ = writeln!(
                out,
                "almena_relay_retries_total{{result=\"{result}\"}} {}",
                get(&self.relay_retries[r as usize])
            );
        }

        family(
            &mut out,
            "almena_pushes_total",
            "counter",
            "Push wake-ups, by service and result.",
        );
        for service in WAKE_SERVICES {
            for (p, result) in PUSHES {
                let _ = writeln!(
                    out,
                    "almena_pushes_total{{service=\"{}\",result=\"{result}\"}} {}",
                    service.as_str(),
                    get(&self.pushes[service as usize][p as usize])
                );
            }
        }

        family(
            &mut out,
            "almena_rings_total",
            "counter",
            "Call pushes, by service and result.",
        );
        for service in RING_SERVICES {
            for (p, result) in PUSHES {
                let _ = writeln!(
                    out,
                    "almena_rings_total{{service=\"{}\",result=\"{result}\"}} {}",
                    service.as_str(),
                    get(&self.rings[service as usize][p as usize])
                );
            }
        }

        family(
            &mut out,
            "almena_websocket_connections",
            "gauge",
            "WebSocket connections open now.",
        );
        let _ = writeln!(
            out,
            "almena_websocket_connections {}",
            self.websockets.load(Ordering::Relaxed)
        );

        family(
            &mut out,
            "almena_live_sessions",
            "gauge",
            "WebSocket connections in live mode now.",
        );
        let _ = writeln!(
            out,
            "almena_live_sessions {}",
            self.live_sessions.load(Ordering::Relaxed)
        );

        family(
            &mut out,
            "almena_mediations_granted_total",
            "counter",
            "mediate-request messages granted (a repeated request counts again).",
        );
        let _ = writeln!(
            out,
            "almena_mediations_granted_total {}",
            get(&self.mediations_granted)
        );

        family(
            &mut out,
            "almena_mediations_removed_total",
            "counter",
            "Mediations removed for being idle longer than ALMENA_MEDIATION_TTL.",
        );
        let _ = writeln!(
            out,
            "almena_mediations_removed_total {}",
            get(&self.mediations_removed)
        );

        family(
            &mut out,
            "almena_turn_credentials_total",
            "counter",
            "TURN credentials issued.",
        );
        let _ = writeln!(
            out,
            "almena_turn_credentials_total {}",
            get(&self.turn_credentials)
        );
        out
    }
}

fn inc(counter: &AtomicU64, by: u64) {
    counter.fetch_add(by, Ordering::Relaxed);
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

/// `GET /metrics`, for the metrics listener only.
pub fn router() -> Router {
    Router::new().route(
        "/metrics",
        get(|| async {
            (
                [(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                METRICS.render(),
            )
                .into_response()
        }),
    )
}

/// Serves [`router`] on `addr` in the background.
pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %listener.local_addr()?, "metrics listening");
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router()).await {
            tracing::error!(error = %err, "metrics server stopped");
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_series_in_the_text_format() {
        let metrics = Metrics::new();
        metrics.message(Transport::WebSocket, MessageOutcome::Reply);
        metrics.forward(Forward::Queued, 3);
        metrics.push(Service::Apns, Push::InvalidToken);
        metrics.ring(Service::ApnsVoip, Push::Delivered);
        metrics.live_session_opened();
        metrics.websocket_opened();
        metrics.websocket_opened();
        metrics.message_took(Duration::from_millis(20));
        metrics.message_took(Duration::from_secs(60));
        let text = metrics.render();
        assert!(text.contains(
            "almena_didcomm_messages_total{transport=\"websocket\",outcome=\"reply\"} 1"
        ));
        assert!(
            text.contains("almena_didcomm_messages_total{transport=\"http\",outcome=\"reply\"} 0")
        );
        assert!(text.contains("almena_forwards_total{result=\"queued\"} 3"));
        assert!(text.contains("almena_pushes_total{service=\"apns\",result=\"invalid_token\"} 1"));
        assert!(text.contains("almena_rings_total{service=\"apns-voip\",result=\"delivered\"} 1"));
        assert!(!text.contains("almena_pushes_total{service=\"apns-voip\""));
        assert!(text.contains("almena_live_sessions 1"));
        assert!(text.contains("almena_websocket_connections 2"));
        assert!(text.contains("almena_didcomm_message_seconds_bucket{le=\"0.01\"} 0"));
        assert!(text.contains("almena_didcomm_message_seconds_bucket{le=\"0.025\"} 1"));
        assert!(text.contains("almena_didcomm_message_seconds_bucket{le=\"10\"} 1"));
        assert!(text.contains("almena_didcomm_message_seconds_bucket{le=\"+Inf\"} 2"));
        assert!(text.contains("almena_didcomm_message_seconds_count 2"));
        assert!(text.contains("almena_didcomm_message_seconds_sum 60.02"));
        // Every sample belongs to a family announced with HELP and TYPE.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let name = line.split(['{', ' ']).next().unwrap();
            let family = ["_bucket", "_sum", "_count"]
                .iter()
                .find_map(|suffix| name.strip_suffix(suffix))
                .filter(|base| text.contains(&format!("# TYPE {base} histogram")))
                .unwrap_or(name);
            assert!(text.contains(&format!("# TYPE {family} ")), "{name}");
        }
    }
}
