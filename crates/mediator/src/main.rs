use std::sync::Arc;

use std::net::SocketAddr;

use almena_mediator::config::PushMode;
use almena_mediator::dispatch::turn::TurnServer;
use almena_mediator::dispatch::{Limits, Mediator};
use almena_mediator::identity::Identity;
use almena_mediator::push::{Apns, DirectPusher, Fcm, Pusher};
use almena_mediator::store::{self, QueueLimits};
use almena_mediator::transport::{HttpTransport, Transport};
use almena_mediator::{AppState, Config, config::LogFormat, router};
use anyhow::Result;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    match std::env::args().nth(1).as_deref() {
        Some("healthcheck") => return healthcheck(&config),
        Some("rotate-keys") => {
            Identity::rotate(&config.keys_path)?;
            println!(
                "New mediator keys written to {}. Restart the mediator to use them; \
                 messages encrypted to the old keys will be refused.",
                config.keys_path.display()
            );
            return Ok(());
        }
        _ => {}
    }
    init_tracing(config.log_format);

    let identity = Identity::load_or_create(&config.keys_path, &config.public_url)?;
    let store = store::open(
        &config.redis_url,
        config.redis_password.as_ref().map(|s| s.0.as_str()),
    )
    .await?;
    if store.kind() == "memory" {
        tracing::warn!("in-memory storage: every mediation and queued message is lost on restart");
    }
    let limits = Limits {
        max_message_bytes: config.max_message_bytes,
        queue: QueueLimits {
            ttl_secs: config.queue_ttl_secs,
            max_messages: config.queue_max_messages,
            max_bytes: config.queue_max_bytes,
        },
        max_recipient_dids: config.max_recipient_dids,
        push_min_interval_secs: config.push.min_interval_secs,
        push_ring_interval_secs: config.push.ring_interval_secs,
        recipient_proof: config.recipient_proof,
        mediation_ttl_secs: config.mediation_ttl_secs,
    };
    let transport: Option<Arc<dyn Transport>> = if config.federation {
        if config.outbound_allow_insecure {
            tracing::warn!(
                "outbound requests may use plain HTTP and private addresses (ALMENA_OUTBOUND_ALLOW_INSECURE)"
            );
        }
        Some(Arc::new(HttpTransport::new(
            config.outbound_allow_insecure,
        )?))
    } else {
        None
    };
    let mut mediator = Mediator::new(identity, Arc::clone(&store), limits, transport);
    if config.push.mode == PushMode::Direct {
        let fcm = config
            .push
            .fcm_service_account
            .as_deref()
            .map(Fcm::from_file)
            .transpose()?;
        let apns = config.push.apns.as_ref().map(Apns::new).transpose()?;
        let pusher = DirectPusher::new(fcm, apns);
        let services: Vec<_> = pusher.services().iter().map(|s| s.as_str()).collect();
        tracing::info!(?services, "push wake-ups on (direct)");
        mediator = mediator.with_pusher(Arc::new(pusher));
    }
    if let Some(turn) = &config.turn {
        tracing::info!(urls = ?turn.urls, ttl = turn.ttl_secs, "TURN credentials on");
        mediator = mediator.with_turn(TurnServer::new(
            turn.urls.clone(),
            &turn.secret.0,
            turn.ttl_secs,
        ));
    }
    mediator.start_relay_retries();
    mediator.start_cleanup();
    let did = mediator.identity().did.clone();
    let (stop, mut stopping) = tokio::sync::watch::channel(false);
    let state = AppState {
        mediator: Arc::new(mediator),
        store,
        rate_limit: config.rate_limit,
        public_url: config.public_url.clone(),
        client_ip_header: config
            .client_ip_header
            .as_deref()
            .map(axum::http::HeaderName::try_from)
            .transpose()?,
        sockets: Arc::default(),
        stopping: stopping.clone(),
    };

    if let Some(addr) = config.metrics_addr {
        almena_mediator::metrics::serve(addr).await?;
    }
    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, %did, version = almena_mediator::VERSION, "almena mediator listening");

    let server = axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = stop.send(true);
    });
    // Requests in flight get SHUTDOWN_GRACE to finish (a relay's first
    // attempts can take a while); then the process stops anyway, before the
    // container runtime kills it (compose.yml's stop_grace_period is longer).
    let deadline = async {
        let _ = stopping.wait_for(|stopping| *stopping).await;
        tokio::time::sleep(SHUTDOWN_GRACE).await;
    };
    tokio::select! {
        served = std::future::IntoFuture::into_future(server) => served?,
        () = deadline => tracing::warn!(
            grace_secs = SHUTDOWN_GRACE.as_secs(),
            "requests still in flight after the grace period, stopping anyway"
        ),
    }

    tracing::info!("almena mediator stopped");
    Ok(())
}

/// How long requests in flight may take to finish once a shutdown starts.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(20);

/// `almena-mediator healthcheck`: exits 0 if `/health` answers 200. Used by the
/// container healthcheck, since the runtime image ships no curl.
fn healthcheck(config: &Config) -> Result<()> {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;

    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), config.bind.port());
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    anyhow::ensure!(
        response.starts_with("HTTP/1.1 200"),
        "unhealthy: {}",
        response.lines().next().unwrap_or("")
    );
    Ok(())
}

/// Log level comes from `RUST_LOG` (default `info`).
fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Pretty => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
}

/// Resolves on Ctrl+C or SIGTERM (what `docker stop` sends).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
