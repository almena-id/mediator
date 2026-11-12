use std::sync::Arc;

use std::net::SocketAddr;

use almena_mediator::admin::{AdminStore, InvitationKind};
use almena_mediator::config::{Access, PushMode};
use almena_mediator::dispatch::{Limits, Mediator};
use almena_mediator::identity::Identity;
use almena_mediator::push::{Apns, DirectPusher, Fcm, Pusher};
use almena_mediator::routes::Sockets;
use almena_mediator::store::{self, QueueLimits};
use almena_mediator::transport::{HttpTransport, Transport};
use almena_mediator::{AppState, Config, config::LogFormat, router};
use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    match std::env::args().nth(1).as_deref() {
        Some("healthcheck") => return healthcheck(&config),
        Some("setup") => return setup_code(&config),
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

    let admin = Arc::new(AdminStore::open(&config.admin_db_path)?);
    let before = admin.site()?.map(|site| site.public_url);
    let site = admin.settle(config.public_url.as_deref(), config.access)?;
    // A setup code while nobody runs it. Not after a move from the portal:
    // the administrators were invited again at the new address, and a code
    // in the log would let whoever reads it claim it before they do. Once
    // those invitations are spent or expired with nobody back, or when the
    // move came from `ALMENA_PUBLIC_URL` (nobody was shown one), it is.
    let moved_by_variable =
        before.is_some() && before.as_deref() != site.as_ref().map(|site| site.public_url.as_str());
    let reinvited = !admin
        .invitations(InvitationKind::Admin, almena_didcomm::message::now())?
        .is_empty();
    let setup_code = if admin.admin_count()? == 0 && (moved_by_variable || !reinvited) {
        let code = admin.new_setup_code()?;
        let at = site.as_ref().map_or_else(
            || format!("http://<this host>:{}", config.bind.port()),
            |site| site.public_url.clone(),
        );
        let step = if site.is_some() {
            "become its first administrator with your Almena wallet"
        } else {
            "give its public URL, choose public or private, and prove the domain"
        };
        announce_setup_code(config.log_format, &code, &at, step);
        Some(code)
    } else {
        None
    };
    let site = match site {
        Some(site) => site,
        None => {
            let listener = TcpListener::bind(config.bind).await?;
            tracing::info!(addr = %listener.local_addr()?, version = almena_mediator::VERSION, "almena mediator waiting to be set up");
            match almena_mediator::setup::run(
                listener,
                Arc::clone(&admin),
                config.outbound_allow_insecure,
                shutdown_signal(),
            )
            .await?
            {
                Some(site) => {
                    if let Some(code) = &setup_code {
                        announce_setup_code(
                            config.log_format,
                            code,
                            &site.public_url,
                            "become its first administrator with your Almena wallet (the domain is proven; the setup page goes on there by itself)",
                        );
                    }
                    site
                }
                None => {
                    tracing::info!("almena mediator stopped before it was set up");
                    return Ok(());
                }
            }
        }
    };

    let identity = Identity::load_or_create(&config.keys_path, &site.public_url)?;
    let store = store::open(&config.db_path)?;
    if config.db_path == ":memory:" {
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
        max_mediations: config.max_mediations,
        push_min_interval_secs: config.push.min_interval_secs,
        recipient_proof: config.recipient_proof,
        mediation_ttl_secs: config.mediation_ttl_secs,
        relay_rate_limit: config.relay_rate_limit,
        private: site.access == Access::Private,
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
    let mut mediator = Mediator::new(identity, Arc::clone(&store), limits, transport)
        .with_admin(Arc::clone(&admin));
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
    mediator.start_relays();
    mediator.start_cleanup();
    mediator.start_capacity_watch();
    let did = mediator.identity().did.clone();
    let (stop, mut stopping) = tokio::sync::watch::channel(false);
    let restart = Arc::new(tokio::sync::Notify::new());
    let moved = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let state = AppState {
        mediator: Arc::new(mediator),
        store,
        rate_limit: config.rate_limit,
        rate_limit_on_error: config.rate_limit_on_error,
        trusted_proxies: Arc::from(config.trusted_proxies.clone()),
        public_url: site.public_url.clone(),
        client_ip_header: config
            .client_ip_header
            .as_deref()
            .map(axum::http::HeaderName::try_from)
            .transpose()?,
        sockets: Arc::new(Sockets::new(config.max_sockets)),
        stopping: stopping.clone(),
        admin: Arc::clone(&admin),
        signins: Arc::default(),
        url_pinned: config.public_url.is_some(),
        allow_insecure: config.outbound_allow_insecure,
        restart: Arc::clone(&restart),
    };

    if let Some(addr) = config.metrics_addr {
        almena_mediator::metrics::serve(addr).await?;
    }
    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, %did, access = site.access.as_str(), version = almena_mediator::VERSION, "almena mediator listening");

    let server = axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown({
        let restart = Arc::clone(&restart);
        let moved = Arc::clone(&moved);
        async move {
            tokio::select! {
                () = shutdown_signal() => {}
                () = restart.notified() => {
                    moved.store(true, std::sync::atomic::Ordering::SeqCst);
                    tracing::info!("the public URL moved: restarting");
                }
            }
            let _ = stop.send(true);
        }
    });
    // Requests in flight get SHUTDOWN_GRACE to finish; then the process
    // stops anyway, before the container runtime kills it (compose.yml's
    // stop_grace_period is longer). Relays being sent are leased in the
    // store: one cut short is tried again once its lease runs out.
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

    if moved.load(std::sync::atomic::Ordering::SeqCst) {
        return relaunch();
    }
    tracing::info!("almena mediator stopped");
    Ok(())
}

/// Starts this program again in this process — same arguments, same
/// environment, same process id (a container keeps running) — so the
/// mediator comes up as the site's new `did:web`, with nothing of the old
/// one left running.
#[cfg(unix)]
fn relaunch() -> Result<()> {
    use std::os::unix::process::CommandExt;
    let program = std::env::current_exe().context("finding this program")?;
    let error = std::process::Command::new(program)
        .args(std::env::args_os().skip(1))
        .exec();
    Err(error).context("restarting the mediator")
}

/// Windows has no `exec`: the new mediator runs as a child with this
/// process's arguments, environment and console, and this one waits for it
/// and leaves with its exit code, so whatever started the mediator still
/// sees one process running until the mediator stops.
#[cfg(not(unix))]
fn relaunch() -> Result<()> {
    let program = std::env::current_exe().context("finding this program")?;
    let status = std::process::Command::new(program)
        .args(std::env::args_os().skip(1))
        .status()
        .context("restarting the mediator")?;
    std::process::exit(status.code().unwrap_or(1))
}

/// `almena-mediator setup`: prints a new setup code, replacing the one in
/// the log, while the mediator has no administrator.
fn setup_code(config: &almena_mediator::Config) -> Result<()> {
    let admin = AdminStore::open(&config.admin_db_path)
        .with_context(|| format!("opening {}", config.admin_db_path.display()))?;
    anyhow::ensure!(
        admin.admin_count()? == 0,
        "this mediator has administrators already: they manage it from its portal"
    );
    let code = admin.new_setup_code()?;
    let at = admin.site()?.map_or_else(
        || "http://<this host>:<port>".to_owned(),
        |site| site.public_url,
    );
    println!(
        "Setup code: {code}\nOpen:       {at}/setup and enter it\nIt works until the first administrator signs in; any earlier code no longer works."
    );
    Ok(())
}

/// Puts the setup code where whoever runs the mediator cannot miss it: one
/// log line whose message carries the code and the page to enter it on
/// (`setup_code` and `setup_url` as fields too, for JSON logs), and, with
/// readable logs, a framed block on stderr as well. The link never carries
/// the code: a URL ends up in access logs and browser histories.
fn announce_setup_code(format: LogFormat, code: &str, at: &str, step: &str) {
    let url = format!("{at}/setup");
    tracing::warn!(
        setup_code = %code,
        setup_url = %url,
        "SETUP CODE {code}: open {url} and enter it to {step}. It works until the first administrator signs in; `almena-mediator setup` prints a new one"
    );
    if format == LogFormat::Pretty {
        let lines = [
            "ALMENA MEDIATOR: SETUP CODE".to_owned(),
            String::new(),
            format!("  Code   {code}"),
            format!("  Open   {url} and enter the code"),
            format!("  Then   {step}"),
            String::new(),
            "It works until the first administrator signs in.".to_owned(),
            "`almena-mediator setup` prints a new one (the old one stops working).".to_owned(),
        ];
        let width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
        let rule = "═".repeat(width + 2);
        let body: String = lines
            .iter()
            .map(|line| format!("║ {line:<width$} ║\n"))
            .collect();
        eprintln!("\n╔{rule}╗\n{body}╚{rule}╝\n");
    }
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
