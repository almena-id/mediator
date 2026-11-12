//! The onboarding of a mediator that is not set up yet: the one-time setup
//! code (from the log, or `almena-mediator setup`) opens `/setup`, where the
//! operator gives the URL the mediator will be published at and chooses
//! public or private. The URL is then proven twice before it becomes the
//! mediator's `did:web`:
//!
//! - **DNS**: a TXT record at `_almena-mediator.<host>` holds a random value
//!   the page shows — whoever set it controls the domain;
//! - **HTTPS**: `https://<host>/.well-known/almena-setup` answers that same
//!   value — the domain, its proxy and its certificate lead here, which is
//!   what other mediators and wallets need to reach it.
//!
//! Until then this module's router is all the mediator serves (and `/health`
//! answers `200`, status `setup`, so whatever waits on it can start). Once
//! both checks pass, the URL and the mode are written and [`run`] returns:
//! the full mediator starts on the same port, and `/setup` there makes the
//! first administrator. The mode never changes; the URL can move later,
//! from the portal, proven the same way (`portal::site`).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::extract::{Form, Path, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::net::IpAddr;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, GOOGLE, NameServerConfig, ResolverConfig};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::admin::{AdminStore, Pending, Site};
use crate::config::Access;
use crate::home::{self, escape, layout};

/// Where the HTTPS check looks for the value.
pub const WELL_KNOWN: &str = "/.well-known/almena-setup";
/// The label the DNS record goes under: `_almena-mediator.<host>`.
pub const DNS_LABEL: &str = "_almena-mediator";

#[derive(Clone)]
struct SetupState {
    admin: Arc<AdminStore>,
    /// Lets the HTTPS check reach private addresses
    /// (`ALMENA_OUTBOUND_ALLOW_INSECURE`): a domain pointed at this machine
    /// or the local network while trying the onboarding locally.
    allow_insecure: bool,
    done: tokio::sync::watch::Sender<bool>,
}

/// Serves the onboarding on `listener` until the site is set up — then
/// returns it — or until `shutdown` resolves, with `None`.
pub async fn run(
    listener: TcpListener,
    admin: Arc<AdminStore>,
    allow_insecure: bool,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<Option<Site>> {
    let (done, mut finished) = tokio::sync::watch::channel(false);
    let state = SetupState {
        admin: Arc::clone(&admin),
        allow_insecure,
        done,
    };
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = finished.wait_for(|done| *done) => {}
                () = shutdown => {}
            }
        })
        .await?;
    admin.site()
}

fn router(state: SetupState) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/setup") }))
        .route("/setup", get(ask).post(start))
        .route("/setup/site", post(site))
        .route("/setup/check", post(check))
        .route(WELL_KNOWN, get(well_known))
        .route("/health", get(health))
        .route(home::ICON_PATH, get(icon))
        .route("/fonts/{name}", get(font))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// The setup code, always in a form's body: in a URL it would stay in the
/// proxy's access log and the browser's history.
#[derive(Deserialize)]
struct CodeForm {
    code: String,
    /// Back to the URL and mode, to prove another one.
    change: Option<String>,
}

#[derive(Deserialize)]
struct SiteForm {
    code: String,
    url: String,
    access: String,
}

#[derive(Deserialize)]
struct CheckForm {
    code: String,
}

/// `GET /setup`: asks for the code.
async fn ask() -> Response {
    page(ask_code(None)).into_response()
}

/// `POST /setup`: with a valid code, asks for the URL and the mode (or says
/// where the proof of the last one stands).
async fn start(State(state): State<SetupState>, Form(query): Form<CodeForm>) -> Response {
    let code = query.code.trim().to_owned();
    if code.is_empty() {
        return page(ask_code(None)).into_response();
    }
    match state.admin.is_setup_code(&code) {
        Ok(true) => {}
        Ok(false) => return page(ask_code(Some("That is not the setup code."))).into_response(),
        Err(err) => return failed(&err),
    }
    match state.admin.pending() {
        Ok(Some(pending)) if query.change.is_none() => {
            page(prove(&code, &pending, None)).into_response()
        }
        Ok(Some(pending)) => {
            page(ask_site(&code, None, &pending.public_url, pending.access)).into_response()
        }
        Ok(None) => page(ask_site(&code, None, "", Access::Public)).into_response(),
        Err(err) => failed(&err),
    }
}

/// `POST /setup/site`: the URL and the mode; the value to prove it with.
async fn site(State(state): State<SetupState>, Form(form): Form<SiteForm>) -> Response {
    match state.admin.is_setup_code(&form.code) {
        Ok(true) => {}
        Ok(false) => return page(ask_code(Some("That is not the setup code."))).into_response(),
        Err(err) => return failed(&err),
    }
    let access = Access::parse(&form.access).unwrap_or(Access::Public);
    let url = match origin(&form.url) {
        Ok(url) => url,
        Err(why) => {
            return page(ask_site(&form.code, Some(why), &form.url, access)).into_response();
        }
    };
    match state.admin.start_pending(&url, access) {
        Ok(pending) => page(prove(&form.code, &pending, None)).into_response(),
        Err(err) => failed(&err),
    }
}

/// `POST /setup/check`: looks for the DNS record and asks the domain over
/// HTTPS; with both right, fixes the site and hands over to the mediator.
async fn check(State(state): State<SetupState>, Form(form): Form<CheckForm>) -> Response {
    match state.admin.is_setup_code(&form.code) {
        Ok(true) => {}
        Ok(false) => return page(ask_code(Some("That is not the setup code."))).into_response(),
        Err(err) => return failed(&err),
    }
    let pending = match state.admin.pending() {
        Ok(Some(pending)) => pending,
        Ok(None) => {
            return page(ask_site(&form.code, None, "", Access::Public)).into_response();
        }
        Err(err) => return failed(&err),
    };
    let dns = dns_holds(&pending).await;
    let https = https_answers(&pending, state.allow_insecure).await;
    if let (Ok(()), Ok(())) = (&dns, &https) {
        let site = Site {
            public_url: pending.public_url.clone(),
            access: pending.access,
        };
        if let Err(err) = state.admin.set_site(&site) {
            return failed(&err);
        }
        tracing::info!(url = %site.public_url, access = site.access.as_str(), "mediator set up");
        let _ = state.done.send(true);
        return page(set_up(&site, &form.code)).into_response();
    }
    page(prove(&form.code, &pending, Some((dns, https)))).into_response()
}

/// `GET /.well-known/almena-setup`: the value being proven, for the HTTPS
/// check this very mediator makes through its public URL.
async fn well_known(State(state): State<SetupState>) -> Response {
    match state.admin.pending() {
        Ok(Some(pending)) => (
            [
                (header::CONTENT_TYPE, "text/plain"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            pending.token,
        )
            .into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `200` while waiting to be set up: the process is fine, and a proxy that
/// waits for it to be healthy must start for the HTTPS check to pass.
async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "setup",
        "service": env!("CARGO_PKG_NAME"),
        "version": crate::VERSION,
    }))
}

async fn icon() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/png")], home::ICON)
}

async fn font(Path(name): Path<String>) -> Response {
    match home::font(&name) {
        Some(bytes) => ([(header::CONTENT_TYPE, "font/woff2")], bytes).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The origin to publish the mediator at, from what the operator typed: a
/// host or an `https://` URL with nothing after the host but a `/`. Only a
/// domain will do: a `did:web` names one, and DNS proves it.
pub(crate) fn origin(input: &str) -> Result<String, &'static str> {
    let input = input.trim();
    let with_scheme = if input.contains("://") {
        input.to_owned()
    } else {
        format!("https://{input}")
    };
    let url = url::Url::parse(&with_scheme).map_err(|_| "That is not a URL.")?;
    if url.scheme() != "https" {
        return Err("The URL must start with https://.");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("The URL cannot carry a user or a password.");
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("Give the address alone, with nothing after the domain.");
    }
    let Some(url::Host::Domain(host)) = url.host() else {
        return Err("Give a domain name, not an IP address.");
    };
    if !host.contains('.') {
        return Err("Give a full domain name, such as mediator.example.com.");
    }
    let origin = match url.port() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    };
    almena_didcomm::did::web::did_from_origin(&origin).map_err(|_| "That is not a URL.")?;
    Ok(origin)
}

/// The host of an origin `origin` made.
pub(crate) fn host_of(public_url: &str) -> String {
    url::Url::parse(public_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Whether a TXT record at `_almena-mediator.<host>` holds the value.
///
/// **Asked where no cache can hide it.** A resolver that was asked before the
/// record existed keeps answering "no such name" for as long as the zone's
/// negative TTL says (often 30 minutes or more) — the system's, a router's,
/// a VPN's. So the domain's own name servers are asked first, without
/// recursion and without a cache (found through public resolvers); then the
/// public resolvers themselves; then the system's, for a network where only
/// it can be reached. The record counts as soon as one of them shows it.
pub(crate) async fn dns_holds(pending: &Pending) -> Result<(), String> {
    let host = host_of(&pending.public_url);
    let name = format!("{DNS_LABEL}.{host}.");
    let shown = name.trim_end_matches('.').to_owned();
    let public = public_resolver().map_err(|err| format!("No DNS resolver: {err}"))?;

    let mut heard = Vec::new();
    let servers = authoritative_servers(&public, &host).await;
    if !servers.is_empty() {
        let ips: Vec<IpAddr> = servers.iter().flat_map(|(_, ips)| ips.clone()).collect();
        if let Ok(resolver) = resolver(
            ResolverConfig::from_name_servers(
                ips.into_iter().map(NameServerConfig::udp_and_tcp).collect(),
            ),
            false,
        ) {
            let names: Vec<&str> = servers.iter().map(|(name, _)| name.as_str()).collect();
            heard.push((
                format!("the domain's name servers ({})", names.join(", ")),
                txt(&resolver, &name).await,
            ));
        }
    }
    heard.push((
        "public resolvers (1.1.1.1, 8.8.8.8)".to_owned(),
        txt(&public, &name).await,
    ));
    if let Ok(system) = TokioResolver::builder_tokio().and_then(|builder| {
        let mut builder = builder;
        builder.options_mut().cache_size = 0;
        builder.build()
    }) {
        heard.push((
            "this machine's resolver".to_owned(),
            txt(&system, &name).await,
        ));
    }

    if heard.iter().any(|(_, found)| {
        found
            .as_ref()
            .is_ok_and(|values| values.iter().any(|v| v.trim() == pending.token))
    }) {
        return Ok(());
    }
    // Say what the most trustworthy source that answered at all saw.
    let (who, found) = heard
        .iter()
        .find(|(_, found)| found.is_ok())
        .or_else(|| heard.first())
        .map(|(who, found)| (who.as_str(), found.clone()))
        .unwrap_or(("nobody", Err(())));
    match found {
        Ok(values) if values.is_empty() => Err(format!("No TXT record found at {shown} by {who}.")),
        Ok(values) => Err(format!(
            "The TXT record at {shown} holds {}, not the value below (asked {who}).",
            values
                .iter()
                .map(|v| format!("\"{}\"", v.chars().take(80).collect::<String>()))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        Err(()) => Err(format!(
            "{shown} could not be looked up: no DNS server answered."
        )),
    }
}

/// A resolver over `config` that keeps nothing: every check asks again.
fn resolver(config: ResolverConfig, recursion: bool) -> Result<TokioResolver, NetError> {
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    let options = builder.options_mut();
    options.cache_size = 0;
    options.recursion_desired = recursion;
    options.timeout = Duration::from_secs(3);
    options.attempts = 2;
    builder.build()
}

/// Cloudflare's and Google's public resolvers, without a cache of ours.
fn public_resolver() -> Result<TokioResolver, NetError> {
    let mut config = ResolverConfig::udp_and_tcp(&CLOUDFLARE);
    for server in GOOGLE.udp_and_tcp() {
        config.add_name_server(server);
    }
    resolver(config, true)
}

/// The name servers of the zone `host` is in, with their addresses: the
/// first of `host` and its parents that has `NS` records.
async fn authoritative_servers(public: &TokioResolver, host: &str) -> Vec<(String, Vec<IpAddr>)> {
    let labels: Vec<&str> = host.split('.').collect();
    for start in 0..labels.len().saturating_sub(1) {
        let zone = format!("{}.", labels[start..].join("."));
        let Ok(lookup) = public.lookup(zone.as_str(), RecordType::NS).await else {
            continue;
        };
        let names: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::NS(ns) => Some(ns.0.to_string()),
                _ => None,
            })
            .collect();
        if names.is_empty() {
            continue;
        }
        let mut servers = Vec::new();
        for name in names {
            // The zone names its servers: only public addresses are asked,
            // so a zone cannot point the check at this mediator's network.
            if let Ok(ips) = public.lookup_ip(name.as_str()).await {
                let ips: Vec<IpAddr> = ips
                    .iter()
                    .filter(|ip| crate::transport::is_public(*ip))
                    .collect();
                if !ips.is_empty() {
                    servers.push((name.trim_end_matches('.').to_owned(), ips));
                }
            }
        }
        return servers;
    }
    Vec::new()
}

/// The TXT values at `name`: empty when there are none, `Err` when nobody
/// answered at all.
async fn txt(resolver: &TokioResolver, name: &str) -> Result<Vec<String>, ()> {
    match resolver.lookup(name, RecordType::TXT).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|part| String::from_utf8_lossy(part).into_owned())
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect()),
        Err(err) if err.is_no_records_found() || err.is_nx_domain() => Ok(Vec::new()),
        Err(_) => Err(()),
    }
}

/// Whether `https://<host>/.well-known/almena-setup` answers the value:
/// the public URL reaches this mediator, through its proxy and certificate.
/// The host must resolve to public addresses (the same guard as federation's
/// requests), so the check cannot be pointed into the network the mediator
/// sits in; `allow_insecure` lifts that for trying it locally.
pub(crate) async fn https_answers(pending: &Pending, allow_insecure: bool) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .user_agent(format!("almena-mediator/{}", crate::VERSION))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true);
    let client = if allow_insecure {
        client
    } else {
        client.dns_resolver(crate::transport::PublicOnlyResolver)
    };
    let client = client
        .build()
        .map_err(|err| format!("No HTTP client: {err}"))?;
    let url = format!("{}{WELL_KNOWN}", pending.public_url);
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|err| format!("{url} cannot be reached: {}", short(&err)))?;
    if !response.status().is_success() {
        return Err(format!("{url} answered {}.", response.status()));
    }
    let body = response
        .text()
        .await
        .map_err(|err| format!("{url} cannot be read: {}", short(&err)))?;
    if body.trim() == pending.token {
        Ok(())
    } else {
        Err(format!(
            "{url} answers, but not with this mediator's value: the domain leads somewhere else."
        ))
    }
}

/// The innermost cause of a request error: "certificate expired", not the
/// wrapper around it.
fn short(err: &reqwest::Error) -> String {
    let mut source: &dyn std::error::Error = err;
    while let Some(inner) = source.source() {
        source = inner;
    }
    source.to_string()
}

// ---- pages ----

pub(crate) const SETUP_CSS: &str = r#"
main{text-align:left;align-items:stretch;max-width:44rem;margin-inline:auto}
h1{margin:0;font-size:1.75rem}
p{margin:0;color:var(--muted)}
form{display:flex;flex-direction:column;gap:1rem}
label{display:flex;flex-direction:column;gap:.375rem;font-size:.875rem}
input[type=text]{padding:.6rem .75rem;border:1px solid var(--border);border-radius:10px;background:var(--surface);color:var(--text);font:inherit;font-family:var(--font-mono)}
fieldset{display:flex;flex-direction:column;gap:.5rem;margin:0;padding:.75rem 1rem;border:1px solid var(--border);border-radius:12px}
legend{padding:0 .25rem;font-size:.875rem}
fieldset label{flex-direction:row;align-items:baseline;gap:.5rem}
fieldset small{display:block;color:var(--muted)}
button{align-self:flex-start;padding:.6rem 1.25rem;border:0;border-radius:999px;background:var(--brand);color:#fff;font:inherit;font-size:.875rem;font-weight:500;cursor:pointer}
button:hover{filter:brightness(1.1)}
.error{padding:.6rem .85rem;border:1px solid var(--down);border-radius:10px;color:var(--text)}
.steps{display:flex;flex-direction:column;gap:1rem;margin:0;padding-left:1.25rem}
.steps li{line-height:1.7}
.value{display:flex;align-items:center;gap:.75rem;margin:.375rem 0;padding:.5rem .5rem .5rem .75rem;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
.value code{flex:1;min-width:0}
button.copy{flex:none;align-self:center;padding:.3rem .8rem;border:1px solid var(--border);background:transparent;color:var(--text);font-size:.8rem}
button.copy.done{border-color:var(--ok);color:var(--ok)}
form.inline-link{display:block}
button.link{display:inline;padding:0;border:0;border-radius:0;background:none;color:var(--brand);font-weight:inherit;font-size:inherit;text-decoration:underline;cursor:pointer}
.result{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:.375rem;font-size:.875rem}
.result li::before{content:"";display:inline-block;width:.5rem;height:.5rem;margin-right:.5rem;border-radius:50%;background:var(--c)}
.pass{--c:var(--ok)}.fail{--c:var(--down)}
.progress{display:flex;flex-wrap:wrap;gap:.25rem .5rem;list-style:none;margin:0;padding:0;font-size:.8rem;color:var(--muted);counter-reset:step}
.progress li{counter-increment:step;display:flex;align-items:center;gap:.375rem}
.progress li::before{content:counter(step);display:inline-grid;place-items:center;width:1.4rem;height:1.4rem;border:1px solid var(--border);border-radius:50%;font-size:.75rem}
.progress li+li::after{order:-1;content:"";width:1rem;height:1px;background:var(--border)}
.progress .done::before{content:"✓";border-color:var(--ok);color:var(--ok)}
.progress .now{color:var(--text);font-weight:500}
.progress .now::before{border-color:var(--brand);background:var(--brand);color:#fff}
.note{padding:.6rem .85rem;border:1px solid var(--border);border-radius:10px;background:var(--surface);font-size:.875rem}
"#;

/// The onboarding's steps, `at` the current one (0-based).
pub(crate) fn progress(at: usize) -> String {
    const STEPS: [&str; 4] = [
        "Setup code",
        "Address and access",
        "Prove the domain",
        "First administrator",
    ];
    let items: String = STEPS
        .iter()
        .enumerate()
        .map(|(n, step)| {
            let class = match n.cmp(&at) {
                std::cmp::Ordering::Less => " class=\"done\"",
                std::cmp::Ordering::Equal => " class=\"now\" aria-current=\"step\"",
                std::cmp::Ordering::Greater => "",
            };
            format!("<li{class}>{step}</li>")
        })
        .collect();
    format!(r#"<ol class="progress" aria-label="Onboarding">{items}</ol>"#)
}

fn page(main: String) -> Html<String> {
    Html(layout("Set up · Almena Mediator", SETUP_CSS, &main))
}

fn error_box(why: Option<&str>) -> String {
    why.map(|why| format!(r#"<p class="error">{}</p>"#, escape(why)))
        .unwrap_or_default()
}

pub(crate) fn ask_code(why: Option<&str>) -> String {
    format!(
        r#"{progress}<h1>Set up this mediator</h1>
<p>It is not set up yet. Enter the setup code: it is in the mediator's log, and <code>almena-mediator setup</code> prints a new one.</p>
{error}
<form method="post" action="/setup">
<label>Setup code<input type="text" name="code" autocomplete="off" required></label>
<button type="submit">Continue</button>
</form>"#,
        progress = progress(0),
        error = error_box(why),
    )
}

fn ask_site(code: &str, why: Option<&str>, url: &str, access: Access) -> String {
    let checked = |a: Access| if a == access { " checked" } else { "" };
    format!(
        r#"{progress}<h1>Where it will live</h1>
<p>The address the mediator will be published at becomes its identity (<code>did:web</code>). Its administrators can move it later, proving the new domain the same way, but every wallet then connects again.</p>
<p>Who may use it is chosen now and <strong>never changes</strong>: to change it, a new mediator is set up from scratch.</p>
{error}
<form method="post" action="/setup/site">
<input type="hidden" name="code" value="{code}">
<label>Public URL<input type="text" name="url" value="{url}" placeholder="https://mediator.example.com" autocomplete="off" required></label>
<fieldset><legend>Who may use it</legend>
<label><input type="radio" name="access" value="public"{public}><span>Public<small>Any wallet can keep its mailbox here.</small></span></label>
<label><input type="radio" name="access" value="private"{private}><span>Private<small>Only the wallets its administrators invite.</small></span></label>
</fieldset>
<button type="submit">Continue</button>
</form>"#,
        progress = progress(1),
        error = error_box(why),
        code = escape(code),
        url = escape(url),
        public = checked(Access::Public),
        private = checked(Access::Private),
    )
}

pub(crate) type Outcome = (Result<(), String>, Result<(), String>);

/// The two proofs to set up for `pending`, and how the last check went.
pub(crate) fn proof_steps(pending: &Pending, outcome: Option<Outcome>) -> String {
    let host = host_of(&pending.public_url);
    let result = outcome
        .map(|(dns, https)| {
            let line = |label: &str, result: &Result<(), String>| match result {
                Ok(()) => format!(r#"<li class="pass">{label}: found.</li>"#),
                Err(why) => format!(r#"<li class="fail">{label}: {}</li>"#, escape(why)),
            };
            format!(
                r#"<ul class="result">{}{}</ul>"#,
                line("DNS", &dns),
                line("HTTPS", &https)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<ol class="steps">
<li>Add a TXT record to the domain's DNS, named{name}with this value:{token}</li>
<li>Point <code>{host}</code> at this mediator, through a proxy with a valid certificate. This address must answer the same value:{address}</li>
</ol>
{result}
<script>{COPY_SCRIPT}</script>"#,
        name = copyable(&format!("{DNS_LABEL}.{host}")),
        token = copyable(&pending.token),
        address = copyable(&format!("{}{WELL_KNOWN}", pending.public_url)),
        host = escape(&host),
    )
}

/// A value to type somewhere else, with a button that copies it.
fn copyable(value: &str) -> String {
    let value = escape(value);
    format!(
        r#"<span class="value"><code>{value}</code><button type="button" class="copy" data-copy="{value}">Copy</button></span>"#
    )
}

/// Copies a `.copy` button's value: the Clipboard API where the page is a
/// secure context, else a selected text area (plain HTTP during setup), and
/// says so on the button for a moment.
const COPY_SCRIPT: &str = r#"document.addEventListener("click",async e=>{const b=e.target.closest("button.copy");if(!b)return;const v=b.dataset.copy;let ok=false;try{await navigator.clipboard.writeText(v);ok=true}catch{const t=document.createElement("textarea");t.value=v;t.setAttribute("readonly","");t.style.position="fixed";t.style.opacity="0";document.body.append(t);t.select();try{ok=document.execCommand("copy")}catch{}t.remove()}b.textContent=ok?"Copied":"Select and copy";b.classList.toggle("done",ok);setTimeout(()=>{b.textContent="Copy";b.classList.remove("done")},1600)});"#;

fn prove(code: &str, pending: &Pending, outcome: Option<Outcome>) -> String {
    format!(
        r#"{progress}<h1>Prove the domain</h1>
<p><code>{url}</code>, {access}.</p>
{steps}
<form method="post" action="/setup/check">
<input type="hidden" name="code" value="{code}">
<button type="submit">Check</button>
</form>
<form method="post" action="/setup" class="inline-link">
<input type="hidden" name="code" value="{code}">
<input type="hidden" name="change" value="1">
<p><button type="submit" class="link">Use another URL</button>. The value belongs to the domain: another domain has another one, and this one keeps it however often you come back to it.</p>
</form>"#,
        progress = progress(2),
        url = escape(&pending.public_url),
        access = pending.access.as_str(),
        steps = proof_steps(pending, outcome),
        code = escape(code),
    )
}

/// The domain is proven: the mediator starts in full, and this page goes on
/// by itself to becoming its first administrator — a code for the wallet at
/// the public URL — as soon as the mediator answers there. The setup code
/// goes in a form's body, as everywhere; the button is there for a browser
/// without scripts.
fn set_up(site: &Site, code: &str) -> String {
    format!(
        r#"{progress}<h1>Domain proven</h1>
<p>This mediator is now <code>{did}</code>, {access}.</p>
<p id="starting" role="status">Starting it at its public URL… Then your Almena wallet makes you its first administrator.</p>
<form method="post" action="{url}/setup" id="claim">
<input type="hidden" name="code" value="{code}">
<button type="submit">Become its administrator</button>
</form>
<script>
const go=async(tries)=>{{try{{const r=await fetch("/health",{{cache:"no-store"}});if(r.ok){{const j=await r.json();if(j.status!=="setup"){{document.getElementById("claim").submit();return}}}}}}catch{{}}if(tries>0)setTimeout(()=>go(tries-1),1000);else document.getElementById("starting").textContent="It is taking a while: press the button when the mediator answers."}};
go(60);
</script>"#,
        did = escape(
            &almena_didcomm::did::web::did_from_origin(&site.public_url).unwrap_or_default()
        ),
        progress = progress(3),
        access = site.access.as_str(),
        url = escape(&site.public_url),
        code = escape(code),
    )
}

fn failed(err: &anyhow::Error) -> Response {
    tracing::error!(error = %format!("{err:#}"), "setup failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        page("<h1>Something went wrong</h1><p>See the mediator's log.</p>".to_owned()),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn only_a_bare_https_domain_is_an_origin() {
        assert_eq!(
            origin("mediator.example.com").unwrap(),
            "https://mediator.example.com"
        );
        assert_eq!(
            origin(" https://m.example.com/ ").unwrap(),
            "https://m.example.com"
        );
        assert_eq!(
            origin("https://m.example.com:8443").unwrap(),
            "https://m.example.com:8443"
        );
        for bad in [
            "http://m.example.com",
            "https://m.example.com/path",
            "https://m.example.com/?q=1",
            "https://user@m.example.com",
            "https://192.0.2.1",
            "https://[2001:db8::1]",
            "https://localhost",
            "not a url",
        ] {
            assert!(origin(bad).is_err(), "{bad}");
        }
    }

    fn state() -> (SetupState, String) {
        let admin = Arc::new(AdminStore::memory().unwrap());
        let code = admin.new_setup_code().unwrap();
        let (done, _) = tokio::sync::watch::channel(false);
        (
            SetupState {
                admin,
                allow_insecure: false,
                done,
            },
            code,
        )
    }

    async fn send(state: &SetupState, request: Request<Body>) -> (StatusCode, String) {
        let response = router(state.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn get(uri: &str) -> Request<Body> {
        Request::get(uri).body(Body::empty()).unwrap()
    }

    fn post(uri: &str, form: &str) -> Request<Body> {
        Request::post(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form.to_owned()))
            .unwrap()
    }

    #[test]
    fn once_proven_the_page_goes_on_to_the_claim_with_the_code_posted() {
        let site = Site {
            public_url: "https://m.example.com".into(),
            access: Access::Public,
        };
        let body = set_up(&site, "c0de");
        assert!(
            body.contains(
                r#"<form method="post" action="https://m.example.com/setup" id="claim">"#
            )
        );
        assert!(body.contains(r#"name="code" value="c0de""#));
        assert!(!body.contains("?code="));
        assert!(body.contains(r#"fetch("/health""#));
    }

    #[tokio::test]
    async fn the_code_opens_the_setup_and_the_value_is_published() {
        let (state, code) = state();
        let (status, body) = send(&state, get("/setup")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Enter the setup code"));
        let (_, body) = send(&state, post("/setup", "code=wrong")).await;
        assert!(body.contains("That is not the setup code."));
        let (_, body) = send(&state, post("/setup", &format!("code={code}"))).await;
        assert!(body.contains("Public URL"));

        // Nothing is published until a URL is being proven.
        assert_eq!(send(&state, get(WELL_KNOWN)).await.0, StatusCode::NOT_FOUND);
        let (_, body) = send(
            &state,
            post(
                "/setup/site",
                &format!("code={code}&url=https%3A%2F%2Fm.example.com%2Fx&access=private"),
            ),
        )
        .await;
        assert!(body.contains("nothing after the domain"));
        let (_, body) = send(
            &state,
            post(
                "/setup/site",
                &format!("code={code}&url=m.example.com&access=private"),
            ),
        )
        .await;
        let pending = state.admin.pending().unwrap().unwrap();
        assert_eq!(pending.public_url, "https://m.example.com");
        assert_eq!(pending.access, Access::Private);
        assert!(body.contains(&pending.token));
        assert!(body.contains("_almena-mediator.m.example.com"));
        // Each value to type elsewhere comes with its copy button.
        for value in [
            pending.token.as_str(),
            "_almena-mediator.m.example.com",
            "https://m.example.com/.well-known/almena-setup",
        ] {
            assert!(body.contains(&format!(r#"data-copy="{value}""#)), "{value}");
        }
        // Coming back with the code shows the proof; asking to change, the
        // URL again — the code always in the body, never in a link.
        let (_, body) = send(&state, post("/setup", &format!("code={code}"))).await;
        assert!(body.contains("Prove the domain") && !body.contains("?code="));
        let (_, body) = send(&state, post("/setup", &format!("code={code}&change=1"))).await;
        assert!(body.contains(r#"value="https://m.example.com""#));
        let (status, served) = send(&state, get(WELL_KNOWN)).await;
        assert_eq!((status, served), (StatusCode::OK, pending.token.clone()));

        // A wrong code changes nothing.
        let (_, body) = send(
            &state,
            post(
                "/setup/site",
                "code=wrong&url=other.example.com&access=public",
            ),
        )
        .await;
        assert!(body.contains("That is not the setup code."));
        assert_eq!(state.admin.pending().unwrap().unwrap(), pending);

        // Health is fine meanwhile, so a proxy waiting for it starts.
        let (status, body) = send(&state, get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"setup\""));
    }

    /// Against the real DNS: the domain's own name servers are found and
    /// asked, so a record shows even where the local resolver still caches
    /// "no such name". `ALMENA_TEST_TXT_HOST` and `ALMENA_TEST_TXT_VALUE`
    /// name a record that exists.
    #[tokio::test]
    #[ignore = "needs the network and a TXT record"]
    async fn a_published_record_is_found_past_any_cache() {
        let host =
            std::env::var("ALMENA_TEST_TXT_HOST").unwrap_or_else(|_| "mediator.almena.id".into());
        let value = std::env::var("ALMENA_TEST_TXT_VALUE").expect("ALMENA_TEST_TXT_VALUE");
        let public = public_resolver().unwrap();
        assert!(!authoritative_servers(&public, &host).await.is_empty());
        let pending = Pending {
            public_url: format!("https://{host}"),
            access: Access::Public,
            token: value,
        };
        dns_holds(&pending).await.unwrap();
        let wrong = Pending {
            token: "not-the-value".into(),
            ..pending
        };
        let why = dns_holds(&wrong).await.unwrap_err();
        assert!(
            why.contains("not the value below") && why.contains("name servers"),
            "{why}"
        );
    }

    #[tokio::test]
    async fn an_unproven_domain_is_not_set_up() {
        let (state, code) = state();
        send(
            &state,
            post(
                "/setup/site",
                &format!("code={code}&url=almena-test.invalid&access=public"),
            ),
        )
        .await;
        let (_, body) = send(&state, post("/setup/check", &format!("code={code}"))).await;
        assert!(body.contains(r#"class="fail">DNS"#));
        assert!(body.contains(r#"class="fail">HTTPS"#));
        assert_eq!(state.admin.site().unwrap(), None);
    }
}
