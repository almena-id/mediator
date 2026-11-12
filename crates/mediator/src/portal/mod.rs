//! The administration portal of a mediator that is set up: becoming its
//! first administrator (`/setup`, with the setup code) and signing in
//! (`/portal`), both with the Almena wallet ([`crate::signin`]), and what a
//! signed-in administrator sees.
//!
//! A session is a cookie (`almena_admin`: `HttpOnly`, `SameSite=Strict`,
//! `Secure` under HTTPS) whose SHA-256 the administration database keeps
//! ([`AdminStore::new_session`]). The browser waiting for a wallet holds the
//! request's poll secret in another (`almena_signin`), so only it collects
//! the session the wallet's answer opens. Forms are `POST`s from the
//! mediator's own origin.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

mod dashboard;
mod site;

pub use dashboard::*;
pub use site::*;

use crate::admin::{AdminStore, InvitationKind};
use crate::home::{escape, layout, qr_svg};
use crate::routes::{AppState, Client};
use crate::signin::{self, Outcome, Purpose, Refused, RequestObject};

/// The administrator's session cookie.
const SESSION_COOKIE: &str = "almena_admin";
/// The waiting browser's cookie: `<request id>.<poll secret>`.
const SIGNIN_COOKIE: &str = "almena_signin";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The setup code, in a form's body: in a URL it would stay in the proxy's
/// access log and the browser's history.
#[derive(Deserialize, ToSchema)]
pub struct CodeForm {
    code: String,
}

/// A page for `/setup` once there are administrators, if there are.
fn set_up_already(state: &AppState) -> Option<Response> {
    match state.admin.admin_count() {
        Ok(0) => None,
        Ok(_) => Some(
            page(
                "Set up",
                r#"<h1>Set up already</h1><p>This mediator has its administrators. They <a href="/portal">sign in to its portal</a>.</p>"#.to_owned(),
            )
            .into_response(),
        ),
        Err(err) => Some(failed(&err)),
    }
}

/// Set up
///
/// While the mediator has no administrator, asks for the setup code.
#[utoipa::path(
    get,
    path = "/setup",
    tag = "portal",
    responses((status = 200, description = "HTML page", content_type = "text/html"))
)]
pub async fn setup(State(state): State<AppState>) -> Response {
    set_up_already(&state)
        .unwrap_or_else(|| page("Set up", crate::setup::ask_code(None)).into_response())
}

/// Become the administrator
///
/// With the setup code, while the mediator has no administrator: a QR code
/// and a link for the Almena wallet. Whoever answers it becomes the first
/// administrator.
#[utoipa::path(
    post,
    path = "/setup",
    tag = "portal",
    request_body(content = CodeForm, content_type = "application/x-www-form-urlencoded"),
    responses((status = 200, description = "HTML page", content_type = "text/html"))
)]
pub async fn claim(
    State(state): State<AppState>,
    client: Client,
    axum::Form(form): axum::Form<CodeForm>,
) -> Response {
    if let Some(response) = set_up_already(&state) {
        return response;
    }
    let code = form.code.trim();
    if code.is_empty() {
        return page("Set up", crate::setup::ask_code(None)).into_response();
    }
    match state.admin.is_setup_code(code) {
        Ok(true) => {}
        Ok(false) => {
            return page(
                "Set up",
                crate::setup::ask_code(Some("That is not the setup code.")),
            )
            .into_response();
        }
        Err(err) => return failed(&err),
    }
    wallet_page(
        &state,
        client,
        Purpose::Claim,
        &crate::setup::progress(3),
        "Become its administrator",
        "Scan this code with your Almena wallet, or open the link on the phone that has it. Your wallet signs in with a key it keeps for this mediator only; the wallet that answers becomes its first administrator.",
    )
}

/// Portal
///
/// A signed-in administrator's page; otherwise, signing in with the Almena
/// wallet.
#[utoipa::path(
    get,
    path = "/portal",
    tag = "portal",
    responses((status = 200, description = "HTML page", content_type = "text/html"))
)]
pub async fn portal(State(state): State<AppState>, client: Client, headers: HeaderMap) -> Response {
    match signed_in(&state.admin, &headers) {
        Ok(Some(did)) => dashboard::overview(&state, &did).await,
        Ok(None) => match state.admin.admin_count() {
            Ok(0) => Redirect::to("/setup").into_response(),
            Ok(_) => wallet_page(
                &state,
                client,
                Purpose::SignIn,
                "",
                "Sign in",
                "Scan this code with your Almena wallet, or open the link on the phone that has it.",
            ),
            Err(err) => failed(&err),
        },
        Err(err) => failed(&err),
    }
}

/// Where a waiting sign-in stands, for the page polling it.
#[derive(Serialize, ToSchema)]
pub struct SignInStatus {
    /// `waiting`, `signed_in`, `not_an_admin`, `taken` (somebody became the
    /// administrator first) or `gone` (expired, or not this browser's).
    #[schema(example = "waiting")]
    status: &'static str,
}

/// A sign-in request swapped for a new one, for the page showing it.
#[derive(Serialize, ToSchema)]
pub struct Renewed {
    /// `renewed` (a new code: `link` and `qr`), `in_use` (a wallet read it:
    /// it stays) or `gone` (expired, or not this browser's).
    #[schema(example = "renewed")]
    status: &'static str,
    /// The new `almena://auth` link.
    #[serde(skip_serializing_if = "Option::is_none")]
    link: Option<String>,
    /// The new QR code, as SVG.
    #[serde(skip_serializing_if = "Option::is_none")]
    qr: Option<String>,
}

/// Renew the sign-in code
///
/// Swaps this browser's sign-in request (its `almena_signin` cookie) for a
/// new one with the same purpose, while no wallet has read it, so the code
/// on screen keeps changing; the new one comes with its cookie.
#[utoipa::path(
    post,
    path = "/portal/sign-in/renew",
    tag = "portal",
    responses((status = 200, description = "The new code, or why not", body = Renewed))
)]
pub async fn renew_sign_in(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let answer = |status, link: Option<String>, cookie: Option<String>| {
        let qr = link.as_deref().map(qr_svg);
        let mut response = axum::Json(Renewed { status, link, qr }).into_response();
        if let Some(value) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        response
    };
    if !same_origin(&headers, &state) {
        return answer("gone", None, None);
    }
    let Some((id, poll)) = cookie(&headers, SIGNIN_COOKIE).and_then(|value| {
        let (id, poll) = value.split_once('.')?;
        Some((id.to_owned(), poll.to_owned()))
    }) else {
        return answer("gone", None, None);
    };
    match state.signins.renew(&id, &poll, now()) {
        Ok(signin::Renewal::Renewed(started)) => {
            let link = signin::wallet_link(&state.public_url, &started.id);
            let value = format!("{}.{}", started.id, started.poll);
            answer(
                "renewed",
                Some(link),
                Some(set_cookie(SIGNIN_COOKIE, &value, &state)),
            )
        }
        Ok(signin::Renewal::InUse) => answer("in_use", None, None),
        Ok(signin::Renewal::Gone) => answer("gone", None, None),
        Err(err) => failed(&err),
    }
}

/// Sign-in status
///
/// What the wallet did with this browser's request (its `almena_signin`
/// cookie). `signed_in` comes with the session cookie.
#[utoipa::path(
    post,
    path = "/portal/sign-in/status",
    tag = "portal",
    responses((status = 200, description = "Where it stands", body = SignInStatus))
)]
pub async fn sign_in_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some((id, poll)) = cookie(&headers, SIGNIN_COOKIE).and_then(|value| {
        let (id, poll) = value.split_once('.')?;
        Some((id.to_owned(), poll.to_owned()))
    }) else {
        return status("gone", None);
    };
    let at = now();
    let did = match state.signins.outcome(&id, &poll, at) {
        Outcome::Waiting => return status("waiting", None),
        Outcome::Gone => return status("gone", None),
        Outcome::Answered { purpose, did } => {
            let allowed = match purpose {
                // The first to answer becomes the administrator; the setup
                // code goes with it.
                Purpose::Claim => match state.admin.claim(&did, at) {
                    Ok(true) => Ok(true),
                    Ok(false) => return status("taken", Some(clear(SIGNIN_COOKIE, &state))),
                    Err(err) => Err(err),
                },
                Purpose::SignIn => state.admin.is_admin(&did),
                // An invitation to be an administrator: one use. Somebody
                // who is one already just signs in, and leaves it unspent.
                Purpose::Join(invitation) => match state.admin.is_admin(&did) {
                    Ok(true) => Ok(true),
                    Ok(false) => {
                        match state
                            .admin
                            .use_invitation(InvitationKind::Admin, &invitation, at)
                        {
                            Ok(Some(_)) => state.admin.add_admin(&did, at).map(|()| {
                                tracing::info!(%did, "administrator joined by invitation");
                                true
                            }),
                            Ok(None) => return status("gone", Some(clear(SIGNIN_COOKIE, &state))),
                            Err(err) => Err(err),
                        }
                    }
                    Err(err) => Err(err),
                },
            };
            match allowed {
                Ok(true) => did,
                Ok(false) => return status("not_an_admin", Some(clear(SIGNIN_COOKIE, &state))),
                Err(err) => return failed(&err),
            }
        }
    };
    match state.admin.new_session(&did, at) {
        Ok(token) => {
            tracing::info!(%did, "administrator signed in");
            let mut response = status("signed_in", Some(clear(SIGNIN_COOKIE, &state)));
            if let Ok(value) = HeaderValue::from_str(&set_cookie(SESSION_COOKIE, &token, &state)) {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            response
        }
        Err(err) => failed(&err),
    }
}

/// Sign out
///
/// Ends this browser's session.
#[utoipa::path(
    post,
    path = "/portal/sign-out",
    tag = "portal",
    responses((status = 303, description = "Back to the portal"))
)]
pub async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !same_origin(&headers, &state) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(token) = cookie(&headers, SESSION_COOKIE)
        && let Err(err) = state.admin.end_session(&token)
    {
        return failed(&err);
    }
    let mut response = Redirect::to("/portal").into_response();
    if let Ok(value) = HeaderValue::from_str(&clear(SESSION_COOKIE, &state)) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// Sign-in request
///
/// The request the wallet reads (SIOPv2, `direct_post`): who asks, the
/// nonce, where the answer goes.
#[utoipa::path(
    get,
    path = "/portal/requests/{id}",
    tag = "portal",
    params(("id" = String, Path, description = "The request")),
    responses(
        (status = 200, description = "The request", body = RequestObject),
        (status = 404, description = "No such request"),
        (status = 409, description = "Answered already"),
        (status = 410, description = "Expired")
    )
)]
pub async fn read_request(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.signins.request(&id, &state.public_url, now()) {
        Ok(request) => axum::Json(request).into_response(),
        Err(refused) => refusal(refused),
    }
}

/// Sign-in answer
///
/// The wallet's `id_token`, posted as a form (`id_token=…`) or as JSON.
#[utoipa::path(
    post,
    path = "/portal/requests/{id}/response",
    tag = "portal",
    params(("id" = String, Path, description = "The request")),
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "`id_token=…`, or JSON `{\"id_token\": …}`"),
    responses(
        (status = 204, description = "Taken"),
        (status = 400, description = "`invalid_token`"),
        (status = 404, description = "No such request"),
        (status = 409, description = "Answered already"),
        (status = 410, description = "Expired")
    )
)]
pub async fn answer_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    let token = if json {
        serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["id_token"].as_str().map(str::to_owned))
    } else {
        url::form_urlencoded::parse(&body)
            .find(|(key, _)| key == "id_token")
            .map(|(_, value)| value.into_owned())
    };
    let Some(token) = token else {
        return refusal(Refused::InvalidToken);
    };
    match state.signins.answer(&id, &token, &state.public_url, now()) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(refused) => refusal(refused),
    }
}

// ---- helpers ----

/// The administrator this browser is signed in as, if any.
fn signed_in(admin: &AdminStore, headers: &HeaderMap) -> anyhow::Result<Option<String>> {
    match cookie(headers, SESSION_COOKIE) {
        Some(token) => admin.session(&token, now()),
        None => Ok(None),
    }
}

/// The administrator behind a form: signed in, and the form posted from this
/// mediator's own pages. Otherwise the response to send instead.
fn acting(state: &AppState, headers: &HeaderMap) -> Result<String, Box<Response>> {
    if !same_origin(headers, state) {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    }
    match signed_in(&state.admin, headers) {
        Ok(Some(did)) => Ok(did),
        Ok(None) => Err(Box::new(Redirect::to("/portal").into_response())),
        Err(err) => Err(Box::new(failed(&err))),
    }
}

/// A new wallet request for `purpose`, shown as a QR code and a link, with
/// the cookie that lets this browser collect the answer.
fn wallet_page(
    state: &AppState,
    client: Client,
    purpose: Purpose,
    before: &str,
    title: &str,
    lead: &str,
) -> Response {
    // Where to begin again once a code is past renewing: the setup asks for
    // its code again, an invitation is opened again.
    let again = match &purpose {
        Purpose::Claim => "/setup".to_owned(),
        Purpose::SignIn => "/portal".to_owned(),
        Purpose::Join(id) => format!("/portal/join/{id}"),
    };
    let started = match state.signins.start(purpose, client.0, now()) {
        Ok(Some(started)) => started,
        Ok(None) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                page(
                    title,
                    "<h1>Busy</h1><p>Too many sign-ins are waiting. Finish one you opened, or try again in a few minutes.</p>"
                        .to_owned(),
                ),
            )
                .into_response();
        }
        Err(err) => return failed(&err),
    };
    let link = signin::wallet_link(&state.public_url, &started.id);
    // The code changes every `RENEW_SECS` while no wallet has read it; one a
    // wallet opened stays until it is answered or expires.
    let main = format!(
        r#"{before}<h1>{title}</h1>
<p>{lead}</p>
<figure class="signin"><div class="qr" id="qr" role="img" aria-label="Sign-in QR code">{qr}</div></figure>
<a class="open" id="open" href="{link}">Open in Almena wallet</a>
<p id="state" role="status">Waiting for your wallet… The code changes every minute.</p>
<script>
const say={{taken:"Somebody else became the administrator first.",not_an_admin:"That wallet is not an administrator of this mediator.",gone:"This code expired."}};
let over=false;
const stop=(text)=>{{over=true;const s=document.getElementById("state");s.textContent=text+" ";const a=document.createElement("a");a.href={again};a.textContent="Start again";s.append(a)}};
const poll=async()=>{{if(over)return;try{{const r=await fetch("/portal/sign-in/status",{{method:"POST"}});const j=await r.json();if(j.status==="signed_in"){{location.href="/portal";return}}if(j.status!=="waiting"){{stop(say[j.status]||say.gone);return}}}}catch{{}}setTimeout(poll,2000)}};
const renew=async()=>{{if(over)return;try{{const r=await fetch("/portal/sign-in/renew",{{method:"POST"}});const j=await r.json();if(j.status==="renewed"){{document.getElementById("qr").innerHTML=j.qr;document.getElementById("open").href=j.link}}else if(j.status==="in_use"){{document.getElementById("state").textContent="Your wallet has the code: answer it there.";return}}}}catch{{}}setTimeout(renew,{renew_ms})}};
setTimeout(poll,2000);
setTimeout(renew,{renew_ms});
</script>"#,
        title = escape(title),
        lead = escape(lead),
        qr = qr_svg(&link),
        link = escape(&link),
        again = serde_json::to_string(&again).unwrap_or_else(|_| "\"/portal\"".to_owned()),
        renew_ms = signin::RENEW_SECS * 1000,
    );
    let mut response = page(title, main).into_response();
    let value = format!("{}.{}", started.id, started.poll);
    if let Ok(value) = HeaderValue::from_str(&set_cookie(SIGNIN_COOKIE, &value, state)) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// Join as an administrator
///
/// The page an invitation to be an administrator leads to: signing in with
/// the Almena wallet takes it.
#[utoipa::path(
    get,
    path = "/portal/join/{id}",
    tag = "portal",
    params(("id" = String, Path, description = "The invitation")),
    responses(
        (status = 200, description = "HTML page", content_type = "text/html"),
        (status = 404, description = "No such invitation, or spent")
    )
)]
pub async fn join(
    State(state): State<AppState>,
    client: Client,
    Path(id): Path<String>,
) -> Response {
    match state.admin.invitation(InvitationKind::Admin, &id, now()) {
        Ok(Some(_)) => wallet_page(
            &state,
            client,
            Purpose::Join(id),
            "",
            "Become an administrator",
            "You were invited to help run this mediator. Scan this code with your Almena wallet, or open the link on the phone that has it.",
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            page(
                "Invitation",
                "<h1>This invitation is no good</h1><p>It was used, expired or withdrawn. Ask for a new one.</p>".to_owned(),
            ),
        )
            .into_response(),
        Err(err) => failed(&err),
    }
}

const PORTAL_CSS: &str = r#"
h2{margin:.5rem 0 0;font-size:1.125rem}
dl{display:grid;grid-template-columns:auto minmax(0,1fr);gap:.5rem 1rem;margin:0;font-size:.875rem}
dt{color:var(--muted)}dd{margin:0;min-width:0}
.rows{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:.5rem;font-size:.875rem}
.rows li{display:flex;flex-wrap:wrap;gap:.5rem 1rem;align-items:center;padding:.6rem .75rem;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
.rows li.empty{color:var(--muted)}
.rows span{color:var(--muted)}
.row-action{margin-left:auto}
form.inline{flex-direction:row;flex-wrap:wrap;align-items:flex-end;gap:.75rem}
form.inline label{flex:1 1 10rem}
form.inline label:has(input[type=number]){flex:0 0 auto}
form.inline input[type=text]{width:100%;box-sizing:border-box}
input[type=number]{width:6rem;padding:.6rem .75rem;border:1px solid var(--border);border-radius:10px;background:var(--surface);color:var(--text);font:inherit}
button.small{padding:.3rem .8rem;font-size:.8rem}
.signin{margin:.5rem 0 0;align-self:center}
.qr{width:16rem;max-width:80vw;padding:.75rem;border-radius:16px;background:#fff;box-sizing:border-box}
.qr svg{display:block;width:100%;height:auto}
.open{align-self:center}
#state{text-align:center}
button.ghost{background:transparent;border:1px solid var(--border);color:var(--text)}
main:has(.dash){max-width:72rem;justify-content:flex-start}
form.inline button{align-self:flex-end}
.dash{display:flex;flex-direction:column;gap:1.25rem}
.dash-nav{display:flex;flex-wrap:wrap;align-items:center;gap:.25rem;padding-bottom:.75rem;border-bottom:1px solid var(--border);font-size:.875rem}
.dash-nav a{padding:.4rem .8rem;border-radius:999px;color:var(--muted);text-decoration:none}
.dash-nav a:hover{background:var(--hover);color:var(--text)}
.dash-nav a[aria-current]{background:var(--surface);color:var(--text);box-shadow:inset 0 0 0 1px var(--border)}
.dash-nav .who{flex-direction:row;align-items:center;gap:.5rem;margin-left:auto;color:var(--muted);font-size:.8rem}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(12rem,1fr));gap:.75rem}
.card{display:flex;flex-direction:column;gap:.25rem;padding:1rem;border:1px solid var(--border);border-radius:14px;background:var(--surface);text-decoration:none}
.card:hover{border-color:var(--brand)}
.card .label{font-size:.8rem;color:var(--muted)}
.card strong{font-family:var(--font-brand);font-size:1.75rem;line-height:1.2}
.card span:last-child{font-size:.8rem;color:var(--muted)}
.dot{display:inline-block;width:.5rem;height:.5rem;margin-right:.5rem;border-radius:50%;background:var(--c)}
.table{overflow-x:auto;border:1px solid var(--border);border-radius:12px}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th,td{padding:.55rem .75rem;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
th{font-weight:500;color:var(--muted);background:var(--surface)}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--hover)}
.num{text-align:right}
td span{color:var(--muted)}
td.near{color:var(--down)}
td .row-action{margin:0}
.count,.empty{font-size:.875rem;color:var(--muted)}
.pager{display:flex;gap:1rem;align-items:center;font-size:.875rem}
.pager span{color:var(--muted)}
form.search{max-width:32rem}
.consequences{margin:0;padding-left:1.25rem;display:flex;flex-direction:column;gap:.5rem;font-size:.9rem;color:var(--muted)}
.consequences strong{color:var(--text)}
.actions{display:flex;flex-wrap:wrap;gap:.75rem}
"#;

fn page(title: &str, main: String) -> Html<String> {
    Html(layout(
        &format!("{title} · Almena Mediator"),
        &format!("{}{PORTAL_CSS}", crate::setup::SETUP_CSS),
        &main,
    ))
}

fn status(status: &'static str, cookie: Option<String>) -> Response {
    let mut response = axum::Json(SignInStatus { status }).into_response();
    if let Some(value) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn refusal(refused: Refused) -> Response {
    let (code, detail) = match refused {
        Refused::NotFound => (StatusCode::NOT_FOUND, "request_not_found"),
        Refused::Expired => (StatusCode::GONE, "request_expired"),
        Refused::AlreadyAnswered => (StatusCode::CONFLICT, "already_answered"),
        Refused::InvalidToken => (StatusCode::BAD_REQUEST, "invalid_token"),
    };
    (code, axum::Json(serde_json::json!({ "detail": detail }))).into_response()
}

fn failed(err: &anyhow::Error) -> Response {
    tracing::error!(error = %format!("{err:#}"), "portal failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        page(
            "Error",
            "<h1>Something went wrong</h1><p>See the mediator's log.</p>".to_owned(),
        ),
    )
        .into_response()
}

/// The value of cookie `name`.
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

fn secure(state: &AppState) -> &'static str {
    if state.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    }
}

fn set_cookie(name: &str, value: &str, state: &AppState) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Strict{}",
        secure(state)
    )
}

fn clear(name: &str, state: &AppState) -> String {
    format!(
        "{name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        secure(state)
    )
}

/// A form posted from this mediator's own pages: its `Origin`, when the
/// browser sends one, is the public URL.
fn same_origin(headers: &HeaderMap, state: &AppState) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|origin| origin == state.public_url)
}

/// `YYYY-MM-DD` (UTC) of epoch seconds.
fn date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_civil() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_794_355_200), "2026-11-11");
    }
}
