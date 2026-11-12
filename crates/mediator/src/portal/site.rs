//! The site: where the mediator is published and who may use it. The mode
//! was fixed at setup and never changes. The URL can move: the new domain
//! is proven as the onboarding proved the first (a TXT record at
//! `_almena-mediator.<host>`, `/.well-known/almena-setup` answering over
//! HTTPS), then the site moves and the mediator restarts as the new
//! `did:web`.
//!
//! Moving is not light, and the page says so: the mediator's DID changes,
//! so every wallet connects again; and a wallet signs in with a key it
//! keeps per address, so the administrators are invited again at the new
//! one ([`crate::admin::AdminStore::move_site`]).

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::dashboard::{Section, dashboard};
use super::{acting, failed, now, page, signed_in};
use crate::admin::Pending;
use crate::home::escape;
use crate::routes::AppState;
use crate::setup::{Outcome, dns_holds, https_answers, origin, proof_steps};

/// Site
///
/// The URL, the DID and the access mode; moving the URL, proven again.
#[utoipa::path(
    get,
    path = "/portal/site",
    tag = "portal",
    responses(
        (status = 200, description = "HTML page", content_type = "text/html"),
        (status = 303, description = "Not signed in")
    )
)]
pub async fn site(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let did = match signed_in(&state.admin, &headers) {
        Ok(Some(did)) => did,
        Ok(None) => return Redirect::to("/portal").into_response(),
        Err(err) => return failed(&err),
    };
    match state.admin.pending() {
        Ok(pending) => site_page(&state, &did, pending.as_ref(), None, None),
        Err(err) => failed(&err),
    }
}

fn site_page(
    state: &AppState,
    did: &str,
    pending: Option<&Pending>,
    outcome: Option<Outcome>,
    why: Option<&str>,
) -> Response {
    let private = state.mediator.limits().private;
    let error = why
        .map(|why| format!(r#"<p class="error">{}</p>"#, escape(why)))
        .unwrap_or_default();
    let consequences = format!(
        r#"<ul class="consequences">
<li>The mediator's DID becomes the new address's <code>did:web</code>: <strong>every wallet that uses it has to connect again</strong>, and relationships through it stop until their wallets move them.{members}</li>
<li>A wallet signs in with a key it keeps for each address, so <strong>no administrator is recognised at the new one</strong>: each gets an invitation to be one again there. Yours is shown when the move is done; the others' are under Administrators.</li>
<li>The mediator restarts at once, at the new address.</li>
</ul>"#,
        members = if private {
            " Members need new invitations."
        } else {
            ""
        },
    );
    let moving = if state.url_pinned {
        r#"<h2>Move it</h2>
<p class="note">The URL is set by <code>ALMENA_PUBLIC_URL</code>: whoever runs the mediator changes it there and restarts it. Administrators are invited again at the new address, as in a move made here.</p>"#
            .to_owned()
    } else if let Some(pending) = pending {
        format!(
            r#"<h2>Moving to <code>{url}</code></h2>
{consequences}
{error}
{steps}
<div class="actions">
<form method="post" action="/portal/site/check" onsubmit="return confirm(this.dataset.q)" data-q="If both proofs hold, the mediator moves and restarts now. Every wallet has to connect again. Move it?"><button type="submit">Check and move</button></form>
<form method="post" action="/portal/site/cancel"><button type="submit" class="ghost">Cancel the move</button></form>
</div>"#,
            url = escape(&pending.public_url),
            steps = proof_steps(pending, outcome),
        )
    } else {
        format!(
            r#"<h2>Move it</h2>
<p>To publish the mediator at another address, give it here and prove the new domain as at setup. Before moving it:</p>
{consequences}
{error}
<form method="post" action="/portal/site/url" class="inline">
<label>New public URL<input type="text" name="url" placeholder="https://mediator.example.com" autocomplete="off" required></label>
<button type="submit">Continue</button>
</form>"#
        )
    };
    let main = format!(
        r#"<h1>Site</h1>
<dl>
<dt>URL</dt><dd><code>{url}</code></dd>
<dt>DID</dt><dd><code>{mediator}</code></dd>
<dt>Access</dt><dd>{access}</dd>
</dl>
<p class="note">Who may use it was chosen at setup and never changes: a {other} mediator is a new one, set up from scratch.</p>
{moving}"#,
        url = escape(&state.public_url),
        mediator = escape(&state.mediator.identity().did),
        access = if private {
            "Private: only the wallets its administrators invite"
        } else {
            "Public: any wallet"
        },
        other = if private { "public" } else { "private" },
    );
    dashboard(state, did, Section::Site, "Site", &main)
}

#[derive(Deserialize)]
pub struct UrlForm {
    url: String,
}

/// Move the URL
///
/// Starts moving the mediator to another URL: a fresh value for the new
/// domain's DNS record and HTTPS answer.
#[utoipa::path(
    post,
    path = "/portal/site/url",
    tag = "portal",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "`url`"),
    responses(
        (status = 303, description = "To the proof"),
        (status = 400, description = "Not a domain URL, the current one, or set by ALMENA_PUBLIC_URL"),
        (status = 403, description = "Not from this mediator's pages")
    )
)]
pub async fn move_url(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UrlForm>,
) -> Response {
    let did = match acting(&state, &headers) {
        Ok(did) => did,
        Err(response) => return *response,
    };
    let refuse = |why: &str| {
        let mut response = site_page(&state, &did, None, None, Some(why));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        response
    };
    if state.url_pinned {
        return refuse("The URL is set by ALMENA_PUBLIC_URL.");
    }
    let url = match origin(&form.url) {
        Ok(url) => url,
        Err(why) => return refuse(why),
    };
    if url == state.public_url {
        return refuse("That is the mediator's URL already.");
    }
    let access = if state.mediator.limits().private {
        crate::config::Access::Private
    } else {
        crate::config::Access::Public
    };
    match state.admin.start_pending(&url, access) {
        Ok(_) => {
            tracing::info!(by = %did, to = %url, "moving the public URL: proving the domain");
            Redirect::to("/portal/site").into_response()
        }
        Err(err) => failed(&err),
    }
}

/// Check and move
///
/// Looks for the new domain's DNS record and asks it over HTTPS; with both
/// right, moves the site, invites the administrators again there and
/// restarts the mediator as the new `did:web`.
#[utoipa::path(
    post,
    path = "/portal/site/check",
    tag = "portal",
    responses(
        (status = 200, description = "Moved, or how the proof went", content_type = "text/html"),
        (status = 303, description = "Nothing being moved"),
        (status = 403, description = "Not from this mediator's pages")
    )
)]
pub async fn check_move(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let did = match acting(&state, &headers) {
        Ok(did) => did,
        Err(response) => return *response,
    };
    let pending = match state.admin.pending() {
        Ok(Some(pending)) if !state.url_pinned => pending,
        Ok(_) => return Redirect::to("/portal/site").into_response(),
        Err(err) => return failed(&err),
    };
    let dns = dns_holds(&pending).await;
    let https = https_answers(&pending, state.allow_insecure).await;
    if dns.is_err() || https.is_err() {
        return site_page(&state, &did, Some(&pending), Some((dns, https)), None);
    }
    let invitation = match state
        .admin
        .move_site(&pending.public_url, Some(&did), now())
    {
        Ok(invitation) => invitation,
        Err(err) => return failed(&err),
    };
    tracing::warn!(by = %did, from = %state.public_url, to = %pending.public_url, "public URL moved: restarting");
    state.restart.notify_one();
    let rejoin = invitation
        .map(|id| format!("{}/portal/join/{id}", pending.public_url))
        .unwrap_or_else(|| format!("{}/portal", pending.public_url));
    let main = format!(
        r#"<h1>Moved</h1>
<p>The mediator is restarting as <code>{did}</code>.</p>
<p>Your session here is over. To administer it at its new address, open your invitation and sign in with your wallet:</p>
<a class="open" href="{rejoin}">Become an administrator again</a>
<label>Link<input type="text" readonly value="{rejoin}" onclick="this.select()"></label>
<p>It lasts 7 days. The other administrators' invitations wait under Administrators: send them on once you are in. If this link is lost, <code>almena-mediator setup</code> prints a setup code while the mediator has no administrator.</p>"#,
        did = escape(
            &almena_didcomm::did::web::did_from_origin(&pending.public_url).unwrap_or_default()
        ),
        rejoin = escape(&rejoin),
    );
    page("Moved", main).into_response()
}

/// Cancel the move
#[utoipa::path(
    post,
    path = "/portal/site/cancel",
    tag = "portal",
    responses(
        (status = 303, description = "Back to the site"),
        (status = 403, description = "Not from this mediator's pages")
    )
)]
pub async fn cancel_move(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = acting(&state, &headers) {
        return *response;
    }
    match state.admin.drop_pending() {
        Ok(()) => Redirect::to("/portal/site").into_response(),
        Err(err) => failed(&err),
    }
}

/// Domain proof
///
/// The value a domain being proven must answer over HTTPS: what the
/// mediator checks through the new URL before moving there. `404` when no
/// move is under way.
#[utoipa::path(
    get,
    path = "/.well-known/almena-setup",
    tag = "portal",
    responses(
        (status = 200, description = "The value", content_type = "text/plain"),
        (status = 404, description = "Nothing being proven")
    )
)]
pub async fn domain_proof(State(state): State<AppState>) -> Response {
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
