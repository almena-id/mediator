//! What a signed-in administrator manages, one page per section under a
//! shared navigation: the overview (`/portal`), the mailboxes, a private
//! mediator's members and their invitations, the administrators and their
//! invitations. The site — its URL and how it moves — is [`super::site`].

use std::collections::HashMap;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::{acting, date, failed, now, page, signed_in};
use crate::admin::{ADMIN_INVITATION_SECS, Invitation, InvitationKind};
use crate::home::{escape, qr_svg};
use crate::routes::AppState;

/// Longest label an invitation takes.
const MAX_LABEL: usize = 80;
/// Most uses one member invitation may have.
const MAX_USES: u32 = 1_000;
/// Longest a member invitation may last, in days.
const MAX_DAYS: u64 = 90;
/// Mailboxes on one page of the list.
const PAGE_SIZE: u64 = 50;

/// The dashboard's sections, for its navigation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Section {
    Overview,
    Mailboxes,
    Members,
    Admins,
    Site,
}

/// A dashboard page: the navigation (members only when private, the
/// signed-in administrator and signing out), then `main`.
pub(super) fn dashboard(
    state: &AppState,
    did: &str,
    at: Section,
    title: &str,
    main: &str,
) -> Response {
    let private = state.mediator.limits().private;
    let link = |section: Section, href: &str, label: &str| {
        let current = if section == at {
            r#" aria-current="page""#
        } else {
            ""
        };
        format!(r#"<a href="{href}"{current}>{label}</a>"#)
    };
    let nav = format!(
        r#"<nav class="dash-nav" aria-label="Administration">{overview}{mailboxes}{members}{admins}{site}
<form method="post" action="/portal/sign-out" class="who"><code title="{did}">{short}</code><button type="submit" class="ghost small">Sign out</button></form></nav>"#,
        overview = link(Section::Overview, "/portal", "Overview"),
        mailboxes = link(Section::Mailboxes, "/portal/mailboxes", "Mailboxes"),
        members = if private {
            link(Section::Members, "/portal/members", "Members")
        } else {
            String::new()
        },
        admins = link(Section::Admins, "/portal/admins", "Administrators"),
        site = link(Section::Site, "/portal/site", "Site"),
        did = escape(did),
        short = escape(&short(did)),
    );
    page(title, format!(r#"<div class="dash">{nav}{main}</div>"#)).into_response()
}

/// The overview: what the mediator holds, who runs it and where it lives.
pub(super) async fn overview(state: &AppState, did: &str) -> Response {
    let at = now();
    let healthy = state.store.ping().await.is_ok();
    let totals = match state.store.totals().await {
        Ok(totals) => totals,
        Err(err) => return failed(&err),
    };
    let listed = (|| -> anyhow::Result<_> {
        Ok((
            state.admin.admins()?.len(),
            state.admin.members()?.len(),
            state.admin.invitations(InvitationKind::Member, at)?.len(),
            state.admin.invitations(InvitationKind::Admin, at)?.len(),
            state.admin.pending()?,
        ))
    })();
    let (admins, members, member_invitations, admin_invitations, pending) = match listed {
        Ok(listed) => listed,
        Err(err) => return failed(&err),
    };
    let limits = state.mediator.limits();
    let ceiling = if limits.max_mediations > 0 {
        format!("of {} at most", limits.max_mediations)
    } else {
        "no ceiling".to_owned()
    };
    let card = |href: &str, label: &str, value: String, note: String| {
        format!(
            r#"<a class="card" href="{href}"><span class="label">{label}</span><strong>{value}</strong><span>{note}</span></a>"#
        )
    };
    let mut cards = vec![
        card(
            "/portal/mailboxes",
            "Mailboxes",
            totals.mailboxes.to_string(),
            ceiling,
        ),
        card(
            "/portal/mailboxes",
            "Messages waiting",
            totals.messages.to_string(),
            size(totals.bytes),
        ),
        card(
            "/portal/mailboxes",
            "Recipient DIDs",
            totals.dids.to_string(),
            format!(
                "at most {} in one mailbox, of {}",
                totals.fullest, limits.max_recipient_dids
            ),
        ),
        card(
            "/portal/mailboxes",
            "Push devices",
            totals.devices.to_string(),
            "woken when a message waits".to_owned(),
        ),
        card(
            "/portal/mailboxes",
            "Relays pending",
            totals.relays.to_string(),
            "to other mediators".to_owned(),
        ),
    ];
    if limits.private {
        cards.push(card(
            "/portal/members",
            "Members",
            members.to_string(),
            format!(
                "{member_invitations} open invitation{}",
                plural(member_invitations as u64)
            ),
        ));
    }
    cards.push(card(
        "/portal/admins",
        "Administrators",
        admins.to_string(),
        format!(
            "{admin_invitations} open invitation{}",
            plural(admin_invitations as u64)
        ),
    ));
    let moving = pending
        .map(|pending| {
            format!(
                r#"<p class="note">Moving to <code>{}</code>: <a href="/portal/site">prove the new domain</a> to finish.</p>"#,
                escape(&pending.public_url)
            )
        })
        .unwrap_or_default();
    let main = format!(
        r#"<h1>Overview</h1>
{moving}
<div class="cards">{cards}</div>
<h2>Site</h2>
<dl>
<dt>Status</dt><dd><span class="dot {status_class}"></span>{status}</dd>
<dt>URL</dt><dd><code>{url}</code></dd>
<dt>DID</dt><dd><code>{mediator}</code></dd>
<dt>Access</dt><dd>{access}</dd>
<dt>Version</dt><dd><code>{version}</code></dd>
</dl>
<p><a href="/portal/site">Manage the site</a></p>"#,
        cards = cards.concat(),
        status_class = if healthy { "pass" } else { "fail" },
        status = if healthy {
            "Operational"
        } else {
            "Storage unavailable"
        },
        url = escape(&state.public_url),
        mediator = escape(&state.mediator.identity().did),
        access = access_text(limits.private),
        version = crate::VERSION,
    );
    dashboard(state, did, Section::Overview, "Overview", &main)
}

#[derive(Deserialize)]
pub struct MailboxQuery {
    /// Part of a mailbox's DID or of one of its recipient DIDs.
    q: Option<String>,
    /// The page, from 1.
    page: Option<u64>,
}

/// Mailboxes
///
/// Every mailbox held, the most recently active first, with what waits in
/// it; searched by part of its DID or of one of its recipient DIDs.
#[utoipa::path(
    get,
    path = "/portal/mailboxes",
    tag = "portal",
    params(
        ("q" = Option<String>, Query, description = "Part of a DID"),
        ("page" = Option<u64>, Query, description = "The page, from 1")
    ),
    responses((status = 200, description = "HTML page", content_type = "text/html"))
)]
pub async fn mailboxes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<MailboxQuery>,
) -> Response {
    let did = match signed_in(&state.admin, &headers) {
        Ok(Some(did)) => did,
        Ok(None) => return Redirect::to("/portal").into_response(),
        Err(err) => return failed(&err),
    };
    let search = query.q.unwrap_or_default().trim().to_owned();
    let at_page = query.page.unwrap_or(1).max(1);
    let (listed, matching) = match state
        .store
        .mailboxes(&search, (at_page - 1) * PAGE_SIZE, PAGE_SIZE)
        .await
    {
        Ok(found) => found,
        Err(err) => return failed(&err),
    };
    let private = state.mediator.limits().private;
    let labels: HashMap<String, String> = match state.admin.members() {
        Ok(members) => members
            .into_iter()
            .map(|member| (member.mediation, member.label))
            .collect(),
        Err(err) => return failed(&err),
    };
    let max_dids = state.mediator.limits().max_recipient_dids as u64;
    let rows: String = listed
        .iter()
        .map(|mailbox| {
            let member = if private {
                format!(
                    "<td>{}</td>",
                    labels
                        .get(&mailbox.id)
                        .map(|label| escape(label))
                        .unwrap_or_else(|| "—".to_owned())
                )
            } else {
                String::new()
            };
            format!(
                r#"<tr><td><code title="{id}">{short}</code></td>{member}<td>{seen}</td><td class="num{near}">{dids}<span> / {max_dids}</span></td><td class="num">{messages}<span>{bytes}</span></td><td class="num">{devices}</td><td>{remove}</td></tr>"#,
                id = escape(&mailbox.id),
                short = escape(&short(&mailbox.id)),
                seen = when(mailbox.seen),
                dids = mailbox.dids,
                // Within a tenth of the ceiling: its wallet will soon be
                // unable to open new contacts here.
                near = if mailbox.dids * 10 >= max_dids * 9 { " near" } else { "" },
                messages = mailbox.messages,
                bytes = if mailbox.messages > 0 {
                    format!(" · {}", size(mailbox.bytes))
                } else {
                    String::new()
                },
                devices = mailbox.devices,
                remove = confirm_button(
                    "/portal/mailboxes/remove",
                    "mediation",
                    &mailbox.id,
                    "Remove",
                    "Remove this mailbox and everything waiting in it?"
                ),
            )
        })
        .collect();
    let pages = matching.div_ceil(PAGE_SIZE).max(1);
    let link = |n: u64, label: &str| {
        format!(
            r#"<a href="/portal/mailboxes?q={q}&amp;page={n}">{label}</a>"#,
            q = escape(
                &url::form_urlencoded::byte_serialize(search.as_bytes()).collect::<String>()
            ),
        )
    };
    let pager = if pages > 1 {
        format!(
            r#"<p class="pager">{prev}<span>Page {at_page} of {pages}</span>{next}</p>"#,
            prev = if at_page > 1 {
                link(at_page - 1, "← Previous")
            } else {
                String::new()
            },
            next = if at_page < pages {
                link(at_page + 1, "Next →")
            } else {
                String::new()
            },
        )
    } else {
        String::new()
    };
    let table = if listed.is_empty() {
        format!(
            r#"<p class="empty">{}</p>"#,
            if search.is_empty() {
                "No mailbox yet."
            } else {
                "No mailbox matches."
            }
        )
    } else {
        format!(
            r#"<div class="table"><table>
<thead><tr><th>Mailbox</th>{member}<th>Last active</th><th class="num" title="Recipient DIDs: the inbox, the contact card and one per contact, against the ceiling a mailbox may hold">DIDs</th><th class="num">Waiting</th><th class="num">Devices</th><th></th></tr></thead>
<tbody>{rows}</tbody></table></div>"#,
            member = if private { "<th>Member</th>" } else { "" },
        )
    };
    let main = format!(
        r#"<h1>Mailboxes</h1>
<p>One per wallet that keeps its messages here: the DID it asked with, the DIDs it receives at — its inbox, its contact card and one per contact, up to {max_dids} — and what waits for it. Removing one deletes all of that; {after}</p>
<form method="get" action="/portal/mailboxes" class="inline search">
<label>Search<input type="text" name="q" value="{search}" placeholder="Part of a DID" autocomplete="off"></label>
<button type="submit">Search</button>
</form>
<p class="count">{matching} mailbox{es}{matched}</p>
{table}
{pager}"#,
        after = if private {
            "its wallet would need a new invitation."
        } else {
            "its wallet can ask for a new one."
        },
        search = escape(&search),
        max_dids = max_dids,
        es = if matching == 1 { "" } else { "es" },
        matched = if search.is_empty() { "" } else { " match" },
    );
    dashboard(&state, &did, Section::Mailboxes, "Mailboxes", &main)
}

#[derive(Deserialize)]
pub struct MailboxForm {
    mediation: String,
}

/// Remove a mailbox
///
/// Deletes a mailbox — its DIDs, what waits in it, its devices — and, on a
/// private mediator, forgets its member.
#[utoipa::path(
    post,
    path = "/portal/mailboxes/remove",
    tag = "portal",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "`mediation`"),
    responses(
        (status = 303, description = "Back to the mailboxes"),
        (status = 403, description = "Not from this mediator's pages")
    )
)]
pub async fn remove_mailbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MailboxForm>,
) -> Response {
    let did = match acting(&state, &headers) {
        Ok(did) => did,
        Err(response) => return *response,
    };
    match drop_mailbox(&state, &form.mediation, &did).await {
        Ok(()) => Redirect::to("/portal/mailboxes").into_response(),
        Err(err) => failed(&err),
    }
}

/// Deletes a mailbox and its member, if it was one.
async fn drop_mailbox(state: &AppState, mediation: &str, by: &str) -> anyhow::Result<()> {
    state.store.remove_mediation(mediation).await?;
    state.admin.remove_member(mediation)?;
    tracing::info!(%by, %mediation, "mailbox removed");
    Ok(())
}

/// Members
///
/// A private mediator's members — the wallets it took by invitation — and
/// the invitations still open.
#[utoipa::path(
    get,
    path = "/portal/members",
    tag = "portal",
    responses(
        (status = 200, description = "HTML page", content_type = "text/html"),
        (status = 303, description = "Not signed in, or a public mediator")
    )
)]
pub async fn members(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let did = match signed_in(&state.admin, &headers) {
        Ok(Some(did)) => did,
        Ok(None) => return Redirect::to("/portal").into_response(),
        Err(err) => return failed(&err),
    };
    if !state.mediator.limits().private {
        return Redirect::to("/portal").into_response();
    }
    let at = now();
    let listed = (|| -> anyhow::Result<_> {
        Ok((
            state.admin.members()?,
            state.admin.invitations(InvitationKind::Member, at)?,
        ))
    })();
    let (members, invitations) = match listed {
        Ok(listed) => listed,
        Err(err) => return failed(&err),
    };
    // Members whose mailbox went (idle too long) are members no more.
    let mut present = Vec::with_capacity(members.len());
    for member in members {
        match state.store.has_mediation(&member.mediation).await {
            Ok(true) => present.push(member),
            Ok(false) => {
                if let Err(err) = state.admin.remove_member(&member.mediation) {
                    return failed(&err);
                }
            }
            Err(err) => return failed(&err),
        }
    }
    let rows: String = present
        .iter()
        .map(|member| {
            format!(
                r#"<li><strong>{label}</strong><code title="{mediation}">{short}</code><span>since {since}</span>{remove}</li>"#,
                label = escape(&member.label),
                mediation = escape(&member.mediation),
                short = escape(&short(&member.mediation)),
                since = date(member.joined),
                remove = confirm_button(
                    "/portal/members/remove",
                    "mediation",
                    &member.mediation,
                    "Remove",
                    "Remove this member and their mailbox?"
                ),
            )
        })
        .collect();
    let main = format!(
        r#"<h1>Members</h1>
<p>A private mediator takes only the wallets it invites. Removing a member deletes their mailbox and what waits in it.</p>
<ul class="rows">{members}</ul>
<h2>Invite members</h2>
<p>An invitation is a QR code or a link; each wallet that opens it uses it once.</p>
<form method="post" action="/portal/invitations" class="inline">
<label>For<input type="text" name="label" maxlength="{MAX_LABEL}" placeholder="Family, Ana's phone…" required></label>
<label>Uses<input type="number" name="uses" min="1" max="{MAX_USES}" value="1" required></label>
<label>Days<input type="number" name="days" min="1" max="{MAX_DAYS}" value="7" required></label>
<button type="submit">Create</button>
</form>
<h2>Open invitations</h2>
<ul class="rows">{invitations}</ul>"#,
        members = or_empty(rows, "Nobody yet."),
        invitations = or_empty(invitation_rows(&invitations), "None."),
    );
    dashboard(&state, &did, Section::Members, "Members", &main)
}

/// Administrators
///
/// Who runs the mediator, and the invitations to join them.
#[utoipa::path(
    get,
    path = "/portal/admins",
    tag = "portal",
    responses(
        (status = 200, description = "HTML page", content_type = "text/html"),
        (status = 303, description = "Not signed in")
    )
)]
pub async fn admins(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let did = match signed_in(&state.admin, &headers) {
        Ok(Some(did)) => did,
        Ok(None) => return Redirect::to("/portal").into_response(),
        Err(err) => return failed(&err),
    };
    let listed = (|| -> anyhow::Result<_> {
        Ok((
            state.admin.admins()?,
            state.admin.invitations(InvitationKind::Admin, now())?,
        ))
    })();
    let (admins, invitations) = match listed {
        Ok(listed) => listed,
        Err(err) => return failed(&err),
    };
    let rows: String = admins
        .iter()
        .map(|admin| {
            let you = if admin.did == did { " (you)" } else { "" };
            format!(
                r#"<li><code title="{did}">{short}</code>{you}<span>since {since}</span>{remove}</li>"#,
                did = escape(&admin.did),
                short = escape(&short(&admin.did)),
                since = date(admin.added),
                remove = confirm_button(
                    "/portal/admins/remove",
                    "did",
                    &admin.did,
                    "Remove",
                    if admin.did == did {
                        "Stop being an administrator?"
                    } else {
                        "Remove this administrator?"
                    }
                ),
            )
        })
        .collect();
    let main = format!(
        r#"<h1>Administrators</h1>
<p>All administrators are equal: any of them can invite or remove the others. Each signs in with their Almena wallet.</p>
<ul class="rows">{rows}</ul>
<h2>Invite an administrator</h2>
<p>A link for one person, for 7 days: they open it and sign in with their wallet.</p>
<form method="post" action="/portal/admins/invite" class="inline">
<label>For<input type="text" name="label" maxlength="{MAX_LABEL}" placeholder="Who it is for" required></label>
<button type="submit">Create</button>
</form>
<h2>Open invitations</h2>
<ul class="rows">{invitations}</ul>"#,
        invitations = or_empty(invitation_rows(&invitations), "None."),
    );
    dashboard(&state, &did, Section::Admins, "Administrators", &main)
}

/// The rows of a list of invitations, each with its link and withdrawal.
fn invitation_rows(invitations: &[Invitation]) -> String {
    invitations
        .iter()
        .map(|invitation| {
            let uses = if invitation.kind == InvitationKind::Member {
                format!(
                    "<span>{} use{} left</span>",
                    invitation.uses,
                    plural(u64::from(invitation.uses))
                )
            } else {
                String::new()
            };
            format!(
                r#"<li><a href="/portal/invitations/{id}">{label}</a>{uses}<span>until {until}</span>{withdraw}</li>"#,
                id = escape(&invitation.id),
                label = escape(&invitation.label),
                until = date(invitation.expires),
                withdraw = confirm_button(
                    &format!("/portal/invitations/{}/withdraw", invitation.id),
                    "",
                    "",
                    "Withdraw",
                    "Withdraw this invitation?"
                ),
            )
        })
        .collect()
}

#[derive(Deserialize)]
pub struct MemberInvitationForm {
    label: String,
    uses: u32,
    days: u64,
}

/// Invite members
///
/// A new invitation for wallets to keep their mailbox at this private
/// mediator: `uses` wallets may take it, for `days` days.
#[utoipa::path(
    post,
    path = "/portal/invitations",
    tag = "portal",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "`label`, `uses` (1–1000), `days` (1–90)"),
    responses(
        (status = 303, description = "To the new invitation"),
        (status = 400, description = "Not private, or out of bounds"),
        (status = 403, description = "Not from this mediator's pages")
    )
)]
pub async fn create_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MemberInvitationForm>,
) -> Response {
    let did = match acting(&state, &headers) {
        Ok(did) => did,
        Err(response) => return *response,
    };
    if !state.mediator.limits().private {
        return (
            StatusCode::BAD_REQUEST,
            "A public mediator needs no invitations.",
        )
            .into_response();
    }
    let label = form.label.trim();
    if label.is_empty()
        || label.chars().count() > MAX_LABEL
        || !(1..=MAX_USES).contains(&form.uses)
        || !(1..=MAX_DAYS).contains(&form.days)
    {
        return (
            StatusCode::BAD_REQUEST,
            "Check the label, the uses (1–1000) and the days (1–90).",
        )
            .into_response();
    }
    let at = now();
    match state.admin.invite(
        InvitationKind::Member,
        label,
        form.uses,
        at + form.days * 86_400,
        &did,
        at,
    ) {
        Ok(invitation) => {
            Redirect::to(&format!("/portal/invitations/{}", invitation.id)).into_response()
        }
        Err(err) => failed(&err),
    }
}

#[derive(Deserialize)]
pub struct AdminInvitationForm {
    label: String,
}

/// Invite an administrator
///
/// A new invitation to be an administrator: one use, for 7 days.
#[utoipa::path(
    post,
    path = "/portal/admins/invite",
    tag = "portal",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "`label`"),
    responses(
        (status = 303, description = "To the new invitation"),
        (status = 400, description = "No label"),
        (status = 403, description = "Not from this mediator's pages")
    )
)]
pub async fn invite_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminInvitationForm>,
) -> Response {
    let did = match acting(&state, &headers) {
        Ok(did) => did,
        Err(response) => return *response,
    };
    let label = form.label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL {
        return (StatusCode::BAD_REQUEST, "Say who it is for.").into_response();
    }
    let at = now();
    match state.admin.invite(
        InvitationKind::Admin,
        label,
        1,
        at + ADMIN_INVITATION_SECS,
        &did,
        at,
    ) {
        Ok(invitation) => {
            Redirect::to(&format!("/portal/invitations/{}", invitation.id)).into_response()
        }
        Err(err) => failed(&err),
    }
}

/// The open invitation `id`, of either kind.
fn find_invitation(state: &AppState, id: &str) -> anyhow::Result<Option<Invitation>> {
    let at = now();
    match state.admin.invitation(InvitationKind::Member, id, at)? {
        Some(member) => Ok(Some(member)),
        None => state.admin.invitation(InvitationKind::Admin, id, at),
    }
}

/// Where an invitation of `kind` is listed.
fn listed_at(kind: InvitationKind) -> &'static str {
    match kind {
        InvitationKind::Member => "/portal/members",
        InvitationKind::Admin => "/portal/admins",
    }
}

/// An invitation
///
/// What to hand over: for members, the mediator's invitation as a QR code
/// and links; for an administrator, the link to join.
#[utoipa::path(
    get,
    path = "/portal/invitations/{id}",
    tag = "portal",
    params(("id" = String, Path, description = "The invitation")),
    responses(
        (status = 200, description = "HTML page", content_type = "text/html"),
        (status = 404, description = "No such invitation, or spent")
    )
)]
pub async fn show_invitation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let did = match signed_in(&state.admin, &headers) {
        Ok(Some(did)) => did,
        Ok(None) => return Redirect::to("/portal").into_response(),
        Err(err) => return failed(&err),
    };
    let invitation = match find_invitation(&state, &id) {
        Ok(Some(invitation)) => invitation,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                page(
                    "Invitation",
                    r#"<h1>No such invitation</h1><p>It was used up, expired or withdrawn. <a href="/portal">Back</a></p>"#.to_owned(),
                ),
            )
                .into_response();
        }
        Err(err) => return failed(&err),
    };
    let (lead, shown, open) = match invitation.kind {
        InvitationKind::Member => {
            let message = crate::oob::member_invitation(state.mediator.identity(), &invitation.id);
            (
                format!(
                    "Hand this to whoever should keep their mailbox here: they scan it with the Almena wallet, or open the link on the phone that has it. {} use{} left, until {}.",
                    invitation.uses,
                    plural(u64::from(invitation.uses)),
                    date(invitation.expires)
                ),
                crate::oob::invitation_url(&state.public_url, &message),
                crate::oob::wallet_url(&message),
            )
        }
        InvitationKind::Admin => {
            let url = format!("{}/portal/join/{}", state.public_url, invitation.id);
            (
                format!(
                    "Send this link to the new administrator. They open it and sign in with their Almena wallet. One use, until {}.",
                    date(invitation.expires)
                ),
                url.clone(),
                url,
            )
        }
    };
    let section = match invitation.kind {
        InvitationKind::Member => Section::Members,
        InvitationKind::Admin => Section::Admins,
    };
    let main = format!(
        r#"<h1>{label}</h1>
<p>{lead}</p>
<figure class="signin"><div class="qr" role="img" aria-label="Invitation QR code">{qr}</div></figure>
<a class="open" href="{open}">{open_label}</a>
<label>Link<input type="text" readonly value="{shown}" onclick="this.select()"></label>
<p><a href="{back}">Back</a></p>"#,
        label = escape(&invitation.label),
        lead = escape(&lead),
        qr = qr_svg(&shown),
        open = escape(&open),
        open_label = if invitation.kind == InvitationKind::Member {
            "Open in Almena wallet"
        } else {
            "Open the link"
        },
        shown = escape(&shown),
        back = listed_at(invitation.kind),
    );
    dashboard(&state, &did, section, "Invitation", &main)
}

/// Withdraw an invitation
#[utoipa::path(
    post,
    path = "/portal/invitations/{id}/withdraw",
    tag = "portal",
    params(("id" = String, Path, description = "The invitation")),
    responses(
        (status = 303, description = "Back to where it was listed"),
        (status = 403, description = "Not from this mediator's pages")
    )
)]
pub async fn withdraw_invitation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = acting(&state, &headers) {
        return *response;
    }
    let back = match find_invitation(&state, &id) {
        Ok(found) => found.map_or("/portal", |invitation| listed_at(invitation.kind)),
        Err(err) => return failed(&err),
    };
    match state.admin.withdraw(&id) {
        Ok(()) => Redirect::to(back).into_response(),
        Err(err) => failed(&err),
    }
}

/// Remove a member
///
/// Deletes the member's mailbox — its DIDs, what waits in it, its devices —
/// and forgets the member. Its wallet would need a new invitation.
#[utoipa::path(
    post,
    path = "/portal/members/remove",
    tag = "portal",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "`mediation`"),
    responses(
        (status = 303, description = "Back to the members"),
        (status = 403, description = "Not from this mediator's pages")
    )
)]
pub async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MailboxForm>,
) -> Response {
    let did = match acting(&state, &headers) {
        Ok(did) => did,
        Err(response) => return *response,
    };
    match drop_mailbox(&state, &form.mediation, &did).await {
        Ok(()) => Redirect::to("/portal/members").into_response(),
        Err(err) => failed(&err),
    }
}

#[derive(Deserialize)]
pub struct AdminForm {
    did: String,
}

/// Remove an administrator
///
/// Any administrator may remove any, themselves included: running the
/// mediator is up to them. Without any, whoever runs it gets a new setup
/// code at the next start (or from `almena-mediator setup`).
#[utoipa::path(
    post,
    path = "/portal/admins/remove",
    tag = "portal",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "`did`"),
    responses(
        (status = 303, description = "Back to the administrators"),
        (status = 403, description = "Not from this mediator's pages")
    )
)]
pub async fn remove_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminForm>,
) -> Response {
    let did = match acting(&state, &headers) {
        Ok(did) => did,
        Err(response) => return *response,
    };
    match state.admin.remove_admin(&form.did) {
        Ok(()) => {
            tracing::info!(by = %did, admin = %form.did, "administrator removed");
            Redirect::to("/portal/admins").into_response()
        }
        Err(err) => failed(&err),
    }
}

// ---- helpers ----

fn access_text(private: bool) -> &'static str {
    if private {
        "Private: only the wallets its administrators invite"
    } else {
        "Public: any wallet"
    }
}

fn plural(n: u64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn or_empty(rows: String, empty: &str) -> String {
    if rows.is_empty() {
        format!(r#"<li class="empty">{empty}</li>"#)
    } else {
        rows
    }
}

/// A small form that posts `name=value` to `action`, after the browser
/// asks `question`.
pub(super) fn confirm_button(
    action: &str,
    name: &str,
    value: &str,
    label: &str,
    question: &str,
) -> String {
    let field = if name.is_empty() {
        String::new()
    } else {
        format!(
            r#"<input type="hidden" name="{name}" value="{}">"#,
            escape(value)
        )
    };
    format!(
        r#"<form method="post" action="{action}" class="row-action" onsubmit="return confirm(this.dataset.q)" data-q="{question}">{field}<button type="submit" class="ghost small">{label}</button></form>"#,
        action = escape(action),
        question = escape(question),
    )
}

/// A long DID, shortened for a list: its start and its end.
pub(super) fn short(did: &str) -> String {
    if did.chars().count() <= 40 {
        return did.to_owned();
    }
    let head: String = did.chars().take(24).collect();
    let tail: String = did.chars().skip(did.chars().count() - 8).collect();
    format!("{head}…{tail}")
}

/// `1.2 KB`, `3 B`: a size for people.
fn size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// `YYYY-MM-DD HH:MM` (UTC) of epoch seconds.
fn when(secs: u64) -> String {
    format!(
        "{} {:02}:{:02}",
        date(secs),
        secs % 86_400 / 3_600,
        secs % 3_600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_times_read_well() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1536), "1.5 KB");
        assert_eq!(size(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(
            when(1_794_355_200 + 3_600 * 13 + 60 * 7),
            "2026-11-11 13:07"
        );
        assert_eq!(short("did:peer:2.short"), "did:peer:2.short");
        assert!(short(&"x".repeat(60)).contains('…'));
    }
}
