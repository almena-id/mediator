//! Message Pickup 3.0 (the mediator side). Live mode needs a WebSocket
//! session; over HTTP it is refused.

use almena_didcomm::message::now;
use almena_didcomm::{Attachment, Message};
use serde_json::{Value, json};

use super::live::Session;
use super::protocols::{self, Problem};
use super::{Handled, Mediator};

/// Most messages one `delivery` carries, whatever `limit` asks for.
pub const MAX_BATCH: u64 = 100;

/// Handles a Message Pickup message from `requester` (an authenticated DID)
/// that arrived on `session` (a WebSocket) or over HTTP (`None`).
pub async fn handle(
    mediator: &Mediator,
    requester: &str,
    message: &Message,
    session: Option<&mut Session>,
) -> anyhow::Result<Handled> {
    let store = mediator.store();
    if !store.has_mediation(requester).await? {
        return Ok(Handled::Problem(Problem::NoMediation));
    }
    // Any pickup means the wallet is awake: pushes may resume.
    mediator.picked_up(requester).await?;
    // `recipient_did`, when given, must be one of the requester's.
    let recipient = match message.body.get("recipient_did") {
        None | Some(Value::Null) => None,
        Some(Value::String(did)) => {
            if !store.recipients(requester).await?.contains(did) {
                return Ok(Handled::Problem(Problem::UnknownRecipient(did.clone())));
            }
            Some(did.as_str())
        }
        Some(_) => return Ok(Handled::Problem(Problem::InvalidBody)),
    };
    let ttl = mediator.limits().queue.ttl_secs;
    let live = session.as_deref().is_some_and(|s| s.is_live_for(requester));

    match message.type_.as_str() {
        protocols::STATUS_REQUEST => status(mediator, requester, recipient, message, live).await,
        protocols::DELIVERY_REQUEST => {
            let Some(limit) = message
                .body
                .get("limit")
                .and_then(Value::as_u64)
                .filter(|&l| l > 0)
            else {
                return Ok(Handled::Problem(Problem::InvalidBody));
            };
            let limit = usize::try_from(limit.min(MAX_BATCH)).unwrap_or(1);
            let queued = store.peek(requester, recipient, limit, now(), ttl).await?;
            if queued.is_empty() {
                // The protocol: "If no messages are available to be sent, a status message MUST be sent".
                return status(mediator, requester, recipient, message, live).await;
            }
            let mut body = json!({});
            if let Some(did) = recipient {
                body["recipient_did"] = json!(did);
            }
            let mut delivery = Message::new(protocols::DELIVERY, body).reply_to(message);
            for q in queued {
                delivery =
                    delivery.attachment(Attachment::base64(q.message.as_bytes()).with_id(q.id));
            }
            Ok(Handled::Reply(delivery))
        }
        protocols::MESSAGES_RECEIVED => {
            let Some(ids) = message
                .body
                .get("message_id_list")
                .and_then(Value::as_array)
                .and_then(|ids| {
                    ids.iter()
                        .map(|id| id.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                })
            else {
                return Ok(Handled::Problem(Problem::InvalidBody));
            };
            let removed = store.remove(requester, &ids).await?;
            crate::metrics::METRICS.acknowledged(removed as u64);
            tracing::debug!(mediation = %requester, removed, "messages received");
            status(mediator, requester, recipient, message, live).await
        }
        protocols::LIVE_DELIVERY_CHANGE => {
            let Some(wanted) = message.body.get("live_delivery").and_then(Value::as_bool) else {
                return Ok(Handled::Problem(Problem::InvalidBody));
            };
            match (wanted, session) {
                (true, None) => Ok(Handled::Problem(Problem::LiveModeNotSupported)),
                (true, Some(session)) => {
                    mediator.live().enable(session, requester);
                    status(mediator, requester, recipient, message, true).await
                }
                (false, Some(session)) => {
                    mediator.live().disable(session);
                    status(mediator, requester, recipient, message, false).await
                }
                (false, None) => status(mediator, requester, recipient, message, false).await,
            }
        }
        _ => Ok(Handled::Problem(Problem::UnsupportedType)),
    }
}

async fn status(
    mediator: &Mediator,
    mediation: &str,
    recipient: Option<&str>,
    request: &Message,
    live: bool,
) -> anyhow::Result<Handled> {
    let now = now();
    let summary = mediator
        .store()
        .summary(mediation, recipient, now, mediator.limits().queue.ttl_secs)
        .await?;
    let mut body = json!({
        "message_count": summary.count,
        "total_bytes": summary.total_bytes,
        "live_delivery": live,
    });
    if let (Some(oldest), Some(newest)) = (summary.oldest, summary.newest) {
        body["oldest_received_time"] = json!(oldest);
        body["newest_received_time"] = json!(newest);
        body["longest_waited_seconds"] = json!(now.saturating_sub(oldest));
    }
    if let Some(did) = recipient {
        body["recipient_did"] = json!(did);
    }
    Ok(Handled::Reply(
        Message::new(protocols::STATUS, body).reply_to(request),
    ))
}
