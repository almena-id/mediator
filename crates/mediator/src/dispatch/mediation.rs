//! Coordinate Mediation 3.0 (the mediator side) and Routing 2.0 `forward`.

use almena_didcomm::crypto::jwe::Jwe;
use almena_didcomm::did::did_of;
use almena_didcomm::message::now;
use almena_didcomm::{Message, PossessionProof, b64};
use serde_json::{Value, json};

use super::protocols::{self, Problem};
use super::{Handled, Mediator, ReceiveError};
use crate::admin::InvitationKind;
use crate::metrics::{Forward, METRICS, Refusal};
use crate::store::{AddRecipient, Queued, RemoveRecipient};

/// Most `add`s needing a possession proof one `recipient-update` may carry:
/// each may cost a DID resolution and a signature check, so one message
/// cannot ask for many, however many DIDs a mediation may hold.
pub const MAX_PROVED_ADDS: usize = 100;
/// Most entries one `recipient-update` may carry: each is a store call.
pub const MAX_UPDATES: usize = 1_000;

/// Handles a Coordinate Mediation message from `requester` (an authenticated DID).
pub async fn handle(
    mediator: &Mediator,
    requester: &str,
    message: &Message,
) -> anyhow::Result<Handled> {
    let store = mediator.store();
    match message.type_.as_str() {
        protocols::MEDIATE_REQUEST => {
            // Open with limits (SPEC.md §11): granted while there is room;
            // a mediation already held always is, so its wallet keeps working.
            // A private mediator takes only the wallets its administrators
            // invite: a new one answers an invitation (its id as `pthid`),
            // which gives up one use. One held already needs none. Granting
            // is serialised: looking it up, taking the use and granting are
            // one step, however often the wallet asks at once.
            let _granting = mediator.granting().await;
            let invited = if mediator.limits().private && !store.has_mediation(requester).await? {
                let taken = match (mediator.admin(), message.pthid.as_deref()) {
                    (Some(admin), Some(id)) => admin
                        .use_invitation(InvitationKind::Member, id, now())?
                        .map(|label| (admin, id, label)),
                    _ => None,
                };
                let Some(taken) = taken else {
                    tracing::debug!(mediation = %requester, "mediation denied: private, not invited");
                    let deny = Message::new(
                        protocols::MEDIATE_DENY,
                        json!({"reason": "invitation_required"}),
                    );
                    return Ok(Handled::Reply(deny.reply_to(message)));
                };
                Some(taken)
            } else {
                None
            };
            if !store
                .grant_mediation(requester, now(), mediator.limits().max_mediations)
                .await?
            {
                if let Some((admin, id, _)) = &invited {
                    admin.give_back_use(InvitationKind::Member, id)?;
                }
                let refusal = Refusal::Mediations;
                METRICS.capacity_refused(refusal);
                tracing::debug!(mediation = %requester, ?refusal, "mediation denied: at capacity");
                let deny = Message::new(protocols::MEDIATE_DENY, json!({"reason": "full"}));
                return Ok(Handled::Reply(deny.reply_to(message)));
            }
            if let Some((admin, _, label)) = &invited {
                admin.add_member(requester, label, now())?;
                tracing::info!(mediation = %requester, %label, "member joined by invitation");
            }
            METRICS.mediation_granted();
            tracing::debug!(mediation = %requester, "mediation granted");
            let grant = Message::new(
                protocols::MEDIATE_GRANT,
                // `max_recipient_dids` is Almena's: how many DIDs this
                // mediation may register, for the wallet to show and warn.
                json!({
                    "routing_did": [mediator.identity().did],
                    "max_recipient_dids": mediator.limits().max_recipient_dids,
                }),
            );
            Ok(Handled::Reply(grant.reply_to(message)))
        }
        protocols::RECIPIENT_UPDATE => {
            if !store.has_mediation(requester).await? {
                return Ok(Handled::Problem(Problem::NoMediation));
            }
            let Some(updates) = message
                .body
                .get("updates")
                .and_then(Value::as_array)
                .filter(|updates| updates.len() <= MAX_UPDATES)
            else {
                return Ok(Handled::Problem(Problem::InvalidBody));
            };
            // How many DIDs the mediation may hold (`ALMENA_MAX_RECIPIENT_DIDS`).
            let max = mediator.limits().max_recipient_dids;
            // Each `add` of another DID may cost a DID resolution and a
            // signature check: no more of them in one message than
            // `MAX_PROVED_ADDS`, when they need a proof at all.
            if mediator.limits().recipient_proof {
                let proved = updates
                    .iter()
                    .filter(|u| u.get("action").and_then(Value::as_str) == Some("add"))
                    .filter_map(|u| u.get("recipient_did").and_then(Value::as_str))
                    .filter(|did| is_did(did) && *did != requester)
                    .count();
                if proved > MAX_PROVED_ADDS {
                    return Ok(Handled::Problem(Problem::InvalidBody));
                }
            }
            let mut held = store.recipients(requester).await?;
            let mut updated = Vec::with_capacity(updates.len());
            for update in updates {
                let did = update
                    .get("recipient_did")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let action = update
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let full = action == "add" && !held.iter().any(|r| r == did) && held.len() >= max;
                let mut reason = full.then_some("limit");
                let result = if !is_did(did) || full {
                    "client_error"
                } else if action == "add"
                    && let Err(reason) = check_proof(mediator, requester, did, update).await
                {
                    tracing::debug!(mediation = %requester, recipient = %did, reason, "recipient refused");
                    "client_error"
                } else {
                    match action {
                        "add" => match store.add_recipient(requester, did, max).await? {
                            AddRecipient::Added => {
                                held.push(did.to_owned());
                                "success"
                            }
                            AddRecipient::AlreadyYours => "no_change",
                            AddRecipient::TakenByOther | AddRecipient::NoMediation => {
                                "client_error"
                            }
                            AddRecipient::LimitReached => {
                                reason = Some("limit");
                                "client_error"
                            }
                        },
                        "remove" => match store.remove_recipient(requester, did).await? {
                            RemoveRecipient::Removed => {
                                held.retain(|r| r != did);
                                "success"
                            }
                            RemoveRecipient::NotRegistered => "no_change",
                            RemoveRecipient::NotYours => "client_error",
                        },
                        _ => "client_error",
                    }
                };
                let mut entry = json!({"recipient_did": did, "action": action, "result": result});
                // Almena's: why, when it is the mediation's DID limit.
                if let Some(reason) = reason {
                    entry["reason"] = json!(reason);
                }
                updated.push(entry);
            }
            let response = Message::new(
                protocols::RECIPIENT_UPDATE_RESPONSE,
                json!({ "updated": updated }),
            );
            Ok(Handled::Reply(response.reply_to(message)))
        }
        protocols::RECIPIENT_QUERY => {
            if !store.has_mediation(requester).await? {
                return Ok(Handled::Problem(Problem::NoMediation));
            }
            let all = store.recipients(requester).await?;
            let body = match message.body.get("paginate") {
                None => json!({ "dids": dids(&all) }),
                Some(paginate) => {
                    let (Some(limit), Some(offset)) = (
                        paginate.get("limit").and_then(Value::as_u64),
                        paginate.get("offset").and_then(Value::as_u64),
                    ) else {
                        return Ok(Handled::Problem(Problem::InvalidBody));
                    };
                    let offset = usize::try_from(offset).unwrap_or(usize::MAX).min(all.len());
                    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
                    let page = &all[offset..offset.saturating_add(limit).min(all.len())];
                    json!({
                        "dids": dids(page),
                        "pagination": {
                            "count": page.len(),
                            "offset": offset,
                            "remaining": all.len() - offset - page.len(),
                        }
                    })
                }
            };
            Ok(Handled::Reply(
                Message::new(protocols::RECIPIENT, body).reply_to(message),
            ))
        }
        _ => Ok(Handled::Problem(Problem::UnsupportedType)),
    }
}

/// How old a possession proof may be, and how far ahead of our clock.
const PROOF_MAX_AGE_SECS: u64 = 300;
const PROOF_MAX_SKEW_SECS: u64 = 60;

/// A recipient DID other than the mediation's own must come with a proof
/// that the requester controls it: a [`PossessionProof`] (`update.proof`)
/// issued by that DID, for this mediator, on behalf of this mediation, and
/// recent. Without it anyone could claim someone else's DID first.
async fn check_proof(
    mediator: &Mediator,
    requester: &str,
    did: &str,
    update: &Value,
) -> Result<(), &'static str> {
    if !mediator.limits().recipient_proof || did == requester {
        return Ok(());
    }
    let token = update
        .get("proof")
        .and_then(Value::as_str)
        .ok_or("no proof")?;
    let proof = PossessionProof::unpack(token, mediator.resolver())
        .await
        .map_err(|_| "proof does not verify")?;
    let now = now();
    if proof.iss != did {
        Err("proof is for another DID")
    } else if proof.aud != mediator.identity().did {
        Err("proof is for another mediator")
    } else if proof.sub != requester {
        Err("proof is for another mediation")
    } else if proof.iat + PROOF_MAX_AGE_SECS < now || proof.iat > now + PROOF_MAX_SKEW_SECS {
        Err("proof is not recent")
    } else {
        Ok(())
    }
}

fn dids(list: &[String]) -> Vec<Value> {
    list.iter()
        .map(|did| json!({ "recipient_did": did }))
        .collect()
}

/// A DID without fragment, query or path.
fn is_did(value: &str) -> bool {
    value.starts_with("did:") && value.len() > 4 && did_of(value) == value
}

/// Routing 2.0: queues each attached message for `next` when it is a
/// recipient DID (or one of its key ids) registered with this mediator, and
/// relays it to `next`'s own mediator otherwise (see `relay`). Forward
/// senders are anonymous by design, so failures are reported at the HTTP
/// level (see `ReceiveError`), never as DIDComm problem reports.
pub async fn forward(mediator: &Mediator, message: &Message) -> Result<(), ReceiveError> {
    let next = message
        .body
        .get("next")
        .and_then(Value::as_str)
        .ok_or(ReceiveError::BadForward("forward without next"))?;
    let attachments = message
        .attachments
        .as_deref()
        .filter(|a| !a.is_empty())
        .ok_or(ReceiveError::BadForward("forward without attachments"))?;

    // Check everything before queueing anything.
    let mut payloads = Vec::with_capacity(attachments.len());
    for attachment in attachments {
        let payload = if let Some(json) = &attachment.data.json {
            json.to_string()
        } else if let Some(base64) = &attachment.data.base64 {
            String::from_utf8(
                b64::decode(base64)
                    .map_err(|_| ReceiveError::BadForward("attachment is not base64url"))?,
            )
            .map_err(|_| ReceiveError::BadForward("attachment is not UTF-8"))?
        } else {
            return Err(ReceiveError::BadForward(
                "only json and base64 attachments are supported",
            ));
        };
        // Message Pickup delivers only DIDComm encrypted messages.
        Jwe::parse(&payload).map_err(|_| {
            ReceiveError::BadForward("attachment is not an encrypted DIDComm message")
        })?;
        payloads.push(payload);
    }

    let recipient = did_of(next);
    let Some(mediation) = mediator.store().mediation_of(recipient).await? else {
        // Not ours: pass it on to the mediator that mediates `next`, if allowed.
        return super::relay::relay(mediator, next, payloads).await;
    };
    queue_all(mediator, &mediation, recipient, payloads).await?;
    tracing::debug!(%recipient, count = attachments.len(), "forward queued");
    METRICS.forward(Forward::Queued, attachments.len() as u64);
    mediator.wake(&mediation);
    Ok(())
}

/// Queues one encrypted message for `recipient` of `mediation` and pushes
/// it to the mediation's live sessions. Waking its devices is the caller's.
pub async fn queue(
    mediator: &Mediator,
    mediation: &str,
    recipient: &str,
    payload: String,
) -> Result<(), ReceiveError> {
    queue_all(mediator, mediation, recipient, vec![payload]).await
}

/// [`queue`] for several messages: all of them, or none if they do not all
/// fit, so that the sender's retry duplicates nothing.
async fn queue_all(
    mediator: &Mediator,
    mediation: &str,
    recipient: &str,
    payloads: Vec<String>,
) -> Result<(), ReceiveError> {
    let received = now();
    let ids = mediator
        .store()
        .enqueue_all(
            mediation,
            recipient,
            &payloads,
            received,
            mediator.limits().queue,
        )
        .await?
        .ok_or(ReceiveError::QueueFull)?;
    let queued: Vec<Queued> = ids
        .into_iter()
        .zip(payloads)
        .map(|(id, message)| Queued {
            id,
            recipient: recipient.to_owned(),
            received,
            message,
        })
        .collect();
    for queued in &queued {
        mediator.live().notify(mediation, queued);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dids_only() {
        assert!(is_did("did:peer:2.abc"));
        assert!(!is_did("did:peer:2.abc#key-1"));
        assert!(!is_did("did:"));
        assert!(!is_did("https://example.com"));
    }
}
