//! Packing messages into envelopes: plaintext, signed, anoncrypt and authcrypt.

use crate::crypto::content::ContentEncryption;
use crate::crypto::jwe::{Jwe, Recipient, Sender};
use crate::crypto::jws::Jws;
use crate::did::{DidDocument, DidResolver, did_of};
use crate::message::{Attachment, Message};
use crate::secrets::SecretsResolver;
use crate::{Error, PublicKey, Result, SecretKey};

/// Options for [`Message::pack_encrypted`].
#[derive(Debug, Clone, Copy)]
pub struct PackOptions {
    /// Wrap the authcrypt envelope in an anoncrypt one so that `skid` is not
    /// visible outside (spec: "Protecting the Sender Identity").
    pub protect_sender: bool,
    /// Content encryption for anoncrypt layers (authcrypt always uses A256CBC-HS512).
    pub anoncrypt_enc: ContentEncryption,
    /// Wrap the message in `forward` messages for the recipient's mediators,
    /// as its `DIDCommMessaging` service asks (spec: "Sender Process to Enable
    /// Forwarding"). Without a service nothing is wrapped.
    pub forward: bool,
    /// What the `forward`s tell the recipient's mediator about how soon the
    /// message is needed (see [`Urgency`]).
    pub urgency: Urgency,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            protect_sender: false,
            anoncrypt_enc: ContentEncryption::A256CbcHs512,
            forward: true,
            urgency: Urgency::Normal,
        }
    }
}

/// How soon the recipient needs a message, as the `forward`s that carry it
/// tell its mediator (Almena's own `urgency` header). It says what kind of
/// wake-up the message deserves and nothing else: not who sent it, nor what
/// it says. A mediator that does not know the header ignores it, as DIDComm
/// asks of unknown headers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Urgency {
    /// An ordinary message: the recipient's devices get the usual wake-up.
    #[default]
    Normal,
    /// A call offer: the recipient's phone rings, and the offer is worthless
    /// once the caller gives up.
    Call,
}

/// The `forward` header that carries [`Urgency`]; its only value is `call`.
pub const URGENCY: &str = "urgency";

impl Urgency {
    /// The urgency a `forward` carries. Anything but `"call"`, including no
    /// header at all, is [`Urgency::Normal`]: a value this side does not know
    /// must not ring a phone.
    pub fn of(message: &Message) -> Self {
        match message.extra_headers.get(URGENCY).and_then(|v| v.as_str()) {
            Some("call") => Self::Call,
            _ => Self::Normal,
        }
    }

    /// The header value, `None` for [`Urgency::Normal`] (it is never written).
    fn header(self) -> Option<&'static str> {
        match self {
            Self::Normal => None,
            Self::Call => Some("call"),
        }
    }
}

/// Message type of Routing 2.0 `forward` messages.
pub const FORWARD: &str = "https://didcomm.org/routing/2.0/forward";

/// A packed encrypted message and the keys used.
#[derive(Debug, Clone)]
pub struct PackedMessage {
    pub message: String,
    /// Sender key (authcrypt), if any.
    pub from_kid: Option<String>,
    /// Signing key, if the message was signed first.
    pub sign_by_kid: Option<String>,
    /// Recipient keys the content key was wrapped to.
    pub to_kids: Vec<String>,
    /// Where to send `message`: the transport URI of the recipient's (or its
    /// mediator's) `DIDCommMessaging` service, if it has one.
    pub service_uri: Option<String>,
    /// Whether `message` is wrapped in `forward` messages for mediators.
    pub forwarded: bool,
}

impl Message {
    /// Plaintext JSON (`typ` = `application/didcomm-plain+json`).
    pub fn pack_plaintext(&self) -> Result<String> {
        self.validate()?;
        self.to_plaintext_json()
    }

    /// Signs the message (JWS). `sign_by` is the signer DID, or one of its
    /// `authentication` key ids; it must be the message's `from`. Returns the
    /// JWS and the signing key id.
    pub async fn pack_signed(
        &self,
        sign_by: &str,
        resolver: &dyn DidResolver,
        secrets: &dyn SecretsResolver,
    ) -> Result<(String, String)> {
        self.validate()?;
        if self.from.as_deref() != Some(did_of(sign_by)) {
            return Err(Error::inconsistent("the signer must be the message's from"));
        }
        let (kid, key) = find_signing_key(sign_by, resolver, secrets).await?;
        let jws = Jws::sign(self.to_plaintext_json()?.as_bytes(), &kid, &key)?;
        Ok((jws.to_json()?, kid))
    }

    /// Encrypts the message for `to` (a DID, or one of its `keyAgreement` key
    /// ids). With `from` (a DID or key id; must be the message's `from`) it is
    /// authcrypt, without it anoncrypt. With `sign_by` the message is signed
    /// before encryption.
    pub async fn pack_encrypted(
        &self,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
        resolver: &dyn DidResolver,
        secrets: &dyn SecretsResolver,
        options: PackOptions,
    ) -> Result<PackedMessage> {
        self.validate()?;
        if let Some(from) = from
            && self.from.as_deref() != Some(did_of(from))
        {
            return Err(Error::inconsistent("the sender must be the message's from"));
        }
        if let Some(recipients) = &self.to
            && !recipients.iter().any(|r| r == did_of(to))
        {
            return Err(Error::inconsistent(
                "the recipient is not in the message's to",
            ));
        }

        let (payload, sign_by_kid) = match sign_by {
            Some(sign_by) => {
                // Spec: the signed JWM inside an encrypted one MUST have `to`.
                if self.to.is_none() {
                    return Err(Error::malformed("a signed and encrypted message needs to"));
                }
                let (jws, kid) = self.pack_signed(sign_by, resolver, secrets).await?;
                (jws, Some(kid))
            }
            None => (self.to_plaintext_json()?, None),
        };

        let recipient_doc = resolver.resolve(did_of(to)).await?;
        let recipient_keys = key_agreement_keys(&recipient_doc, to)?;

        let (message, from_kid, to_kids) = match from {
            Some(from) => {
                let sender_doc = resolver.resolve(did_of(from)).await?;
                let (sender_kid, sender_key, recipients) =
                    find_authcrypt_keys(&sender_doc, from, &recipient_keys, secrets).await?;
                let recipients: Vec<Recipient<'_>> = recipients
                    .iter()
                    .map(|(kid, key)| Recipient { kid, key })
                    .collect();
                let jwe = Jwe::authcrypt(
                    payload.as_bytes(),
                    &Sender {
                        kid: &sender_kid,
                        key: &sender_key,
                    },
                    &recipients,
                )?
                .to_json()?;
                let jwe = if options.protect_sender {
                    Jwe::anoncrypt(jwe.as_bytes(), &recipients, options.anoncrypt_enc)?.to_json()?
                } else {
                    jwe
                };
                let kids = recipients.iter().map(|r| r.kid.to_owned()).collect();
                (jwe, Some(sender_kid), kids)
            }
            None => {
                let curve = recipient_keys[0].1.curve();
                let recipients: Vec<Recipient<'_>> = recipient_keys
                    .iter()
                    .filter(|(_, key)| key.curve() == curve)
                    .map(|(kid, key)| Recipient { kid, key })
                    .collect();
                let jwe = Jwe::anoncrypt(payload.as_bytes(), &recipients, options.anoncrypt_enc)?
                    .to_json()?;
                let kids = recipients.iter().map(|r| r.kid.to_owned()).collect();
                (jwe, None, kids)
            }
        };

        let (message, service_uri, forwarded) = if options.forward {
            let routed = route_with(
                message,
                to,
                resolver,
                options.anoncrypt_enc,
                options.urgency,
            )
            .await?;
            (
                routed.message,
                routed.service_uri,
                routed.first_hop.is_some(),
            )
        } else {
            (message, None, false)
        };

        Ok(PackedMessage {
            message,
            from_kid,
            sign_by_kid,
            to_kids,
            service_uri,
            forwarded,
        })
    }
}

/// A message made ready for transport by [`route`].
#[derive(Debug, Clone)]
pub struct Routed {
    /// The message, wrapped in `forward`s if the route has hops.
    pub message: String,
    /// Where to send it; `None` if the recipient has no DIDComm service.
    pub service_uri: Option<String>,
    /// The first routing hop (a DID or key id) the outermost `forward` is
    /// encrypted to; `None` when nothing was wrapped.
    pub first_hop: Option<String>,
}

/// Wraps an already encrypted message for each routing hop of `to`'s
/// `DIDCommMessaging` service (spec: "Sender Process to Enable Forwarding").
/// [`Message::pack_encrypted`] does this itself unless told not to;
/// mediators call it to relay a `forward` payload to its next party.
///
/// The service's first endpoint that accepts `didcomm/v2` is used. If its
/// `uri` is a DID (spec: "Using a DID as an endpoint"), that DID is a
/// mediator: its `keyAgreement` keys go first in the routing keys, and the
/// transport URI comes from its own service. Each routing key, from last to
/// first, gets a `forward` whose `next` is the hop after it.
pub async fn route(
    packed: String,
    to: &str,
    resolver: &dyn DidResolver,
    enc: ContentEncryption,
) -> Result<Routed> {
    route_with(packed, to, resolver, enc, Urgency::Normal).await
}

/// [`route`], with every `forward` carrying `urgency`: each mediator on the
/// way learns it, so the last one can wake the recipient accordingly.
pub async fn route_with(
    mut packed: String,
    to: &str,
    resolver: &dyn DidResolver,
    enc: ContentEncryption,
    urgency: Urgency,
) -> Result<Routed> {
    let recipient = did_of(to);
    let doc = resolver.resolve(recipient).await?;
    let Some(endpoint) = first_didcomm_endpoint(&doc)? else {
        return Ok(Routed {
            message: packed,
            service_uri: None,
            first_hop: None,
        });
    };

    let mut routing_keys = endpoint.routing_keys.clone();
    let uri = if endpoint.uri.starts_with("did:") {
        let mediator = resolver.resolve(&endpoint.uri).await?;
        let mediator_endpoint = first_didcomm_endpoint(&mediator)?.ok_or_else(|| {
            Error::NoCompatibleKeys(format!("mediator {} has no DIDComm service", mediator.id))
        })?;
        if mediator_endpoint.uri.starts_with("did:") {
            return Err(Error::unsupported(
                "a mediator whose endpoint is another DID",
            ));
        }
        routing_keys.insert(0, mediator.id.clone());
        mediator_endpoint.uri
    } else {
        endpoint.uri
    };

    for (i, hop) in routing_keys.iter().enumerate().rev() {
        let next = routing_keys.get(i + 1).map_or(recipient, String::as_str);
        let envelope: serde_json::Value = serde_json::from_str(&packed)?;
        let mut forward = Message::new(FORWARD, serde_json::json!({ "next": next }))
            .to([did_of(hop)])
            .attachment(
                Attachment::json(envelope).with_media_type(crate::crypto::jwe::ENCRYPTED_TYP),
            );
        if let Some(value) = urgency.header() {
            forward = forward.header(URGENCY, value.into());
        }
        let hop_doc = resolver.resolve(did_of(hop)).await?;
        let keys = key_agreement_keys(&hop_doc, hop)?;
        let curve = keys[0].1.curve();
        let recipients: Vec<Recipient<'_>> = keys
            .iter()
            .filter(|(_, key)| key.curve() == curve)
            .map(|(kid, key)| Recipient { kid, key })
            .collect();
        packed =
            Jwe::anoncrypt(forward.to_plaintext_json()?.as_bytes(), &recipients, enc)?.to_json()?;
    }
    Ok(Routed {
        message: packed,
        service_uri: Some(uri),
        first_hop: routing_keys.into_iter().next(),
    })
}

fn first_didcomm_endpoint(doc: &DidDocument) -> Result<Option<crate::did::DidCommEndpoint>> {
    for service in doc.didcomm_services() {
        for endpoint in service.didcomm_endpoints()? {
            if endpoint.accept.is_empty() || endpoint.accept.iter().any(|a| a == "didcomm/v2") {
                return Ok(Some(endpoint));
            }
        }
    }
    Ok(None)
}

/// The recipient's `keyAgreement` keys usable for DIDComm: just `to` if it is
/// a key id, else all of them.
fn key_agreement_keys(doc: &DidDocument, to: &str) -> Result<Vec<(String, PublicKey)>> {
    let keys: Vec<(String, PublicKey)> = if to.contains('#') {
        vec![(to.to_owned(), doc.key_agreement_key(to)?.clone())]
    } else {
        doc.key_agreement_methods()
            .filter(|m| m.key.curve().is_key_agreement())
            .map(|m| (m.id.clone(), m.key.clone()))
            .collect()
    };
    if keys.is_empty() {
        return Err(Error::NoCompatibleKeys(format!(
            "{to} has no keyAgreement keys"
        )));
    }
    Ok(keys)
}

/// The first sender `keyAgreement` key we hold a secret for that shares a
/// curve with at least one recipient key, and those recipient keys.
async fn find_authcrypt_keys(
    sender_doc: &DidDocument,
    from: &str,
    recipient_keys: &[(String, PublicKey)],
    secrets: &dyn SecretsResolver,
) -> Result<(String, SecretKey, Vec<(String, PublicKey)>)> {
    let candidates: Vec<String> = if from.contains('#') {
        sender_doc.key_agreement_key(from)?;
        vec![from.to_owned()]
    } else {
        sender_doc.key_agreement.clone()
    };
    for kid in candidates {
        let Some(secret) = secrets.get_secret(&kid).await? else {
            continue;
        };
        let matching: Vec<_> = recipient_keys
            .iter()
            .filter(|(_, key)| key.curve() == secret.curve())
            .cloned()
            .collect();
        if !matching.is_empty() {
            return Ok((kid, secret, matching));
        }
    }
    Err(Error::NoCompatibleKeys(format!(
        "no key of {from} we hold shares a curve with the recipient"
    )))
}

/// The signing key for `sign_by` (a DID or one of its `authentication` key
/// ids): the first `authentication` key we hold a secret for and that can sign.
pub(crate) async fn find_signing_key(
    sign_by: &str,
    resolver: &dyn DidResolver,
    secrets: &dyn SecretsResolver,
) -> Result<(String, SecretKey)> {
    let doc = resolver.resolve(did_of(sign_by)).await?;
    let candidates: Vec<String> = if sign_by.contains('#') {
        doc.authentication_key(sign_by)?;
        vec![sign_by.to_owned()]
    } else {
        doc.authentication.clone()
    };
    for kid in candidates {
        if let Some(secret) = secrets.get_secret(&kid).await?
            && secret.curve().signature_alg().is_some()
        {
            return Ok((kid, secret));
        }
    }
    Err(Error::SecretNotFound(format!("signing key for {sign_by}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urgency_reads_only_call() {
        let forward = |value: Option<serde_json::Value>| {
            let message = Message::new(FORWARD, serde_json::json!({"next": "did:example:bob"}));
            match value {
                Some(value) => message.header(URGENCY, value),
                None => message,
            }
        };
        assert_eq!(Urgency::of(&forward(None)), Urgency::Normal);
        let call = forward(Urgency::Call.header().map(Into::into));
        assert_eq!(Urgency::of(&call), Urgency::Call);
        // Through the wire format and back.
        let json = call.to_plaintext_json().unwrap();
        let parsed: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.extra_headers[URGENCY], "call");
        assert_eq!(Urgency::of(&parsed), Urgency::Call);
        // Values this side does not know never ring.
        for unknown in [
            serde_json::json!("CALL"),
            serde_json::json!("urgent"),
            serde_json::json!(true),
            serde_json::json!(null),
        ] {
            assert_eq!(Urgency::of(&forward(Some(unknown))), Urgency::Normal);
        }
        assert_eq!(Urgency::default(), Urgency::Normal);
        assert_eq!(PackOptions::default().urgency, Urgency::Normal);
    }
}
