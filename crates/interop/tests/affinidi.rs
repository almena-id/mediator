//! `almena-didcomm` and the mediator against Affinidi's DIDComm library
//! (`affinidi-messaging-didcomm` 0.15, DIDComm v2.1).
//!
//! Envelopes both ways on every key agreement curve both support — X25519,
//! P-256, P-384 and P-521 (didcomm-rust has no P-384/P-521, so this is where
//! those are checked against another implementation) — and signatures. Then
//! a whole mediation run with Affinidi as the wallets and the mediator
//! in-process, on X25519 and on P-384 (the mediator's two curves): ping,
//! mediation, a `forward` from Alice, pickup by Bob and acknowledgement.
//!
//! Affinidi's library has no Coordinate Mediation or Pickup helpers, so the
//! protocol messages are built here; every envelope is Affinidi's.

use std::sync::Arc;

use affinidi_crypto::jose::key_agreement::{
    Curve as TheirCurve, PrivateKeyAgreement, PublicKeyAgreement,
};
use affinidi_messaging_didcomm::jws::sign::JwsSigner;
use affinidi_messaging_didcomm::message::{forward, pack, unpack as their_unpack};
use affinidi_messaging_didcomm::{Message as TheirMessage, UnpackResult};
use almena_didcomm::did::DidDocument;
use almena_didcomm::did::peer::{Purpose, peer2};
use almena_didcomm::{
    Curve, InMemorySecrets, LocalResolver, Message, PackOptions, SecretKey, StaticResolver, unpack,
};
use almena_mediator::dispatch::{Limits, Mediator, Outcome};
use almena_mediator::identity::Identity;
use almena_mediator::store::{MemoryStore, QueueLimits};
use serde_json::{Value, json};

const TYPE: &str = "https://example.com/protocols/interop/1.0/hello";
const AGREEMENT: [Curve; 4] = [Curve::X25519, Curve::P256, Curve::P384, Curve::P521];

fn their_curve(curve: Curve) -> TheirCurve {
    match curve {
        Curve::X25519 => TheirCurve::X25519,
        Curve::P256 => TheirCurve::P256,
        Curve::P384 => TheirCurve::P384,
        Curve::P521 => TheirCurve::P521,
        other => panic!("no key agreement on {other:?}"),
    }
}

/// Our key as Affinidi's.
fn their_private(key: &SecretKey) -> PrivateKeyAgreement {
    PrivateKeyAgreement::from_raw_bytes(their_curve(key.curve()), &key.to_bytes()).unwrap()
}

fn their_public(key: &almena_didcomm::PublicKey) -> PublicKeyAgreement {
    PublicKeyAgreement::from_jwk(&serde_json::to_value(key.to_jwk()).unwrap()).unwrap()
}

fn seed(key: &SecretKey) -> [u8; 32] {
    key.to_bytes().as_slice().try_into().unwrap()
}

/// A `did:peer:2` party: an Ed25519 signing key (`#key-1`) and a key
/// agreement key (`#key-2`), optionally reachable through a mediator.
struct Party {
    did: String,
    signing: SecretKey,
    agreement: SecretKey,
    ours: InMemorySecrets,
}

impl Party {
    fn new(curve: Curve, mediator: Option<&str>) -> Self {
        let signing = SecretKey::generate(Curve::Ed25519).unwrap();
        let agreement = SecretKey::generate(curve).unwrap();
        let services: Vec<Value> = mediator
            .map(|m| json!({"type": "DIDCommMessaging", "serviceEndpoint": {"uri": m, "accept": ["didcomm/v2"]}}))
            .into_iter()
            .collect();
        let did = peer2(
            &[
                (Purpose::Verification, &signing.public_key()),
                (Purpose::Encryption, &agreement.public_key()),
            ],
            &services,
        )
        .unwrap();
        let mut ours = InMemorySecrets::new();
        ours.insert(format!("{did}#key-1"), signing.clone());
        ours.insert(format!("{did}#key-2"), agreement.clone());
        Self {
            did,
            signing,
            agreement,
            ours,
        }
    }

    fn signing_kid(&self) -> String {
        format!("{}#key-1", self.did)
    }

    fn agreement_kid(&self) -> String {
        format!("{}#key-2", self.did)
    }

    fn their_private(&self) -> PrivateKeyAgreement {
        their_private(&self.agreement)
    }

    fn their_public(&self) -> PublicKeyAgreement {
        their_public(&self.agreement.public_key())
    }
}

fn opened(result: UnpackResult) -> (TheirMessage, bool, bool) {
    match result {
        UnpackResult::Encrypted {
            message,
            authenticated,
            legacy_kek_used,
            ..
        } => {
            assert!(!legacy_kek_used, "decrypted only with the legacy KEK");
            (message, authenticated, true)
        }
        UnpackResult::Signed { message, .. } => (message, false, false),
        UnpackResult::Plaintext(message) => (message, false, false),
        _ => panic!("unknown unpack result"),
    }
}

// ---- envelopes ----

#[tokio::test]
async fn almena_envelopes_open_with_affinidi() {
    for curve in AGREEMENT {
        let (alice, bob) = (Party::new(curve, None), Party::new(curve, None));
        let message = Message::new(TYPE, json!({"text": "hola"}))
            .from(&alice.did)
            .to([bob.did.as_str()]);
        for from in [None, Some(alice.did.as_str())] {
            let packed = message
                .pack_encrypted(
                    &bob.did,
                    from,
                    None,
                    &LocalResolver::new(),
                    &alice.ours,
                    PackOptions::default(),
                )
                .await
                .unwrap();
            let sender = from.map(|_| alice.their_public());
            let (message, authenticated, encrypted) = opened(
                their_unpack::unpack(
                    &packed.message,
                    Some(&bob.agreement_kid()),
                    Some(&bob.their_private()),
                    sender.as_ref(),
                    None,
                )
                .unwrap_or_else(|err| panic!("{curve:?} from {from:?}: {err}")),
            );
            assert_eq!(message.body["text"], "hola");
            assert!(encrypted);
            assert_eq!(authenticated, from.is_some(), "{curve:?}");
        }
    }

    // A signature.
    let (alice, bob) = (
        Party::new(Curve::X25519, None),
        Party::new(Curve::X25519, None),
    );
    let (jws, _) = Message::new(TYPE, json!({"text": "firmado"}))
        .from(&alice.did)
        .to([bob.did.as_str()])
        .pack_signed(&alice.signing_kid(), &LocalResolver::new(), &alice.ours)
        .await
        .unwrap();
    let verifying: [u8; 32] = alice
        .signing
        .public_key()
        .to_bytes()
        .as_slice()
        .try_into()
        .unwrap();
    let (message, _, _) =
        opened(their_unpack::unpack(&jws, None, None, None, Some(&verifying)).unwrap());
    assert_eq!(message.body["text"], "firmado");
}

#[tokio::test]
async fn affinidi_envelopes_open_with_almena() {
    for curve in AGREEMENT {
        let (alice, bob) = (Party::new(curve, None), Party::new(curve, None));
        let message = TheirMessage::new(TYPE, json!({"text": "hola"}))
            .from(alice.did.clone())
            .to(vec![bob.did.clone()]);
        let bob_key = bob.their_public();
        let recipients = [(bob.agreement_kid(), &bob_key)];
        let recipients: Vec<(&str, &PublicKeyAgreement)> =
            recipients.iter().map(|(k, p)| (k.as_str(), *p)).collect();

        let anon = pack::pack_encrypted_anoncrypt(&message, &recipients).unwrap();
        let (opened, meta) = unpack(&anon, &LocalResolver::new(), &bob.ours)
            .await
            .unwrap_or_else(|err| panic!("anoncrypt {curve:?}: {err}"));
        assert_eq!(opened.body["text"], "hola");
        assert!(meta.encrypted && !meta.authenticated);

        let auth = pack::pack_encrypted_authcrypt(
            &message,
            &alice.agreement_kid(),
            &alice.their_private(),
            &recipients,
        )
        .unwrap();
        let (opened, meta) = unpack(&auth, &LocalResolver::new(), &bob.ours)
            .await
            .unwrap_or_else(|err| panic!("authcrypt {curve:?}: {err}"));
        assert_eq!(opened.from.as_deref(), Some(alice.did.as_str()));
        assert!(meta.authenticated, "{curve:?}");
        assert_eq!(
            meta.encrypted_from_kid.as_deref(),
            Some(alice.agreement_kid().as_str())
        );
    }

    // Signatures on the three curves both libraries sign with.
    for curve in [Curve::Ed25519, Curve::P256, Curve::Secp256k1] {
        let key = SecretKey::generate(curve).unwrap();
        let did = format!("did:example:signer-{}", curve.jwk_crv().to_lowercase());
        let kid = format!("{did}#sign");
        let doc = DidDocument::from_json(&json!({
            "id": did,
            "verificationMethod": [{
                "id": kid,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": serde_json::to_value(key.public_key().to_jwk()).unwrap(),
            }],
            "authentication": [kid],
        }))
        .unwrap();
        let private = seed(&key);
        let signer = match curve {
            Curve::Ed25519 => JwsSigner::Ed25519 {
                kid: &kid,
                private: &private,
            },
            Curve::P256 => JwsSigner::P256 {
                kid: &kid,
                private: &private,
            },
            _ => JwsSigner::Secp256k1 {
                kid: &kid,
                private: &private,
            },
        };
        let message = TheirMessage::new(TYPE, json!({"text": "firmado"})).from(did.clone());
        let jws = pack::pack_signed_multi(&message, &[signer]).unwrap();
        let (opened, meta) = unpack(&jws, &StaticResolver::new([doc]), &InMemorySecrets::new())
            .await
            .unwrap_or_else(|err| panic!("signature {curve:?}: {err}"));
        assert_eq!(opened.body["text"], "firmado");
        assert!(meta.non_repudiation);
        assert_eq!(meta.sign_from.as_deref(), Some(kid.as_str()));
    }
}

// ---- a mediation run ----

const LIMITS: Limits = Limits {
    max_message_bytes: 64 * 1024,
    queue: QueueLimits {
        ttl_secs: 3600,
        max_messages: 10,
        max_bytes: 1024 * 1024,
    },
    max_recipient_dids: 3,
    push_min_interval_secs: 60,
    push_ring_interval_secs: 5,
    recipient_proof: true,
    mediation_ttl_secs: 0,
};

/// The mediator's key agreement key on `curve`, as a kid and Affinidi key.
fn mediator_key(mediator: &Mediator, curve: Curve) -> (String, PublicKeyAgreement) {
    let method = mediator
        .identity()
        .document
        .key_agreement_methods()
        .find(|m| m.key.curve() == curve)
        .unwrap();
    (method.id.clone(), their_public(&method.key))
}

/// Bob, as an Affinidi wallet: authcrypts `type_`/`body` to the mediator with
/// `return_route: "all"`, and opens the reply.
async fn request(
    mediator: &Mediator,
    bob: &Party,
    curve: Curve,
    type_: &str,
    body: Value,
) -> TheirMessage {
    let (mediator_kid, mediator_public) = mediator_key(mediator, curve);
    let mut message = TheirMessage::new(type_, body)
        .from(bob.did.clone())
        .to(vec![mediator.identity().did.clone()]);
    message.extra.insert("return_route".into(), json!("all"));
    let packed = pack::pack_encrypted_authcrypt(
        &message,
        &bob.agreement_kid(),
        &bob.their_private(),
        &[(&mediator_kid, &mediator_public)],
    )
    .unwrap();
    let reply = match mediator.receive(&packed, None).await {
        Ok(Outcome::Reply(reply)) => reply,
        other => panic!("{type_}: expected a reply, got {other:?}"),
    };
    let (reply, authenticated, _) = opened(
        their_unpack::unpack(
            &reply,
            Some(&bob.agreement_kid()),
            Some(&bob.their_private()),
            Some(&mediator_public),
            None,
        )
        .unwrap_or_else(|err| panic!("{type_}: reply did not open: {err}")),
    );
    assert!(authenticated, "{type_}: reply not authcrypted");
    assert_eq!(
        reply.thid.as_deref(),
        Some(message.id.as_str()),
        "{type_}: reply not in the request's thread"
    );
    reply
}

#[tokio::test]
async fn a_mediation_run_with_affinidi_wallets() {
    for curve in [Curve::X25519, Curve::P384] {
        let mediator = Mediator::new(
            Identity::ephemeral("https://mediator.example.com").unwrap(),
            Arc::new(MemoryStore::new()),
            LIMITS,
            None,
        );
        let mediator_did = mediator.identity().did.clone();
        let bob = Party::new(curve, Some(&mediator_did));
        let alice = Party::new(curve, None);

        let pong = request(
            &mediator,
            &bob,
            curve,
            "https://didcomm.org/trust-ping/2.0/ping",
            json!({"response_requested": true}),
        )
        .await;
        assert_eq!(pong.typ, "https://didcomm.org/trust-ping/2.0/ping-response");

        let grant = request(
            &mediator,
            &bob,
            curve,
            "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
            json!({}),
        )
        .await;
        assert_eq!(grant.body["routing_did"], json!([mediator_did]));

        let update = request(
            &mediator,
            &bob,
            curve,
            "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
            json!({"updates": [{"recipient_did": bob.did, "action": "add"}]}),
        )
        .await;
        assert_eq!(update.body["updated"][0]["result"], "success");

        // Alice authcrypts to Bob, wraps it in a forward and anoncrypts
        // that to the mediator — all with Affinidi's library.
        let hello = TheirMessage::new(TYPE, json!({"text": "hola Bob"}))
            .from(alice.did.clone())
            .to(vec![bob.did.clone()]);
        let bob_public = bob.their_public();
        let for_bob = pack::pack_encrypted_authcrypt(
            &hello,
            &alice.agreement_kid(),
            &alice.their_private(),
            &[(&bob.agreement_kid(), &bob_public)],
        )
        .unwrap();
        let wrapped = forward::wrap_in_forward(&bob.did, &for_bob)
            .unwrap()
            .to(vec![mediator_did.clone()]);
        let (mediator_kid, mediator_public) = mediator_key(&mediator, curve);
        let to_mediator =
            pack::pack_encrypted_anoncrypt(&wrapped, &[(&mediator_kid, &mediator_public)]).unwrap();
        assert_eq!(
            mediator.receive(&to_mediator, None).await.unwrap(),
            Outcome::Accepted,
            "{curve:?}: forward"
        );

        let status = request(
            &mediator,
            &bob,
            curve,
            "https://didcomm.org/messagepickup/3.0/status-request",
            json!({}),
        )
        .await;
        assert_eq!(status.body["message_count"], 1, "{curve:?}");

        let delivery = request(
            &mediator,
            &bob,
            curve,
            "https://didcomm.org/messagepickup/3.0/delivery-request",
            json!({"limit": 10}),
        )
        .await;
        assert_eq!(
            delivery.typ,
            "https://didcomm.org/messagepickup/3.0/delivery"
        );
        let attachment = serde_json::to_value(&delivery.attachments.unwrap()[0]).unwrap();
        let queued = String::from_utf8(
            almena_didcomm::b64::decode(attachment["data"]["base64"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let (received, authenticated, _) = opened(
            their_unpack::unpack(
                &queued,
                Some(&bob.agreement_kid()),
                Some(&bob.their_private()),
                Some(&alice.their_public()),
                None,
            )
            .unwrap(),
        );
        assert_eq!(received.body["text"], "hola Bob");
        assert!(authenticated);

        let after = request(
            &mediator,
            &bob,
            curve,
            "https://didcomm.org/messagepickup/3.0/messages-received",
            json!({"message_id_list": [attachment["id"]]}),
        )
        .await;
        assert_eq!(after.body["message_count"], 0, "{curve:?}");
    }
}
