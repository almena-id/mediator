//! `almena-didcomm` against didcomm-rust (SICPA, crate `didcomm` 0.4), both
//! ways: what one packs, the other must unpack, with the same metadata.
//!
//! Covered where both libraries support it: key agreement on X25519 and
//! P-256; anoncrypt with A256CBC-HS512, A256GCM and XC20P; authcrypt, with
//! and without sender protection; signatures with Ed25519, P-256 and
//! secp256k1, alone and inside encryption; plaintext; and a `forward`
//! through a mediator. (didcomm-rust has no P-384 or P-521 key agreement.)

use almena_didcomm::did::DidDocument;
use almena_didcomm::{
    Attachment, ContentEncryption, Curve, InMemorySecrets, Message, PackOptions, SecretKey,
    StaticResolver, unpack,
};
use didcomm::algorithms::AnonCryptAlg;
use didcomm::did::DIDDoc;
use didcomm::did::resolvers::ExampleDIDResolver;
use didcomm::secrets::Secret;
use didcomm::secrets::resolvers::ExampleSecretsResolver;
use didcomm::{PackEncryptedOptions, UnpackOptions};
use serde_json::{Value, json};

const TYPE: &str = "https://example.com/protocols/interop/1.0/hello";
const SIGNING: [(Curve, &str); 3] = [
    (Curve::Ed25519, "sign-ed25519"),
    (Curve::P256, "sign-p256"),
    (Curve::Secp256k1, "sign-k256"),
];

/// A DID with one key agreement key and three signing keys, known to both
/// libraries.
struct Party {
    did: String,
    doc: Value,
    ours: InMemorySecrets,
    theirs: Vec<Secret>,
}

impl Party {
    fn new(name: &str, agreement: Curve) -> Self {
        Self::with_service(name, agreement, None)
    }

    /// `mediator`: the DID this party receives through (a `DIDCommMessaging`
    /// service whose `uri` is the mediator's DID).
    fn with_service(name: &str, agreement: Curve, mediator: Option<&str>) -> Self {
        let did = format!("did:example:{name}");
        let mut ours = InMemorySecrets::new();
        let mut theirs = Vec::new();
        let mut methods = Vec::new();
        let mut add = |fragment: &str, curve: Curve| {
            let kid = format!("{did}#{fragment}");
            let key = SecretKey::generate(curve).unwrap();
            methods.push(json!({
                "id": kid,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": serde_json::to_value(key.public_key().to_jwk()).unwrap(),
            }));
            theirs.push(
                serde_json::from_value(json!({
                    "id": kid,
                    "type": "JsonWebKey2020",
                    "privateKeyJwk": serde_json::to_value(key.to_jwk()).unwrap(),
                }))
                .unwrap(),
            );
            ours.insert(kid.clone(), key);
            kid
        };
        let agreement_kid = add("agreement", agreement);
        let signing: Vec<String> = SIGNING
            .iter()
            .map(|(curve, fragment)| add(fragment, *curve))
            .collect();
        let service: Vec<Value> = mediator
            .map(|m| {
                json!({
                    "id": format!("{did}#didcomm"),
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": {"uri": m, "accept": ["didcomm/v2"], "routingKeys": []},
                })
            })
            .into_iter()
            .collect();
        let doc = json!({
            "id": did,
            "verificationMethod": methods,
            "keyAgreement": [agreement_kid],
            "authentication": signing,
            "service": service,
        });
        Self {
            did,
            doc,
            ours,
            theirs,
        }
    }

    fn kid(&self, fragment: &str) -> String {
        format!("{}#{fragment}", self.did)
    }

    fn their_secrets(&self) -> ExampleSecretsResolver {
        ExampleSecretsResolver::new(self.theirs.clone())
    }
}

fn our_resolver(parties: &[&Party]) -> StaticResolver {
    StaticResolver::new(
        parties
            .iter()
            .map(|p| DidDocument::from_json(&p.doc).unwrap()),
    )
}

fn their_resolver(parties: &[&Party]) -> ExampleDIDResolver {
    ExampleDIDResolver::new(
        parties
            .iter()
            .map(|p| serde_json::from_value::<DIDDoc>(p.doc.clone()).unwrap())
            .collect(),
    )
}

fn our_message(from: &Party, to: &Party) -> Message {
    Message::new(TYPE, json!({"text": "hola"}))
        .from(&from.did)
        .to([to.did.as_str()])
}

fn their_message(from: &Party, to: &Party) -> didcomm::Message {
    didcomm::Message::build("1234567890".into(), TYPE.into(), json!({"text": "hola"}))
        .from(from.did.clone())
        .to(to.did.clone())
        .finalize()
}

fn their_options(anon: AnonCryptAlg, protect_sender: bool) -> PackEncryptedOptions {
    PackEncryptedOptions {
        forward: false,
        protect_sender,
        enc_alg_anon: anon,
        ..PackEncryptedOptions::default()
    }
}

fn our_options(anon: ContentEncryption, protect_sender: bool) -> PackOptions {
    PackOptions {
        forward: false,
        protect_sender,
        anoncrypt_enc: anon,
    }
}

const ENCRYPTIONS: [(ContentEncryption, AnonCryptAlg); 3] = [
    (
        ContentEncryption::A256CbcHs512,
        AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
    ),
    (
        ContentEncryption::A256Gcm,
        AnonCryptAlg::A256gcmEcdhEsA256kw,
    ),
    (ContentEncryption::Xc20p, AnonCryptAlg::Xc20pEcdhEsA256kw),
];
const AGREEMENT: [Curve; 2] = [Curve::X25519, Curve::P256];

// ---- almena → didcomm-rust ----

/// Packs with ours, unpacks with theirs.
async fn ours_to_theirs(
    alice: &Party,
    bob: &Party,
    from: Option<&str>,
    sign_by: Option<&str>,
    options: PackOptions,
) -> (didcomm::Message, didcomm::UnpackMetadata) {
    let packed = our_message(alice, bob)
        .pack_encrypted(
            &bob.did,
            from,
            sign_by,
            &our_resolver(&[alice, bob]),
            &alice.ours,
            options,
        )
        .await
        .unwrap();
    didcomm::Message::unpack(
        &packed.message,
        &their_resolver(&[alice, bob]),
        &bob.their_secrets(),
        &UnpackOptions::default(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn anoncrypt_from_almena() {
    for curve in AGREEMENT {
        for (ours, theirs) in ENCRYPTIONS {
            let (alice, bob) = (Party::new("alice", curve), Party::new("bob", curve));
            let (message, meta) =
                ours_to_theirs(&alice, &bob, None, None, our_options(ours, false)).await;
            assert_eq!(message.body["text"], "hola", "{curve:?} {ours:?}");
            assert!(meta.encrypted && meta.anonymous_sender && !meta.authenticated);
            assert_eq!(meta.enc_alg_anon, Some(theirs), "{curve:?} {ours:?}");
        }
    }
}

#[tokio::test]
async fn authcrypt_from_almena() {
    for curve in AGREEMENT {
        for protect_sender in [false, true] {
            let (alice, bob) = (Party::new("alice", curve), Party::new("bob", curve));
            let (message, meta) = ours_to_theirs(
                &alice,
                &bob,
                Some(&alice.did),
                None,
                our_options(ContentEncryption::A256CbcHs512, protect_sender),
            )
            .await;
            assert_eq!(message.from.as_deref(), Some(alice.did.as_str()));
            assert!(meta.authenticated && !meta.non_repudiation, "{curve:?}");
            assert_eq!(
                meta.encrypted_from_kid.as_deref(),
                Some(alice.kid("agreement").as_str())
            );
            assert_eq!(meta.anonymous_sender, protect_sender, "{curve:?}");
        }
    }
}

#[tokio::test]
async fn signed_and_encrypted_from_almena() {
    for (_, fragment) in SIGNING {
        let (alice, bob) = (
            Party::new("alice", Curve::X25519),
            Party::new("bob", Curve::X25519),
        );
        let (_, meta) = ours_to_theirs(
            &alice,
            &bob,
            Some(&alice.did),
            Some(&alice.kid(fragment)),
            our_options(ContentEncryption::A256CbcHs512, false),
        )
        .await;
        assert!(meta.non_repudiation, "{fragment}");
        assert_eq!(
            meta.sign_from.as_deref(),
            Some(alice.kid(fragment).as_str())
        );
    }
}

#[tokio::test]
async fn signed_and_plaintext_from_almena() {
    let (alice, bob) = (
        Party::new("alice", Curve::X25519),
        Party::new("bob", Curve::X25519),
    );
    for (_, fragment) in SIGNING {
        let (jws, _) = our_message(&alice, &bob)
            .pack_signed(
                &alice.kid(fragment),
                &our_resolver(&[&alice, &bob]),
                &alice.ours,
            )
            .await
            .unwrap();
        let (message, meta) = didcomm::Message::unpack(
            &jws,
            &their_resolver(&[&alice, &bob]),
            &bob.their_secrets(),
            &UnpackOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(message.body["text"], "hola");
        assert!(meta.non_repudiation && !meta.encrypted, "{fragment}");
    }

    let plaintext = our_message(&alice, &bob).pack_plaintext().unwrap();
    let (message, meta) = didcomm::Message::unpack(
        &plaintext,
        &their_resolver(&[&alice, &bob]),
        &bob.their_secrets(),
        &UnpackOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(message.body["text"], "hola");
    assert!(!meta.encrypted && !meta.non_repudiation);
}

// ---- didcomm-rust → almena ----

/// Packs with theirs, unpacks with ours.
async fn theirs_to_ours(
    alice: &Party,
    bob: &Party,
    from: Option<&str>,
    sign_by: Option<&str>,
    options: PackEncryptedOptions,
) -> (Message, almena_didcomm::UnpackMetadata) {
    let (packed, _) = their_message(alice, bob)
        .pack_encrypted(
            &bob.did,
            from,
            sign_by,
            &their_resolver(&[alice, bob]),
            &alice.their_secrets(),
            &options,
        )
        .await
        .unwrap();
    unpack(&packed, &our_resolver(&[alice, bob]), &bob.ours)
        .await
        .unwrap()
}

#[tokio::test]
async fn anoncrypt_from_didcomm_rust() {
    for curve in AGREEMENT {
        for (ours, theirs) in ENCRYPTIONS {
            let (alice, bob) = (Party::new("alice", curve), Party::new("bob", curve));
            let (message, meta) =
                theirs_to_ours(&alice, &bob, None, None, their_options(theirs, false)).await;
            assert_eq!(message.body["text"], "hola", "{curve:?} {ours:?}");
            assert!(meta.encrypted && meta.anonymous_sender && !meta.authenticated);
            assert_eq!(meta.enc_alg_anon, Some(ours), "{curve:?} {ours:?}");
        }
    }
}

#[tokio::test]
async fn authcrypt_from_didcomm_rust() {
    for curve in AGREEMENT {
        for protect_sender in [false, true] {
            let (alice, bob) = (Party::new("alice", curve), Party::new("bob", curve));
            let (message, meta) = theirs_to_ours(
                &alice,
                &bob,
                Some(&alice.did),
                None,
                their_options(AnonCryptAlg::A256cbcHs512EcdhEsA256kw, protect_sender),
            )
            .await;
            assert_eq!(message.from.as_deref(), Some(alice.did.as_str()));
            assert!(meta.authenticated && !meta.non_repudiation, "{curve:?}");
            assert_eq!(
                meta.encrypted_from_kid.as_deref(),
                Some(alice.kid("agreement").as_str())
            );
            // Sender protection is an anoncrypt layer around the authcrypt
            // one. (`anonymous_sender` differs by design: didcomm-rust sets it
            // when the sender is hidden, almena only without authcrypt.)
            assert_eq!(meta.enc_alg_anon.is_some(), protect_sender, "{curve:?}");
        }
    }
}

#[tokio::test]
async fn signed_and_encrypted_from_didcomm_rust() {
    for (_, fragment) in SIGNING {
        let (alice, bob) = (
            Party::new("alice", Curve::X25519),
            Party::new("bob", Curve::X25519),
        );
        let (_, meta) = theirs_to_ours(
            &alice,
            &bob,
            Some(&alice.did),
            Some(&alice.kid(fragment)),
            their_options(AnonCryptAlg::A256cbcHs512EcdhEsA256kw, false),
        )
        .await;
        assert!(meta.non_repudiation, "{fragment}");
        assert_eq!(
            meta.sign_from.as_deref(),
            Some(alice.kid(fragment).as_str())
        );
    }
}

#[tokio::test]
async fn signed_and_plaintext_from_didcomm_rust() {
    let (alice, bob) = (
        Party::new("alice", Curve::X25519),
        Party::new("bob", Curve::X25519),
    );
    for (_, fragment) in SIGNING {
        let (jws, _) = their_message(&alice, &bob)
            .pack_signed(
                &alice.kid(fragment),
                &their_resolver(&[&alice, &bob]),
                &alice.their_secrets(),
            )
            .await
            .unwrap();
        let (message, meta) = unpack(&jws, &our_resolver(&[&alice, &bob]), &bob.ours)
            .await
            .unwrap();
        assert_eq!(message.body["text"], "hola");
        assert!(meta.non_repudiation && !meta.encrypted, "{fragment}");
    }

    let plaintext = their_message(&alice, &bob)
        .pack_plaintext(&their_resolver(&[&alice, &bob]))
        .await
        .unwrap();
    let (message, meta) = unpack(&plaintext, &our_resolver(&[&alice, &bob]), &bob.ours)
        .await
        .unwrap();
    assert_eq!(message.body["text"], "hola");
    assert!(!meta.encrypted && !meta.non_repudiation);
}

// ---- forward through a mediator ----

/// A mediator reachable over HTTPS: both libraries need its service URI.
fn mediator() -> Party {
    let mut mediator = Party::new("mediator", Curve::X25519);
    mediator.doc["service"] = json!([{
        "id": "did:example:mediator#didcomm",
        "type": "DIDCommMessaging",
        "serviceEndpoint": {"uri": "https://mediator.example/didcomm", "accept": ["didcomm/v2"], "routingKeys": []},
    }]);
    mediator
}

/// The payload of a `forward`, as a mediator queues it.
fn forwarded_payload(attachment: &Value) -> String {
    let data = &attachment["data"];
    if let Some(json) = data.get("json") {
        return json.to_string();
    }
    let base64 = data["base64"].as_str().unwrap();
    String::from_utf8(almena_didcomm::b64::decode(base64).unwrap()).unwrap()
}

#[tokio::test]
async fn forward_from_almena_through_a_didcomm_rust_mediator() {
    let mediator = mediator();
    let alice = Party::new("alice", Curve::X25519);
    let bob = Party::with_service("bob", Curve::X25519, Some(&mediator.did));
    let everyone = [&mediator, &alice, &bob];

    let packed = our_message(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &our_resolver(&everyone),
            &alice.ours,
            PackOptions::default(),
        )
        .await
        .unwrap();
    assert!(packed.forwarded);

    // The mediator opens the forward…
    let options = UnpackOptions {
        unwrap_re_wrapping_forward: false,
        ..UnpackOptions::default()
    };
    let (forward, _) = didcomm::Message::unpack(
        &packed.message,
        &their_resolver(&everyone),
        &mediator.their_secrets(),
        &options,
    )
    .await
    .unwrap();
    assert_eq!(forward.type_, almena_didcomm::FORWARD);
    assert_eq!(forward.body["next"], bob.did);
    let attachment = serde_json::to_value(&forward.attachments.unwrap()[0]).unwrap();

    // …and Bob opens what it carried.
    let (message, meta) = didcomm::Message::unpack(
        &forwarded_payload(&attachment),
        &their_resolver(&everyone),
        &bob.their_secrets(),
        &UnpackOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(message.body["text"], "hola");
    assert!(meta.authenticated);
}

#[tokio::test]
async fn forward_from_didcomm_rust_through_an_almena_mediator() {
    let mediator = mediator();
    let alice = Party::new("alice", Curve::X25519);
    let bob = Party::with_service("bob", Curve::X25519, Some(&mediator.did));
    let everyone = [&mediator, &alice, &bob];

    let (packed, meta) = their_message(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &their_resolver(&everyone),
            &alice.their_secrets(),
            &PackEncryptedOptions::default(),
        )
        .await
        .unwrap();
    assert!(meta.messaging_service.is_some());

    let (forward, _) = unpack(&packed, &our_resolver(&everyone), &mediator.ours)
        .await
        .unwrap();
    assert_eq!(forward.type_, almena_didcomm::FORWARD);
    assert_eq!(forward.body["next"], bob.did);
    let attachments: Vec<Attachment> = forward.attachments.unwrap();
    let attachment = serde_json::to_value(&attachments[0]).unwrap();

    let (message, meta) = unpack(
        &forwarded_payload(&attachment),
        &our_resolver(&everyone),
        &bob.ours,
    )
    .await
    .unwrap();
    assert_eq!(message.body["text"], "hola");
    assert!(meta.authenticated);
}
