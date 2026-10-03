//! Round trips between two parties with `did:peer:2` identities, and the
//! checks that must reject inconsistent envelopes.

#![expect(clippy::unwrap_used, reason = "tests")]

use almena_didcomm::crypto::jwe::{Jwe, Recipient, Sender};
use almena_didcomm::crypto::jws::Jws;
use almena_didcomm::did::key::did_key;
use almena_didcomm::did::peer::{Purpose, peer2};
use almena_didcomm::{
    ContentEncryption, Curve, DidResolver, Error, FromPrior, InMemorySecrets, LocalResolver,
    Message, PackOptions, SecretKey, URGENCY, Urgency, route_with, unpack,
};
use serde_json::json;

struct Party {
    did: String,
    secrets: InMemorySecrets,
    signing: SecretKey,
    agreement: SecretKey,
}

impl Party {
    fn new(curve: Curve) -> Self {
        Self::with_services(curve, &[])
    }

    fn with_services(curve: Curve, services: &[serde_json::Value]) -> Self {
        let signing = SecretKey::generate(Curve::Ed25519).unwrap();
        let agreement = SecretKey::generate(curve).unwrap();
        let did = peer2(
            &[
                (Purpose::Verification, &signing.public_key()),
                (Purpose::Encryption, &agreement.public_key()),
            ],
            services,
        )
        .unwrap();
        let mut secrets = InMemorySecrets::new();
        secrets.insert(format!("{did}#key-1"), signing.clone());
        secrets.insert(format!("{did}#key-2"), agreement.clone());
        Self {
            did,
            secrets,
            signing,
            agreement,
        }
    }

    fn signing_kid(&self) -> String {
        format!("{}#key-1", self.did)
    }

    fn agreement_kid(&self) -> String {
        format!("{}#key-2", self.did)
    }
}

fn ping(from: &Party, to: &Party) -> Message {
    Message::new(
        "https://didcomm.org/trust-ping/2.0/ping",
        json!({"response_requested": true}),
    )
    .from(&from.did)
    .to([&to.did])
}

#[tokio::test]
async fn authcrypt_round_trip_on_every_curve() {
    let resolver = LocalResolver::new();
    for curve in [Curve::X25519, Curve::P256, Curve::P384, Curve::P521] {
        let (alice, bob) = (Party::new(curve), Party::new(curve));
        let sent = ping(&alice, &bob);
        let packed = sent
            .pack_encrypted(
                &bob.did,
                Some(&alice.did),
                None,
                &resolver,
                &alice.secrets,
                PackOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            packed.from_kid.as_deref(),
            Some(alice.agreement_kid().as_str())
        );

        let (received, meta) = unpack(&packed.message, &resolver, &bob.secrets)
            .await
            .unwrap();
        assert_eq!(received.id, sent.id);
        assert_eq!(received.body, sent.body);
        assert!(meta.authenticated && !meta.non_repudiation);
        assert_eq!(
            meta.decrypted_by_kid.as_deref(),
            Some(bob.agreement_kid().as_str())
        );
    }
}

#[tokio::test]
async fn anoncrypt_round_trip_with_every_content_encryption() {
    let resolver = LocalResolver::new();
    let (alice, bob) = (Party::new(Curve::X25519), Party::new(Curve::X25519));
    for enc in [
        ContentEncryption::A256CbcHs512,
        ContentEncryption::A256Gcm,
        ContentEncryption::Xc20p,
    ] {
        let options = PackOptions {
            anoncrypt_enc: enc,
            ..PackOptions::default()
        };
        let packed = ping(&alice, &bob)
            .pack_encrypted(&bob.did, None, None, &resolver, &alice.secrets, options)
            .await
            .unwrap();
        let (_, meta) = unpack(&packed.message, &resolver, &bob.secrets)
            .await
            .unwrap();
        assert!(meta.anonymous_sender);
        assert_eq!(meta.enc_alg_anon, Some(enc));
    }
}

#[tokio::test]
async fn protected_sender_signed_round_trip() {
    let resolver = LocalResolver::new();
    let (alice, bob) = (Party::new(Curve::X25519), Party::new(Curve::X25519));
    let options = PackOptions {
        protect_sender: true,
        ..PackOptions::default()
    };
    let packed = ping(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            Some(&alice.did),
            &resolver,
            &alice.secrets,
            options,
        )
        .await
        .unwrap();
    assert!(
        !packed.message.contains(&alice.did),
        "the outer envelope hides skid"
    );

    let (_, meta) = unpack(&packed.message, &resolver, &bob.secrets)
        .await
        .unwrap();
    assert!(meta.authenticated && meta.non_repudiation && meta.enc_alg_anon.is_some());
    assert_eq!(
        meta.sign_from.as_deref(),
        Some(alice.signing_kid().as_str())
    );
}

#[tokio::test]
async fn signed_and_plaintext_round_trips() {
    let resolver = LocalResolver::new();
    let (alice, bob) = (Party::new(Curve::X25519), Party::new(Curve::X25519));
    let (jws, kid) = ping(&alice, &bob)
        .pack_signed(&alice.did, &resolver, &alice.secrets)
        .await
        .unwrap();
    assert_eq!(kid, alice.signing_kid());
    let (_, meta) = unpack(&jws, &resolver, &bob.secrets).await.unwrap();
    assert!(meta.non_repudiation && !meta.encrypted);

    let plain = ping(&alice, &bob).pack_plaintext().unwrap();
    let (_, meta) = unpack(&plain, &resolver, &bob.secrets).await.unwrap();
    assert_eq!(meta, Default::default());
}

#[tokio::test]
async fn did_key_parties_interoperate() {
    let resolver = LocalResolver::new();
    let alice_key = SecretKey::generate(Curve::P256).unwrap();
    let bob_key = SecretKey::generate(Curve::P256).unwrap();
    let (alice, bob) = (
        did_key(&alice_key.public_key()),
        did_key(&bob_key.public_key()),
    );
    let kid = |did: &str| format!("{did}#{}", did.trim_start_matches("did:key:"));
    let mut alice_secrets = InMemorySecrets::new();
    alice_secrets.insert(kid(&alice), alice_key);
    let mut bob_secrets = InMemorySecrets::new();
    bob_secrets.insert(kid(&bob), bob_key);

    let packed = Message::new("t", json!({}))
        .from(&alice)
        .to([&bob])
        .pack_encrypted(
            &bob,
            Some(&alice),
            Some(&alice),
            &resolver,
            &alice_secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();
    let (_, meta) = unpack(&packed.message, &resolver, &bob_secrets)
        .await
        .unwrap();
    assert!(meta.authenticated && meta.non_repudiation);
}

#[tokio::test]
async fn did_rotation_is_verified() {
    let resolver = LocalResolver::new();
    let (old, new, bob) = (
        Party::new(Curve::X25519),
        Party::new(Curve::X25519),
        Party::new(Curve::X25519),
    );
    let from_prior = FromPrior::new(&old.did, &new.did)
        .pack(None, &resolver, &old.secrets)
        .await
        .unwrap();
    let mut message = ping(&new, &bob);
    message.from_prior = Some(from_prior);
    let packed = message
        .pack_encrypted(
            &bob.did,
            Some(&new.did),
            None,
            &resolver,
            &new.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();

    let (_, meta) = unpack(&packed.message, &resolver, &bob.secrets)
        .await
        .unwrap();
    assert_eq!(meta.from_prior.unwrap().iss, old.did);
    assert_eq!(meta.from_prior_issuer_kid, Some(old.signing_kid()));
}

#[tokio::test]
async fn rotation_signed_by_someone_else_is_rejected() {
    let resolver = LocalResolver::new();
    let (old, new, bob) = (
        Party::new(Curve::X25519),
        Party::new(Curve::X25519),
        Party::new(Curve::X25519),
    );
    // `new` claims to rotate from `old`, signing with its own key under old's kid.
    let claims = serde_json::to_vec(&FromPrior::new(&old.did, &new.did)).unwrap();
    let header = json!({"typ": "JWT", "alg": "EdDSA", "kid": old.signing_kid()});
    let b64 = |b: &[u8]| {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    };
    let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(&claims));
    let forged = format!(
        "{input}.{}",
        b64(&new.signing.sign(input.as_bytes()).unwrap())
    );

    let mut message = ping(&new, &bob);
    message.from_prior = Some(forged);
    let packed = message
        .pack_encrypted(
            &bob.did,
            Some(&new.did),
            None,
            &resolver,
            &new.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();
    let err = unpack(&packed.message, &resolver, &bob.secrets)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Crypto(_)), "{err:?}");
}

/// Authcrypt by Alice of a plaintext that claims to come from Carol.
#[tokio::test]
async fn from_that_is_not_the_authcrypt_sender_is_rejected() {
    let resolver = LocalResolver::new();
    let (alice, bob, carol) = (
        Party::new(Curve::X25519),
        Party::new(Curve::X25519),
        Party::new(Curve::X25519),
    );
    let plaintext = ping(&carol, &bob).to_plaintext_json().unwrap();
    let bob_key = bob.agreement.public_key();
    let jwe = Jwe::authcrypt(
        plaintext.as_bytes(),
        &Sender {
            kid: &alice.agreement_kid(),
            key: &alice.agreement,
        },
        &[Recipient {
            kid: &bob.agreement_kid(),
            key: &bob_key,
        }],
    )
    .unwrap();
    let err = unpack(&jwe.to_json().unwrap(), &resolver, &bob.secrets)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Inconsistent(_)), "{err:?}");
}

/// A message addressed to Carol, encrypted to Bob.
#[tokio::test]
async fn to_that_does_not_contain_the_recipient_is_rejected() {
    let resolver = LocalResolver::new();
    let (alice, bob, carol) = (
        Party::new(Curve::X25519),
        Party::new(Curve::X25519),
        Party::new(Curve::X25519),
    );
    let plaintext = ping(&alice, &carol).to_plaintext_json().unwrap();
    let bob_key = bob.agreement.public_key();
    let jwe = Jwe::anoncrypt(
        plaintext.as_bytes(),
        &[Recipient {
            kid: &bob.agreement_kid(),
            key: &bob_key,
        }],
        ContentEncryption::A256Gcm,
    )
    .unwrap();
    let err = unpack(&jwe.to_json().unwrap(), &resolver, &bob.secrets)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Inconsistent(_)), "{err:?}");
}

/// Signed with Alice's key-agreement DID URL listed as the signer: not an
/// authentication key, so the signature must not count.
#[tokio::test]
async fn signature_by_a_non_authentication_key_is_rejected() {
    let resolver = LocalResolver::new();
    let (alice, bob) = (Party::new(Curve::P256), Party::new(Curve::P256));
    let plaintext = ping(&alice, &bob).to_plaintext_json().unwrap();
    let jws = Jws::sign(
        plaintext.as_bytes(),
        &alice.agreement_kid(),
        &alice.agreement,
    )
    .unwrap();
    let err = unpack(&jws.to_json().unwrap(), &resolver, &bob.secrets)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::DidUrlNotFound(_)), "{err:?}");
}

#[tokio::test]
async fn pack_refuses_a_sender_other_than_from() {
    let resolver = LocalResolver::new();
    let (alice, bob) = (Party::new(Curve::X25519), Party::new(Curve::X25519));
    let err = ping(&bob, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &resolver,
            &alice.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Inconsistent(_)));
}

#[tokio::test]
async fn authcrypt_needs_a_shared_curve() {
    let resolver = LocalResolver::new();
    let (alice, bob) = (Party::new(Curve::X25519), Party::new(Curve::P384));
    let err = ping(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &resolver,
            &alice.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoCompatibleKeys(_)));
    // The resolver is still usable afterwards.
    resolver.resolve(&bob.did).await.unwrap();
}

#[tokio::test]
async fn tampered_ciphertext_is_rejected() {
    let resolver = LocalResolver::new();
    let (alice, bob) = (Party::new(Curve::X25519), Party::new(Curve::X25519));
    let packed = ping(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &resolver,
            &alice.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();
    let mut jwe: serde_json::Value = serde_json::from_str(&packed.message).unwrap();
    let ciphertext = jwe["ciphertext"].as_str().unwrap().to_owned();
    let flipped = if ciphertext.starts_with('A') {
        "B"
    } else {
        "A"
    };
    jwe["ciphertext"] = json!(format!("{flipped}{}", &ciphertext[1..]));
    let err = unpack(&jwe.to_string(), &resolver, &bob.secrets)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Crypto(_)), "{err:?}");
}

fn didcomm_service(uri: &str, routing_keys: &[&str]) -> serde_json::Value {
    json!({"type": "DIDCommMessaging", "serviceEndpoint": {"uri": uri, "accept": ["didcomm/v2"], "routingKeys": routing_keys}})
}

/// Opens one `forward` layer as `mediator`; returns `next` and the payload.
async fn open_forward(
    mediator: &Party,
    packed: &str,
    resolver: &LocalResolver,
) -> (String, String) {
    let (forward, meta) = unpack(packed, resolver, &mediator.secrets).await.unwrap();
    assert_eq!(forward.type_, almena_didcomm::FORWARD);
    assert!(meta.anonymous_sender, "forward envelopes are anoncrypted");
    let next = forward.body["next"].as_str().unwrap().to_owned();
    let payload = forward.attachments.unwrap()[0]
        .data
        .json
        .clone()
        .unwrap()
        .to_string();
    (next, payload)
}

#[tokio::test]
async fn messages_to_a_mediated_did_are_wrapped_in_a_forward() {
    let resolver = LocalResolver::new();
    let mediator = Party::with_services(
        Curve::X25519,
        &[didcomm_service("https://mediator.example/didcomm", &[])],
    );
    let bob = Party::with_services(Curve::X25519, &[didcomm_service(&mediator.did, &[])]);
    let alice = Party::new(Curve::X25519);

    let packed = ping(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &resolver,
            &alice.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();
    assert!(packed.forwarded);
    assert_eq!(
        packed.service_uri.as_deref(),
        Some("https://mediator.example/didcomm")
    );

    let (next, payload) = open_forward(&mediator, &packed.message, &resolver).await;
    assert_eq!(next, bob.did);
    let (message, meta) = unpack(&payload, &resolver, &bob.secrets).await.unwrap();
    assert!(meta.authenticated);
    assert_eq!(message.from.as_deref(), Some(alice.did.as_str()));
}

#[tokio::test]
async fn routing_keys_are_wrapped_last_to_first() {
    let resolver = LocalResolver::new();
    let outer = Party::new(Curve::X25519);
    let inner = Party::new(Curve::P384);
    let bob = Party::with_services(
        Curve::X25519,
        &[didcomm_service(
            "https://outer.example/didcomm",
            &[&outer.agreement_kid(), &inner.did],
        )],
    );
    let alice = Party::new(Curve::X25519);

    let packed = ping(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            None,
            None,
            &resolver,
            &alice.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        packed.service_uri.as_deref(),
        Some("https://outer.example/didcomm")
    );

    let (next, payload) = open_forward(&outer, &packed.message, &resolver).await;
    assert_eq!(next, inner.did);
    let (next, payload) = open_forward(&inner, &payload, &resolver).await;
    assert_eq!(next, bob.did);
    unpack(&payload, &resolver, &bob.secrets).await.unwrap();
}

/// The urgency of each `forward` layer from the outside in, opened by
/// `hops` in turn, and the payload under the last one.
async fn urgencies(
    hops: &[&Party],
    mut packed: String,
    resolver: &LocalResolver,
) -> (Vec<Option<serde_json::Value>>, String) {
    let mut found = Vec::new();
    for hop in hops {
        let (forward, _) = unpack(&packed, resolver, &hop.secrets).await.unwrap();
        found.push(forward.extra_headers.get(URGENCY).cloned());
        packed = forward.attachments.unwrap()[0]
            .data
            .json
            .clone()
            .unwrap()
            .to_string();
    }
    (found, packed)
}

#[tokio::test]
async fn every_forward_of_a_call_carries_its_urgency() {
    let resolver = LocalResolver::new();
    let outer = Party::new(Curve::X25519);
    let inner = Party::new(Curve::X25519);
    let bob = Party::with_services(
        Curve::X25519,
        &[didcomm_service(
            "https://outer.example/didcomm",
            &[&outer.did, &inner.did],
        )],
    );
    let alice = Party::new(Curve::X25519);

    let options = PackOptions {
        urgency: Urgency::Call,
        ..PackOptions::default()
    };
    let packed = ping(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &resolver,
            &alice.secrets,
            options,
        )
        .await
        .unwrap();
    let (found, payload) = urgencies(&[&outer, &inner], packed.message, &resolver).await;
    assert_eq!(found, [Some(json!("call")), Some(json!("call"))]);
    // The message itself says nothing about it.
    let (message, _) = unpack(&payload, &resolver, &bob.secrets).await.unwrap();
    assert!(!message.extra_headers.contains_key(URGENCY));

    // A mediator relaying the payload keeps it the same way.
    let relayed = route_with(
        payload,
        &bob.did,
        &resolver,
        ContentEncryption::A256CbcHs512,
        Urgency::Call,
    )
    .await
    .unwrap();
    let (found, _) = urgencies(&[&outer, &inner], relayed.message, &resolver).await;
    assert_eq!(found, [Some(json!("call")), Some(json!("call"))]);
}

#[tokio::test]
async fn ordinary_forwards_carry_no_urgency() {
    let resolver = LocalResolver::new();
    let mediator = Party::with_services(
        Curve::X25519,
        &[didcomm_service("https://mediator.example/didcomm", &[])],
    );
    let bob = Party::with_services(Curve::X25519, &[didcomm_service(&mediator.did, &[])]);
    let alice = Party::new(Curve::X25519);
    let packed = ping(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &resolver,
            &alice.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();
    let (forward, _) = unpack(&packed.message, &resolver, &mediator.secrets)
        .await
        .unwrap();
    assert!(!forward.extra_headers.contains_key(URGENCY));
    assert_eq!(Urgency::of(&forward), Urgency::Normal);
}

#[tokio::test]
async fn forward_can_be_turned_off() {
    let resolver = LocalResolver::new();
    let mediator =
        Party::with_services(Curve::X25519, &[didcomm_service("https://m.example", &[])]);
    let bob = Party::with_services(Curve::X25519, &[didcomm_service(&mediator.did, &[])]);
    let alice = Party::new(Curve::X25519);
    let options = PackOptions {
        forward: false,
        ..PackOptions::default()
    };
    let packed = ping(&alice, &bob)
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &resolver,
            &alice.secrets,
            options,
        )
        .await
        .unwrap();
    assert!(!packed.forwarded);
    unpack(&packed.message, &resolver, &bob.secrets)
        .await
        .unwrap();
}
