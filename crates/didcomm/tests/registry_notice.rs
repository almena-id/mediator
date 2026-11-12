//! A notice the registry API (`../api`, `registry_api.didcomm`, Python) packed
//! for a holder, unpacked as the mediator and then the wallet unpack it: the
//! two implementations agree on the envelope byte for byte.

#![expect(clippy::unwrap_used, reason = "tests")]

use std::sync::Arc;

use almena_didcomm::did::ChainResolver;
use almena_didcomm::{
    DidDocument, DidResolver, InMemorySecrets, Jwk, LocalResolver, SecretKey, StaticResolver,
    unpack,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("registry/notice.json")).unwrap()
}

fn secrets(secret: &Value) -> InMemorySecrets {
    let mut jwk = secret.clone();
    let kid = jwk["kid"].as_str().unwrap().to_owned();
    jwk.as_object_mut().unwrap().remove("kid");
    let key = SecretKey::from_jwk(&serde_json::from_value::<Jwk>(jwk).unwrap()).unwrap();
    let mut secrets = InMemorySecrets::new();
    secrets.insert(kid, key);
    secrets
}

fn resolver(fixture: &Value) -> ChainResolver {
    let docs = ["mediator", "issuer"]
        .map(|who| DidDocument::from_json(&fixture[who]["document"]).unwrap());
    let local: Arc<dyn DidResolver> = Arc::new(LocalResolver::new());
    let known: Arc<dyn DidResolver> = Arc::new(StaticResolver::new(docs));
    ChainResolver::new(vec![local, known])
}

#[tokio::test]
async fn the_mediator_and_then_the_holder_open_a_registry_notice() {
    let fixture = fixture();
    let resolver = resolver(&fixture);

    // The mediator: an anonymous forward to the holder's DID.
    let envelope = fixture["envelope"].as_str().unwrap();
    let mediator = secrets(&fixture["mediator"]["secret"]);
    let (forward, meta) = unpack(envelope, &resolver, &mediator).await.unwrap();
    assert!(meta.anonymous_sender);
    assert_eq!(forward.type_, almena_didcomm::FORWARD);
    let holder_did = fixture["holder"]["did"].as_str().unwrap();
    assert_eq!(forward.body["next"], holder_did);

    // The holder: from the issuer, authenticated.
    let attachment = &forward.attachments.as_ref().unwrap()[0];
    let inner = serde_json::to_string(attachment.data.json.as_ref().unwrap()).unwrap();
    let holder = secrets(&fixture["holder"]["secret"]);
    let (message, meta) = unpack(&inner, &resolver, &holder).await.unwrap();
    assert!(meta.authenticated);
    let issuer = fixture["issuer"]["document"]["id"].as_str().unwrap();
    assert_eq!(message.from.as_deref(), Some(issuer));
    assert_eq!(message.to.as_deref(), Some(&[holder_did.to_owned()][..]));
    assert_eq!(
        message.type_,
        "https://almena.id/protocols/application/1.0/status"
    );
    assert_eq!(message.body, fixture["message"]["body"]);
    assert_eq!(
        message.thid,
        fixture["message"]["thid"].as_str().map(str::to_owned)
    );
}
