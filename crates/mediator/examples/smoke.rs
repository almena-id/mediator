//! End-to-end check of a running mediator, playing two wallets: Bob finds the
//! mediator through its invitation and gets mediation, Alice sends him messages
//! through the mediator, Bob picks them up over HTTP and live over a WebSocket.
//!
//! ```text
//! cargo run -p almena-mediator --example smoke -- http://localhost:8080
//! ```
//!
//! A private mediator takes Bob only by invitation: pass one an
//! administrator made (its link, `…/oob?_oob=…`) after the URL, and Bob
//! answers it.

use almena_didcomm::did::peer::{Purpose, peer2};
use almena_didcomm::did::{ChainResolver, DidDocument, LocalResolver, StaticResolver};
use almena_didcomm::{Curve, InMemorySecrets, Message, PackOptions, SecretKey, b64, unpack};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Frame;

const ENCRYPTED: &str = "application/didcomm-encrypted+json";

struct Wallet {
    name: &'static str,
    did: String,
    secrets: InMemorySecrets,
}

impl Wallet {
    fn new(name: &'static str, services: &[Value]) -> Result<Self> {
        let signing = SecretKey::generate(Curve::Ed25519)?;
        let agreement = SecretKey::generate(Curve::X25519)?;
        let did = peer2(
            &[
                (Purpose::Verification, &signing.public_key()),
                (Purpose::Encryption, &agreement.public_key()),
            ],
            services,
        )?;
        let mut secrets = InMemorySecrets::new();
        secrets.insert(format!("{did}#key-1"), signing);
        secrets.insert(format!("{did}#key-2"), agreement);
        Ok(Self { name, did, secrets })
    }
}

struct Mediator {
    http: reqwest::Client,
    base: String,
    doc: DidDocument,
    resolver: ChainResolver,
}

impl Mediator {
    async fn post(&self, url: &str, body: String) -> Result<(u16, String)> {
        let response = self
            .http
            .post(url)
            .header("content-type", ENCRYPTED)
            .body(body)
            .send()
            .await?;
        Ok((response.status().as_u16(), response.text().await?))
    }

    /// An authcrypted request with `return_route: "all"`; returns the reply.
    async fn request(&self, wallet: &Wallet, type_: &str, body: Value) -> Result<Message> {
        self.request_in(wallet, type_, body, None).await
    }

    /// [`Mediator::request`], answering the invitation `pthid`.
    async fn request_in(
        &self,
        wallet: &Wallet,
        type_: &str,
        body: Value,
        pthid: Option<&str>,
    ) -> Result<Message> {
        let mut message = Message::new(type_, body);
        message.pthid = pthid.map(str::to_owned);
        let packed = message
            .from(&wallet.did)
            .to([self.doc.id.as_str()])
            .header("return_route", json!("all"))
            .pack_encrypted(
                &self.doc.id,
                Some(&wallet.did),
                None,
                &self.resolver,
                &wallet.secrets,
                PackOptions::default(),
            )
            .await?;
        let (status, reply) = self
            .post(&format!("{}/didcomm", self.base), packed.message)
            .await?;
        ensure!(status == 200, "{type_}: HTTP {status}: {reply}");
        let (message, _) = unpack(&reply, &self.resolver, &wallet.secrets).await?;
        println!("  {} ← {}", wallet.name, short(&message.type_));
        if message.type_.ends_with("/problem-report") {
            bail!("{type_}: problem report {}", message.body);
        }
        Ok(message)
    }
}

/// The message name: the last segment of its type URI.
fn short(type_: &str) -> &str {
    type_.rsplit('/').next().unwrap_or(type_)
}

#[tokio::main]
async fn main() -> Result<()> {
    let base = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:8080".into());
    let base = base.trim_end_matches('/').to_owned();
    // An invitation to answer (a private mediator's): its id is the pthid.
    let invited = match std::env::args().nth(2) {
        Some(link) => {
            let encoded = link
                .split_once("_oob=")
                .map(|(_, rest)| rest.split('&').next().unwrap_or(rest))
                .context("the invitation link has no _oob")?;
            let invitation: Value = serde_json::from_slice(&b64::decode(encoded)?)?;
            Some(
                invitation["id"]
                    .as_str()
                    .context("the invitation has no id")?
                    .to_owned(),
            )
        }
        None => None,
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::new();

    println!("1. Mediator DID document ({base}/.well-known/did.json)");
    let doc_json: Value = http
        .get(format!("{base}/.well-known/did.json"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("reading the mediator's DID document")?;
    let doc = DidDocument::from_json(&doc_json)?;
    println!("  mediator DID: {}", doc.id);
    let resolver = ChainResolver::new(vec![
        Arc::new(StaticResolver::new([doc.clone()])),
        Arc::new(LocalResolver::new()),
    ]);
    let mediator = Mediator {
        http,
        base,
        doc,
        resolver,
    };

    let bob = Wallet::new(
        "bob",
        &[
            json!({"type": "DIDCommMessaging", "serviceEndpoint": {"uri": mediator.doc.id, "accept": ["didcomm/v2"]}}),
        ],
    )?;
    let alice = Wallet::new("alice", &[])?;

    let invitation: Value = mediator
        .http
        .get(format!("{}/oob/invitation", mediator.base))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        invitation["invitation"]["from"] == mediator.doc.id,
        "invitation from another DID"
    );
    println!(
        "  invitation: {}",
        invitation["invitation"]["body"]["goal_code"]
    );

    println!("2. Trust Ping");
    mediator
        .request(&alice, "https://didcomm.org/trust-ping/2.0/ping", json!({}))
        .await?;

    println!("3. Bob requests mediation and registers his DID");
    let answer = mediator
        .request_in(
            &bob,
            "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
            json!({}),
            invited.as_deref(),
        )
        .await?;
    ensure!(
        answer.type_.ends_with("/mediate-grant"),
        "mediation denied (a private mediator takes Bob only with an invitation: pass its link)"
    );
    let update = mediator
        .request(
            &bob,
            "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
            json!({"updates": [{"recipient_did": bob.did, "action": "add"}]}),
        )
        .await?;
    ensure!(
        update.body["updated"][0]["result"] == "success",
        "recipient-update: {}",
        update.body
    );

    println!("4. Alice sends Bob a message (wrapped in a forward to the mediator)");
    let packed = Message::new(
        "https://example.com/chat/1.0/message",
        json!({"text": "hello Bob"}),
    )
    .from(&alice.did)
    .to([bob.did.as_str()])
    .pack_encrypted(
        &bob.did,
        Some(&alice.did),
        None,
        &mediator.resolver,
        &alice.secrets,
        PackOptions::default(),
    )
    .await?;
    let uri = packed
        .service_uri
        .context("Bob's DID has no DIDComm service")?;
    // The document advertises the public URL; talk to the one we were given.
    let uri = uri.replacen(
        &mediator.doc.service[0].didcomm_endpoints()?[0].uri,
        &format!("{}/didcomm", mediator.base),
        1,
    );
    let (status, body) = mediator.post(&uri, packed.message).await?;
    ensure!(status == 202, "forward: HTTP {status}: {body}");
    println!("  mediator accepted the forward (202)");

    println!("5. Bob picks it up");
    let status = mediator
        .request(
            &bob,
            "https://didcomm.org/messagepickup/3.0/status-request",
            json!({}),
        )
        .await?;
    ensure!(status.body["message_count"] == 1, "status: {}", status.body);
    let delivery = mediator
        .request(
            &bob,
            "https://didcomm.org/messagepickup/3.0/delivery-request",
            json!({"limit": 10}),
        )
        .await?;
    let attachment = delivery
        .attachments
        .as_deref()
        .and_then(|a| a.first())
        .context("empty delivery")?;
    let inner = String::from_utf8(b64::decode(
        attachment.data.base64.as_deref().context("no base64")?,
    )?)?;
    let (message, meta) = unpack(&inner, &mediator.resolver, &bob.secrets).await?;
    ensure!(
        meta.authenticated && message.from.as_deref() == Some(alice.did.as_str()),
        "not from Alice"
    );
    println!(
        "  Bob read: {:?} (authenticated sender: alice)",
        message.body["text"]
    );

    println!("6. Bob acknowledges");
    let after = mediator
        .request(
            &bob,
            "https://didcomm.org/messagepickup/3.0/messages-received",
            json!({"message_id_list": [attachment.id]}),
        )
        .await?;
    ensure!(
        after.body["message_count"] == 0,
        "queue not empty: {}",
        after.body
    );

    println!("7. Bob goes live over a WebSocket");
    let ws_url = format!("ws{}/ws", mediator.base.trim_start_matches("http"));
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await?;
    let live_on = Message::new(
        "https://didcomm.org/messagepickup/3.0/live-delivery-change",
        json!({"live_delivery": true}),
    )
    .from(&bob.did)
    .to([mediator.doc.id.as_str()])
    .pack_encrypted(
        &mediator.doc.id,
        Some(&bob.did),
        None,
        &mediator.resolver,
        &bob.secrets,
        PackOptions::default(),
    )
    .await?;
    ws.send(Frame::Text(live_on.message.into())).await?;
    let (status, _) = unpack(&next_text(&mut ws).await?, &mediator.resolver, &bob.secrets).await?;
    ensure!(
        status.body["live_delivery"] == true,
        "live mode refused: {}",
        status.body
    );
    println!("  bob ← status (live_delivery: true)");

    let packed = Message::new(
        "https://example.com/chat/1.0/message",
        json!({"text": "live, Bob"}),
    )
    .from(&alice.did)
    .to([bob.did.as_str()])
    .pack_encrypted(
        &bob.did,
        Some(&alice.did),
        None,
        &mediator.resolver,
        &alice.secrets,
        PackOptions::default(),
    )
    .await?;
    let (status, body) = mediator.post(&uri, packed.message).await?;
    ensure!(status == 202, "forward: HTTP {status}: {body}");
    let (delivery, _) =
        unpack(&next_text(&mut ws).await?, &mediator.resolver, &bob.secrets).await?;
    let attachment = delivery
        .attachments
        .as_deref()
        .and_then(|a| a.first())
        .context("empty live delivery")?;
    let inner = String::from_utf8(b64::decode(
        attachment.data.base64.as_deref().context("no base64")?,
    )?)?;
    let (message, _) = unpack(&inner, &mediator.resolver, &bob.secrets).await?;
    println!("  Bob got it live: {:?}", message.body["text"]);
    let ack = Message::new(
        "https://didcomm.org/messagepickup/3.0/messages-received",
        json!({"message_id_list": [attachment.id]}),
    )
    .from(&bob.did)
    .to([mediator.doc.id.as_str()])
    .pack_encrypted(
        &mediator.doc.id,
        Some(&bob.did),
        None,
        &mediator.resolver,
        &bob.secrets,
        PackOptions::default(),
    )
    .await?;
    ws.send(Frame::Text(ack.message.into())).await?;
    let (status, _) = unpack(&next_text(&mut ws).await?, &mediator.resolver, &bob.secrets).await?;
    ensure!(
        status.body["message_count"] == 0,
        "queue not empty: {}",
        status.body
    );
    ws.close(None).await?;

    println!("OK — the mediator works end to end.");
    Ok(())
}

/// The next text frame, within a few seconds.
async fn next_text(
    ws: &mut (impl StreamExt<Item = Result<Frame, tokio_tungstenite::tungstenite::Error>> + Unpin),
) -> Result<String> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await? {
            Some(Ok(Frame::Text(text))) => return Ok(text.to_string()),
            Some(Ok(_)) => continue,
            Some(Err(err)) => return Err(err.into()),
            None => bail!("the WebSocket closed"),
        }
    }
}
