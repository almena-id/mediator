//! TURN credentials (`https://almena.id/protocols/turn/1.0`, SPEC.md
//! §6.9): a mediated wallet asks for short-lived credentials for the TURN
//! server its operator runs beside the mediator, so that its calls can be
//! relayed. They are the time-limited credentials of the TURN REST API, which
//! coturn checks with `use-auth-secret`: nothing is stored.

use almena_didcomm::Message;
use almena_didcomm::message::now;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};

use super::protocols::{Problem, TURN_CREDENTIALS, TURN_CREDENTIALS_REQUEST};
use super::{Handled, Mediator};
use crate::metrics::METRICS;

/// The TURN server wallets are given credentials for.
pub struct TurnServer {
    urls: Vec<String>,
    key: hmac::Key,
    ttl_secs: u64,
}

impl TurnServer {
    /// `urls` are `turn:`/`turns:` URIs; `secret` is the one the TURN server
    /// shares (coturn's `static-auth-secret`); credentials last `ttl_secs`.
    pub fn new(urls: Vec<String>, secret: &str, ttl_secs: u64) -> Self {
        Self {
            urls,
            key: hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret.as_bytes()),
            ttl_secs,
        }
    }

    /// The `credentials` body at `now`: the username is `<expiry>:<random
    /// id>`, the credential base64(HMAC-SHA1(secret, username)), as the TURN
    /// REST API defines them. The id is random so that the TURN server's
    /// logs cannot be joined to a DID.
    fn credentials(&self, now: u64) -> anyhow::Result<Value> {
        let mut id = [0u8; 8];
        SystemRandom::new()
            .fill(&mut id)
            .map_err(|_| anyhow::anyhow!("no randomness for a TURN username"))?;
        let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
        Ok(self.credentials_for(now, &id))
    }

    fn credentials_for(&self, now: u64, id: &str) -> Value {
        let username = format!("{}:{id}", now.saturating_add(self.ttl_secs));
        let credential = STANDARD.encode(hmac::sign(&self.key, username.as_bytes()).as_ref());
        json!({
            "ice_servers": [{
                "urls": self.urls,
                "username": username,
                "credential": credential,
            }],
            "ttl": self.ttl_secs,
        })
    }
}

/// Handles a TURN protocol message from `requester` (an authenticated DID).
pub(crate) async fn handle(
    mediator: &Mediator,
    requester: &str,
    message: &Message,
) -> anyhow::Result<Handled> {
    let Some(turn) = mediator.turn() else {
        return Ok(Handled::Problem(Problem::UnsupportedType));
    };
    if message.type_ != TURN_CREDENTIALS_REQUEST {
        return Ok(Handled::Problem(Problem::UnsupportedType));
    }
    if !mediator.store().has_mediation(requester).await? {
        return Ok(Handled::Problem(Problem::NoMediation));
    }
    METRICS.turn_credentials();
    tracing::debug!(mediation = %requester, "TURN credentials issued");
    Ok(Handled::Reply(
        Message::new(TURN_CREDENTIALS, turn.credentials(now())?).reply_to(message),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_follow_the_turn_rest_api() {
        let turn = TurnServer::new(
            vec!["turn:turn.example.com:3478?transport=udp".into()],
            "north",
            86_400,
        );
        let body = turn.credentials_for(1_700_000_000, "0011223344556677");
        assert_eq!(body["ttl"], 86_400);
        let server = &body["ice_servers"][0];
        assert_eq!(
            server["urls"],
            json!(["turn:turn.example.com:3478?transport=udp"])
        );
        assert_eq!(server["username"], "1700086400:0011223344556677");
        // base64(HMAC-SHA1("north", username)), computed independently.
        assert_eq!(server["credential"], "i37YaUruwshS1zesRXzqpP9zw9A=");
    }

    #[test]
    fn usernames_differ_between_requests() {
        let turn = TurnServer::new(vec!["turn:t.example.com".into()], "s", 60);
        let a = turn.credentials(1).unwrap();
        let b = turn.credentials(1).unwrap();
        assert_ne!(
            a["ice_servers"][0]["username"],
            b["ice_servers"][0]["username"]
        );
    }
}
