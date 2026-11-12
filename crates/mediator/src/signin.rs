//! Signing in with the Almena wallet, the way the registry does it (SIOPv2's
//! `direct_post`): the portal shows `almena://auth?request_uri=…` as a QR
//! code and a link; the wallet reads the request there, puts it to the
//! person, and posts back an `id_token` — a compact JWS, `EdDSA`, whose
//! issuer and subject are the `did:key` the wallet keeps **for this
//! mediator's origin** (derived from it, so the same words give the same
//! DID here on any device, and no other site sees it), whose audience is the
//! mediator and whose nonce is the request's.
//!
//! The request and the answer live on the mediator's public origin, which
//! the wallet derives the key from: an administrator is the same DID for as
//! long as the mediator keeps its URL — which is forever.
//!
//! Requests are held in this process for [`REQUEST_TTL_SECS`] (the mediator
//! is one instance), at most [`MAX_PENDING`] at once and [`PER_CLIENT`] from
//! one client, so one client cannot fill it for everyone. Whoever asked is told
//! by a secret only their browser holds (the `poll` cookie), so nobody else
//! can collect the session a wallet's answer opens.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use almena_didcomm::did::multikey;
use almena_didcomm::{Curve, b64};
use anyhow::{Result, anyhow};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::Value;

/// How long a sign-in request may be answered.
pub const REQUEST_TTL_SECS: u64 = 300;
/// How often the page showing a request swaps it for a new one while no
/// wallet has read it: a code seen on a screen is good for a minute.
pub const RENEW_SECS: u64 = 60;
/// How far a token's `iat` may sit from this clock.
const LEEWAY_SECS: u64 = 300;
/// Requests waiting at once, from everyone.
pub const MAX_PENDING: usize = 1_000;
/// Requests waiting at once from one client (an IPv4 address or an IPv6 /64).
pub const PER_CLIENT: usize = 5;
/// Where the wallet reads a request, under the public origin.
pub const REQUESTS_PATH: &str = "/portal/requests";

/// What a request is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// Becoming the first administrator, with the setup code (`/setup`).
    Claim,
    /// An administrator signing in to the portal.
    SignIn,
    /// Becoming an administrator by the invitation with this id.
    Join(String),
}

#[derive(Debug, Clone)]
struct Pending {
    purpose: Purpose,
    /// Who asked, counted against [`PER_CLIENT`].
    client: Option<IpAddr>,
    nonce: String,
    /// What the browser that asked holds, to collect the answer.
    poll: String,
    expires: u64,
    /// Whether a wallet has read it: then it is not swapped for a new one,
    /// so that wallet can still answer it.
    read: bool,
    /// The DID that answered, once one did.
    answered: Option<String>,
}

/// What [`SignIns::renew`] did.
#[derive(Debug)]
pub enum Renewal {
    /// A new request in place of the old one.
    Renewed(Started),
    /// A wallet read or answered it: it stays as it is.
    InUse,
    /// Expired, unknown or not this browser's.
    Gone,
}

/// A new request: its id, and the secret for the browser's cookie.
#[derive(Debug)]
pub struct Started {
    pub id: String,
    pub poll: String,
}

/// What a request has come to, for the browser that asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Waiting,
    /// Answered: the DID the wallet signed as. Taken once.
    Answered {
        purpose: Purpose,
        did: String,
    },
    /// Expired, unknown, or not this browser's.
    Gone,
}

/// Why a wallet's answer is refused, as the wallet is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// No such request (404).
    NotFound,
    /// Expired (410).
    Expired,
    /// Answered already (409).
    AlreadyAnswered,
    /// The token does not hold (400).
    InvalidToken,
}

/// The request object the wallet reads, as the registry serves it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RequestObject {
    pub response_type: &'static str,
    pub response_mode: &'static str,
    pub client_id: String,
    pub client_name: String,
    pub response_uri: String,
    pub nonce: String,
    pub purpose: &'static str,
    pub expires_at: u64,
}

/// The sign-in requests waiting for a wallet.
#[derive(Default)]
pub struct SignIns {
    pending: Mutex<HashMap<String, Pending>>,
}

impl SignIns {
    /// A new request for `purpose` from `client`, or `None` when too many are
    /// waiting, from everyone or from that client.
    pub fn start(
        &self,
        purpose: Purpose,
        client: Option<IpAddr>,
        now: u64,
    ) -> Result<Option<Started>> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| anyhow!("sign-ins poisoned"))?;
        pending.retain(|_, p| p.expires > now);
        if pending.len() >= MAX_PENDING {
            return Ok(None);
        }
        if client.is_some() && pending.values().filter(|p| p.client == client).count() >= PER_CLIENT
        {
            return Ok(None);
        }
        let started = Started {
            id: random(16)?,
            poll: random(32)?,
        };
        pending.insert(
            started.id.clone(),
            Pending {
                purpose,
                client,
                nonce: random(16)?,
                poll: started.poll.clone(),
                expires: now + REQUEST_TTL_SECS,
                read: false,
                answered: None,
            },
        );
        Ok(Some(started))
    }

    /// Swaps request `id` (held by the browser with `poll`) for a new one
    /// with the same purpose, for a code on screen that keeps changing.
    /// [`Renewal::InUse`] when a wallet has read it or answered it: it stays.
    pub fn renew(&self, id: &str, poll: &str, now: u64) -> Result<Renewal> {
        let (purpose, client) = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| anyhow!("sign-ins poisoned"))?;
            let Some(found) = pending.get(id) else {
                return Ok(Renewal::Gone);
            };
            if found.poll.len() != poll.len() || found.poll != poll || found.expires <= now {
                return Ok(Renewal::Gone);
            }
            if found.read || found.answered.is_some() {
                return Ok(Renewal::InUse);
            }
            let found = pending.remove(id).ok_or_else(|| anyhow!("vanished"))?;
            (found.purpose, found.client)
        };
        Ok(match self.start(purpose, client, now)? {
            Some(started) => Renewal::Renewed(started),
            None => Renewal::Gone,
        })
    }

    /// The request `id` as the wallet reads it, from `public_url`.
    pub fn request(
        &self,
        id: &str,
        public_url: &str,
        now: u64,
    ) -> std::result::Result<RequestObject, Refused> {
        let mut pending = self.pending.lock().map_err(|_| Refused::NotFound)?;
        let found = pending.get_mut(id).ok_or(Refused::NotFound)?;
        if found.expires <= now {
            return Err(Refused::Expired);
        }
        if found.answered.is_some() {
            return Err(Refused::AlreadyAnswered);
        }
        found.read = true;
        Ok(RequestObject {
            response_type: "id_token",
            response_mode: "direct_post",
            client_id: public_url.to_owned(),
            client_name: client_name(public_url),
            response_uri: format!("{}/response", request_uri(public_url, id)),
            nonce: found.nonce.clone(),
            purpose: "sign_in",
            expires_at: found.expires,
        })
    }

    /// Takes the wallet's `id_token` for request `id`: checked, then kept
    /// for the browser that asked.
    pub fn answer(
        &self,
        id: &str,
        id_token: &str,
        public_url: &str,
        now: u64,
    ) -> std::result::Result<String, Refused> {
        let mut pending = self.pending.lock().map_err(|_| Refused::NotFound)?;
        let found = pending.get_mut(id).ok_or(Refused::NotFound)?;
        if found.expires <= now {
            return Err(Refused::Expired);
        }
        if found.answered.is_some() {
            return Err(Refused::AlreadyAnswered);
        }
        let did = verify(id_token, public_url, &found.nonce, now).ok_or(Refused::InvalidToken)?;
        found.answered = Some(did.clone());
        Ok(did)
    }

    /// What request `id` came to, for the browser holding `poll`. An answer
    /// is handed over once.
    pub fn outcome(&self, id: &str, poll: &str, now: u64) -> Outcome {
        let Ok(mut pending) = self.pending.lock() else {
            return Outcome::Gone;
        };
        let Some(found) = pending.get(id) else {
            return Outcome::Gone;
        };
        if found.poll.len() != poll.len() || found.poll != poll || found.expires <= now {
            return Outcome::Gone;
        }
        match found.answered.clone() {
            None => Outcome::Waiting,
            Some(did) => {
                let purpose = found.purpose.clone();
                pending.remove(id);
                Outcome::Answered { purpose, did }
            }
        }
    }
}

/// Where the wallet reads request `id`.
pub fn request_uri(public_url: &str, id: &str) -> String {
    format!("{public_url}{REQUESTS_PATH}/{id}")
}

/// The link the wallet opens: `almena://auth?request_uri=…`.
pub fn wallet_link(public_url: &str, id: &str) -> String {
    let uri: String =
        url::form_urlencoded::byte_serialize(request_uri(public_url, id).as_bytes()).collect();
    format!("almena://auth?request_uri={uri}")
}

/// What the wallet's sheet calls the mediator: its host.
fn client_name(public_url: &str) -> String {
    url::Url::parse(public_url)
        .ok()
        .and_then(|url| {
            url.host_str()
                .map(|host| format!("{host} (Almena Mediator)"))
        })
        .unwrap_or_else(|| "Almena Mediator".to_owned())
}

/// The DID that signed `token`, if it is a well-formed `id_token` for this
/// mediator (`aud`), this request (`nonce`) and now: `EdDSA`, by the Ed25519
/// `did:key` that is both its issuer and subject, whose key id, if any,
/// names that same DID.
fn verify(token: &str, audience: &str, nonce: &str, now: u64) -> Option<String> {
    let mut parts = token.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header: Value = serde_json::from_slice(&b64::decode(header).ok()?).ok()?;
    let claims: Value = serde_json::from_slice(&b64::decode(payload).ok()?).ok()?;
    if header["alg"] != "EdDSA" {
        return None;
    }
    let did = claims["sub"].as_str()?;
    if claims["iss"].as_str() != Some(did) || !did.starts_with("did:key:") || did.len() > 255 {
        return None;
    }
    if let Some(kid) = header.get("kid")
        && kid.as_str()?.split('#').next() != Some(did)
    {
        return None;
    }
    let key = multikey::decode(did.strip_prefix("did:key:")?).ok()?;
    if key.curve() != Curve::Ed25519 {
        return None;
    }
    let signed = format!("{}.{}", header_part(token)?, payload);
    key.verify(signed.as_bytes(), &b64::decode(signature).ok()?)
        .ok()?;
    let audience_holds = match &claims["aud"] {
        Value::String(aud) => aud == audience,
        Value::Array(auds) => auds.iter().any(|aud| aud == audience),
        _ => false,
    };
    let iat = claims["iat"].as_u64()?;
    let exp = claims["exp"].as_u64()?;
    let fresh = iat.abs_diff(now) <= LEEWAY_SECS && exp.saturating_add(LEEWAY_SECS) > now;
    (audience_holds && claims["nonce"] == nonce && fresh).then(|| did.to_owned())
}

fn header_part(token: &str) -> Option<&str> {
    token.split('.').next()
}

/// `bytes` random bytes as lowercase hex.
fn random(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| anyhow!("no randomness available"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// An `id_token` as the wallet makes it, for the tests here and the
/// portal's: by `key`, for `audience` and `nonce`, issued at `iat`.
#[cfg(test)]
pub(crate) fn wallet_token(
    key: &almena_didcomm::SecretKey,
    audience: &str,
    nonce: &str,
    iat: u64,
) -> (String, String) {
    wallet_token_until(key, audience, nonce, iat, iat + 120)
}

/// [`wallet_token`] with its own `exp`.
#[cfg(test)]
fn wallet_token_until(
    key: &almena_didcomm::SecretKey,
    audience: &str,
    nonce: &str,
    iat: u64,
    exp: u64,
) -> (String, String) {
    let did = almena_didcomm::did::key::did_key(&key.public_key());
    let fragment = did.trim_start_matches("did:key:");
    let header =
        serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": format!("{did}#{fragment}")});
    let claims = serde_json::json!({
        "iss": did, "sub": did, "aud": audience, "nonce": nonce, "iat": iat, "exp": exp,
    });
    let input = format!(
        "{}.{}",
        b64::encode(header.to_string().as_bytes()),
        b64::encode(claims.to_string().as_bytes())
    );
    let signature = key.sign(input.as_bytes()).unwrap();
    (format!("{input}.{}", b64::encode(&signature)), did)
}

#[cfg(test)]
mod tests {
    use super::*;
    use almena_didcomm::SecretKey;

    const URL: &str = "https://m.example.com";

    #[test]
    fn a_wallet_signs_in_once_and_only_its_browser_collects_it() {
        let signins = SignIns::default();
        let started = signins
            .start(Purpose::SignIn, None, 1_000)
            .unwrap()
            .unwrap();
        let request = signins.request(&started.id, URL, 1_000).unwrap();
        assert_eq!(request.client_id, URL);
        assert_eq!(request.purpose, "sign_in");
        assert_eq!(request.response_mode, "direct_post");
        assert_eq!(
            request.response_uri,
            format!("{URL}/portal/requests/{}/response", started.id)
        );
        assert_eq!(request.client_name, "m.example.com (Almena Mediator)");
        assert!(wallet_link(URL, &started.id).starts_with(
            "almena://auth?request_uri=https%3A%2F%2Fm.example.com%2Fportal%2Frequests%2F"
        ));
        assert_eq!(
            signins.outcome(&started.id, &started.poll, 1_000),
            Outcome::Waiting
        );

        let key = SecretKey::generate(Curve::Ed25519).unwrap();
        let (token, did) = wallet_token(&key, URL, &request.nonce, 1_000);
        assert_eq!(
            signins.answer(&started.id, &token, URL, 1_010),
            Ok(did.clone())
        );
        assert_eq!(
            signins.answer(&started.id, &token, URL, 1_010),
            Err(Refused::AlreadyAnswered)
        );
        // Another browser, without the secret, gets nothing.
        assert_eq!(signins.outcome(&started.id, "guess", 1_010), Outcome::Gone);
        assert_eq!(
            signins.outcome(&started.id, &started.poll, 1_010),
            Outcome::Answered {
                purpose: Purpose::SignIn,
                did
            }
        );
        // Once.
        assert_eq!(
            signins.outcome(&started.id, &started.poll, 1_010),
            Outcome::Gone
        );
    }

    #[test]
    fn tokens_that_do_not_hold_are_refused() {
        let signins = SignIns::default();
        let key = SecretKey::generate(Curve::Ed25519).unwrap();
        let start = || {
            let started = signins.start(Purpose::Claim, None, 1_000).unwrap().unwrap();
            let nonce = signins.request(&started.id, URL, 1_000).unwrap().nonce;
            (started, nonce)
        };
        let refused = |id: &str, token: &str| signins.answer(id, token, URL, 1_000);

        let (started, nonce) = start();
        let (other_nonce, _) = wallet_token(&key, URL, "other", 1_000);
        assert_eq!(
            refused(&started.id, &other_nonce),
            Err(Refused::InvalidToken)
        );
        let (other_site, _) = wallet_token(&key, "https://elsewhere.example", &nonce, 1_000);
        assert_eq!(
            refused(&started.id, &other_site),
            Err(Refused::InvalidToken)
        );
        let (stale, _) = wallet_token(&key, URL, &nonce, 1_000 - LEEWAY_SECS - 200);
        assert_eq!(refused(&started.id, &stale), Err(Refused::InvalidToken));
        let (good, _) = wallet_token(&key, URL, &nonce, 1_000);
        let mut tampered: Vec<&str> = good.split('.').collect();
        let forged_claims = b64::encode(
            serde_json::json!({"iss": "did:key:z6MkX", "sub": "did:key:z6MkX", "aud": URL,
                "nonce": nonce, "iat": 1_000, "exp": 1_120})
            .to_string()
            .as_bytes(),
        );
        tampered[1] = &forged_claims;
        assert_eq!(
            refused(&started.id, &tampered.join(".")),
            Err(Refused::InvalidToken)
        );
        assert_eq!(
            refused(&started.id, "not.a.token"),
            Err(Refused::InvalidToken)
        );
        assert_eq!(refused("unknown", &good), Err(Refused::NotFound));
        // The right one still goes through.
        assert!(refused(&started.id, &good).is_ok());

        // Past its time, a request can neither be read nor answered.
        let (late, nonce) = start();
        let (token, _) = wallet_token(&key, URL, &nonce, 1_000);
        let after = 1_000 + REQUEST_TTL_SECS;
        assert!(matches!(
            signins.request(&late.id, URL, after),
            Err(Refused::Expired)
        ));
        assert_eq!(
            signins.answer(&late.id, &token, URL, after),
            Err(Refused::Expired)
        );
    }

    #[test]
    fn requests_waiting_at_once_are_bounded() {
        let signins = SignIns::default();
        for _ in 0..MAX_PENDING {
            assert!(
                signins
                    .start(Purpose::SignIn, None, 1_000)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            signins
                .start(Purpose::SignIn, None, 1_000)
                .unwrap()
                .is_none()
        );
        // Expired ones make room.
        assert!(
            signins
                .start(Purpose::SignIn, None, 1_000 + REQUEST_TTL_SECS)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_code_on_screen_is_renewed_until_a_wallet_reads_it() {
        let signins = SignIns::default();
        let first = signins.start(Purpose::Claim, None, 1_000).unwrap().unwrap();
        // Somebody else's cookie renews nothing.
        assert!(matches!(
            signins.renew(&first.id, "not-the-poll", 1_010).unwrap(),
            Renewal::Gone
        ));
        let Renewal::Renewed(second) = signins.renew(&first.id, &first.poll, 1_060).unwrap() else {
            panic!("not renewed");
        };
        // The old code is no good any more; the new one keeps the purpose.
        assert!(signins.request(&first.id, URL, 1_060).is_err());
        let request = signins.request(&second.id, URL, 1_061).unwrap();
        // Once a wallet read it, it stays, for that wallet to answer.
        assert!(matches!(
            signins.renew(&second.id, &second.poll, 1_120).unwrap(),
            Renewal::InUse
        ));
        let key = SecretKey::generate(Curve::Ed25519).unwrap();
        let (token, did) = wallet_token(&key, URL, &request.nonce, 1_121);
        signins.answer(&second.id, &token, URL, 1_121).unwrap();
        assert_eq!(
            signins.outcome(&second.id, &second.poll, 1_122),
            Outcome::Answered {
                purpose: Purpose::Claim,
                did
            }
        );
        // Past its time, it is gone.
        let late = signins
            .start(Purpose::SignIn, None, 2_000)
            .unwrap()
            .unwrap();
        assert!(matches!(
            signins
                .renew(&late.id, &late.poll, 2_000 + REQUEST_TTL_SECS)
                .unwrap(),
            Renewal::Gone
        ));
    }

    #[test]
    fn one_client_cannot_fill_the_requests() {
        let signins = SignIns::default();
        let flooder = Some(IpAddr::from([203, 0, 113, 7]));
        for _ in 0..PER_CLIENT {
            assert!(
                signins
                    .start(Purpose::SignIn, flooder, 1_000)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            signins
                .start(Purpose::SignIn, flooder, 1_000)
                .unwrap()
                .is_none()
        );
        // Anyone else still signs in.
        let admin = Some(IpAddr::from([198, 51, 100, 1]));
        assert!(
            signins
                .start(Purpose::SignIn, admin, 1_000)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_huge_expiry_is_no_panic() {
        let key = SecretKey::generate(Curve::Ed25519).unwrap();
        let (token, did) = wallet_token_until(&key, URL, "n", 1_000, u64::MAX);
        assert_eq!(verify(&token, URL, "n", 1_000), Some(did));
    }
}
