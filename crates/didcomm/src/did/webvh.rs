//! `did:webvh` 1.0 (<https://identity.foundation/didwebvh/v1.0/>): where a
//! DID's log is, and the DID document it ends in, believed only once every
//! entry has been checked from the first. Fetching the log needs HTTP and is
//! left to the caller; this crate stays transport-free.
//!
//! A `did:webvh:{SCID}:{host}[:path]` keeps its history at
//! `https://{host}/{path}/did.jsonl` (`/.well-known/did.jsonl` for a bare
//! host): one entry per line, `{versionId, versionTime, parameters, state,
//! proof}`. Walking it, every entry must hold:
//!
//! - **the SCID**: the first entry, without its proof, its `versionId` set to
//!   the SCID and every SCID written back as `{SCID}`, hashes (SHA-256 over
//!   its RFC 8785 form, as a base58btc multihash) to the SCID the DID names;
//!   it names the method (`did:webvh:1.0`), that SCID and its `updateKeys`;
//! - **the chain**: `versionId` is `{n}-{hash}`, `n` counting from 1, and the
//!   hash is the entry's without its proof, with the previous `versionId` in
//!   place of its own (the SCID, for the first);
//! - **the proof**: an `eddsa-jcs-2022` Data Integrity proof
//!   (`assertionMethod`) by one of the update keys in force before it — the
//!   first entry's own, for the first — named as its `did:key`;
//! - **pre-rotation**: once `nextKeyHashes` are set, new `updateKeys` must
//!   each hash to one of them;
//! - **the rest**: `versionTime` never goes back, the method and SCID never
//!   change, `state.id` is the DID itself, and nothing follows a
//!   deactivation. A deactivated DID resolves to nothing.
//!
//! Witnesses are not supported: a log that asks for them is refused rather
//! than half believed. Whatever does not hold refuses the whole log.
//!
//! The Almena registry's identities are `did:webvh`; the wallet resolves them
//! the same way (`wallet/src-tauri/src/webvh.rs`), and both are held to a log
//! the registry wrote (`tests/webvh/registry-did.jsonl`).

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::crypto::keys::Curve;
use crate::did::{DidDocument, multikey};
use crate::{Error, Result};

const METHOD: &str = "did:webvh:1.0";
const PLACEHOLDER: &str = "{SCID}";
const CRYPTOSUITE: &str = "eddsa-jcs-2022";

/// Where a `did:webvh`'s log is: `https://{host}/{path}/did.jsonl`.
pub fn log_url(did: &str) -> Result<String> {
    let bad = || Error::malformed(format!("not a did:webvh: {did}"));
    let rest = did.strip_prefix("did:webvh:").ok_or_else(bad)?;
    let mut parts = rest.split(':');
    parts
        .next()
        .filter(|scid| !scid.is_empty())
        .ok_or_else(bad)?;
    let host = parts
        .next()
        .filter(|host| !host.is_empty())
        .ok_or_else(bad)?
        .replace("%3A", ":")
        .replace("%3a", ":");
    let path: Vec<&str> = parts.collect();
    if host.contains(['/', '?', '#', '@']) || path.iter().any(|part| part.is_empty()) {
        return Err(bad());
    }
    Ok(if path.is_empty() {
        format!("https://{host}/.well-known/did.jsonl")
    } else {
        format!("https://{host}/{}/did.jsonl", path.join("/"))
    })
}

/// The DID document `did`'s log ends in, if every entry of `log` (JSON Lines,
/// oldest first) holds. A deactivated DID is [`Error::DidNotFound`]; a log
/// that does not hold, [`Error::Resolver`].
pub fn resolve(log: &str, did: &str) -> Result<DidDocument> {
    match walk(log, did) {
        Some(Walked::Active(state)) => DidDocument::from_json(&state),
        Some(Walked::Deactivated) => Err(Error::DidNotFound(did.to_owned())),
        None => Err(Error::Resolver(format!("{did}: its log does not hold"))),
    }
}

/// SHA-256 as a base58btc multihash (`Qm…`): what SCIDs, entry hashes and
/// next key hashes are.
fn multihash(data: &[u8]) -> String {
    let mut bytes = vec![0x12, 0x20];
    bytes.extend_from_slice(&Sha256::digest(data));
    bs58::encode(bytes).into_string()
}

/// RFC 8785, the JSON Canonicalization Scheme, for what log entries hold:
/// keys sorted by UTF-16 code units, no whitespace, integers only.
fn jcs(value: &Value) -> Option<String> {
    Some(match value {
        Value::Null | Value::Bool(_) | Value::String(_) => value.to_string(),
        Value::Number(number) if number.is_i64() || number.is_u64() => number.to_string(),
        Value::Number(_) => return None,
        Value::Array(items) => {
            let parts: Option<Vec<String>> = items.iter().map(jcs).collect();
            format!("[{}]", parts?.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                parts.push(format!(
                    "{}:{}",
                    Value::String(key.clone()),
                    jcs(&map[key])?
                ));
            }
            format!("{{{}}}", parts.join(","))
        }
    })
}

fn scid_of(did: &str) -> Option<&str> {
    did.strip_prefix("did:webvh:")?
        .split(':')
        .next()
        .filter(|scid| !scid.is_empty())
}

fn without_proof(entry: &Map<String, Value>) -> Map<String, Value> {
    entry
        .iter()
        .filter(|(name, _)| name.as_str() != "proof")
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// Whether `proof` is an `eddsa-jcs-2022` signature over `entry` (its proof
/// left out) by one of `signers`, named as that key's `did:key`.
fn proves(entry: &Map<String, Value>, proof: &Value, signers: &[String]) -> bool {
    let check = || -> Option<()> {
        let options = proof.as_object()?;
        let method = options.get("verificationMethod")?.as_str()?;
        let value = options.get("proofValue")?.as_str()?;
        let (named, key) = method.split_once('#')?;
        if options.get("type")?.as_str()? != "DataIntegrityProof"
            || options.get("cryptosuite")?.as_str()? != CRYPTOSUITE
            || options.get("proofPurpose")?.as_str()? != "assertionMethod"
            || named != format!("did:key:{key}")
            || !signers.iter().any(|signer| signer == key)
            // An entry has no context, so its proof options carry none.
            || options.contains_key("@context") != entry.contains_key("@context")
        {
            return None;
        }
        let public = multikey::decode(key).ok()?;
        if public.curve() != Curve::Ed25519 {
            return None;
        }
        let mut unsigned = options.clone();
        unsigned.remove("proofValue");
        let mut hashed = Sha256::digest(jcs(&Value::Object(unsigned))?.as_bytes()).to_vec();
        hashed.extend_from_slice(&Sha256::digest(
            jcs(&Value::Object(without_proof(entry)))?.as_bytes(),
        ));
        let signature = bs58::decode(value.strip_prefix('z')?).into_vec().ok()?;
        public.verify(&hashed, &signature).ok()
    };
    check().is_some()
}

enum Walked {
    Active(Value),
    Deactivated,
}

/// Walks the log; `None` as soon as anything does not hold.
fn walk(log: &str, did: &str) -> Option<Walked> {
    let scid = scid_of(did)?;
    let entries: Vec<Map<String, Value>> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| match serde_json::from_str(line) {
            Ok(Value::Object(entry)) => Some(entry),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let mut update_keys: Vec<String> = Vec::new();
    let mut next_hashes: Vec<String> = Vec::new();
    let mut previous: Option<String> = None;
    let mut time = String::new();
    let mut deactivated = false;
    let mut state = None;

    for (at, entry) in entries.iter().enumerate() {
        if deactivated {
            return None;
        }
        let version_id = entry.get("versionId")?.as_str()?;
        let (number, hash) = version_id.split_once('-')?;
        if number.parse::<usize>().ok()? != at + 1 {
            return None;
        }
        let parameters = entry.get("parameters")?.as_object()?;
        let first = previous.is_none();

        // The method and the SCID: named by the first entry, never changed.
        if parameters
            .get("method")
            .is_some_and(|method| method != METHOD)
            || parameters
                .get("scid")
                .is_some_and(|named| named.as_str() != Some(scid))
            || (first && (parameters.get("method").is_none() || parameters.get("scid").is_none()))
        {
            return None;
        }
        if parameters.get("witness").is_some_and(|witness| {
            !witness.is_null() && witness.as_object().is_none_or(|w| !w.is_empty())
        }) {
            return None;
        }

        // The chain: hashed with the previous versionId (the SCID, first).
        let mut chained = without_proof(entry);
        let before = previous.clone().unwrap_or_else(|| scid.to_owned());
        chained.insert("versionId".into(), Value::String(before));
        let chained = Value::Object(chained);
        let text = jcs(&chained)?;
        if multihash(text.as_bytes()) != hash {
            return None;
        }
        if first && multihash(text.replace(scid, PLACEHOLDER).as_bytes()) != scid {
            return None;
        }

        // Who may sign it: the keys in force before it; the first, its own.
        let named_keys = match parameters.get("updateKeys") {
            Some(keys) => Some(strings(keys)?),
            None => None,
        };
        let signers = if first {
            named_keys.clone().filter(|keys| !keys.is_empty())?
        } else {
            update_keys.clone()
        };
        let proofs = match entry.get("proof")? {
            Value::Array(items) => items.clone(),
            single => vec![single.clone()],
        };
        if !proofs.iter().any(|proof| proves(entry, proof, &signers)) {
            return None;
        }

        // Pre-rotation: new update keys were committed to beforehand.
        if let Some(keys) = &named_keys {
            if !next_hashes.is_empty()
                && !keys
                    .iter()
                    .all(|key| next_hashes.contains(&multihash(key.as_bytes())))
            {
                return None;
            }
            update_keys = keys.clone();
        }
        if let Some(hashes) = parameters.get("nextKeyHashes") {
            next_hashes = strings(hashes)?;
        }

        let when = entry.get("versionTime")?.as_str()?;
        if when < time.as_str() {
            return None;
        }
        time = when.to_owned();
        deactivated = parameters.get("deactivated") == Some(&Value::Bool(true));
        let document = entry.get("state")?;
        if document.get("id")?.as_str()? != did {
            return None;
        }
        state = Some(document.clone());
        previous = Some(version_id.to_owned());
    }
    if deactivated {
        return Some(Walked::Deactivated);
    }
    state.map(Walked::Active)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::PublicKey;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn written(key: &SigningKey) -> String {
        multikey::encode(
            &PublicKey::from_bytes(Curve::Ed25519, key.verifying_key().as_bytes()).unwrap(),
        )
    }

    /// `entry` with an `eddsa-jcs-2022` proof by `key`, as wallets sign.
    fn sign(entry: Value, key: &SigningKey) -> Value {
        let multikey = written(key);
        let mut options = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": CRYPTOSUITE,
            "verificationMethod": format!("did:key:{multikey}#{multikey}"),
            "created": "2026-10-01T00:00:00Z",
            "proofPurpose": "assertionMethod",
        });
        let mut hashed = Sha256::digest(jcs(&options).unwrap().as_bytes()).to_vec();
        hashed.extend_from_slice(&Sha256::digest(jcs(&entry).unwrap().as_bytes()));
        let signature = key.sign(&hashed);
        options["proofValue"] = json!(format!(
            "z{}",
            bs58::encode(signature.to_bytes()).into_string()
        ));
        let mut signed = entry;
        signed["proof"] = json!([options]);
        signed
    }

    /// The first entry of a DID at `location` (`host:path`), as the registry
    /// makes it: the SCID hashed with placeholders, then put in place.
    fn genesis(location: &str, key: &SigningKey, state: Value) -> (String, Value) {
        let mut document = state;
        document["id"] = json!(format!("did:webvh:{PLACEHOLDER}:{location}"));
        let preliminary = json!({
            "versionId": PLACEHOLDER,
            "versionTime": "2026-10-01T00:00:00Z",
            "parameters": {"method": METHOD, "scid": PLACEHOLDER, "updateKeys": [written(key)]},
            "state": document,
        });
        let scid = multihash(jcs(&preliminary).unwrap().as_bytes());
        let mut entry: Value =
            serde_json::from_str(&preliminary.to_string().replace(PLACEHOLDER, &scid)).unwrap();
        let hash = multihash(jcs(&entry).unwrap().as_bytes());
        entry["versionId"] = json!(format!("1-{hash}"));
        (format!("did:webvh:{scid}:{location}"), sign(entry, key))
    }

    /// The entry after `previous`, signed by `key`.
    fn following(previous: &Value, parameters: Value, state: Value, key: &SigningKey) -> Value {
        let before = previous["versionId"].as_str().unwrap();
        let number: u64 = before.split('-').next().unwrap().parse().unwrap();
        let mut entry = json!({
            "versionId": before,
            "versionTime": "2026-10-02T00:00:00Z",
            "parameters": parameters,
            "state": state,
        });
        let hash = multihash(jcs(&entry).unwrap().as_bytes());
        entry["versionId"] = json!(format!("{}-{hash}", number + 1));
        sign(entry, key)
    }

    fn lines(entries: &[Value]) -> String {
        entries.iter().map(|entry| format!("{entry}\n")).collect()
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// An issuer's document as the registry publishes it: an X25519
    /// `keyAgreement` key and a DIDComm service through a mediator.
    fn issuer_state(did: &str) -> Value {
        let agreement = multikey::encode(&PublicKey::from_bytes(Curve::X25519, &[9; 32]).unwrap());
        json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#{agreement}"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": agreement,
            }],
            "keyAgreement": [format!("{did}#{agreement}")],
            "service": [{
                "id": format!("{did}#didcomm"),
                "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": "did:web:mediator.almena.id", "accept": ["didcomm/v2"]},
            }],
        })
    }

    #[test]
    fn a_log_resolves_to_its_last_state_once_every_entry_holds() {
        let owner = key(1);
        let (did, first) = genesis("almena.id:ids:idn_uni", &owner, json!({}));
        let second = following(&first, json!({}), issuer_state(&did), &owner);
        let doc = resolve(&lines(&[first.clone(), second.clone()]), &did).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.key_agreement_methods().count(), 1);
        assert_eq!(doc.didcomm_services().count(), 1);

        // Another DID's log, a broken chain, entries out of order, a change
        // after signing, an empty or unreadable log.
        let (other, _) = genesis("almena.id:ids:idn_other", &owner, json!({}));
        assert!(resolve(&lines(std::slice::from_ref(&first)), &other).is_err());
        assert!(resolve(&lines(std::slice::from_ref(&second)), &did).is_err());
        assert!(resolve(&lines(&[second.clone(), first.clone()]), &did).is_err());
        let mut altered = second.clone();
        altered["state"]["keyAgreement"] = json!([format!("{did}#zOther")]);
        assert!(resolve(&lines(&[first, altered]), &did).is_err());
        assert!(resolve("", &did).is_err());
        assert!(resolve("not json\n", &did).is_err());
    }

    #[test]
    fn only_the_update_keys_in_force_sign_the_next_entry() {
        let owner = key(1);
        let heir = key(2);
        let (did, first) = genesis("almena.id:ids:idn_uni", &owner, json!({}));
        let state = first["state"].clone();
        let usurped = following(&first, json!({}), state.clone(), &heir);
        assert!(resolve(&lines(&[first.clone(), usurped]), &did).is_err());
        let handover = following(
            &first,
            json!({"updateKeys": [written(&heir)]}),
            state.clone(),
            &owner,
        );
        let next = following(&handover, json!({}), state.clone(), &heir);
        assert!(resolve(&lines(&[first.clone(), handover.clone(), next]), &did).is_ok());
        let stale = following(&handover, json!({}), state, &owner);
        assert!(resolve(&lines(&[first, handover, stale]), &did).is_err());
    }

    #[test]
    fn pre_rotation_deactivation_and_witnesses_are_held_to() {
        let owner = key(1);
        let heir = written(&key(2));
        let (did, first) = genesis("almena.id:ids:idn_uni", &owner, json!({}));
        let state = first["state"].clone();
        let committed = following(
            &first,
            json!({"nextKeyHashes": [multihash(heir.as_bytes())]}),
            state.clone(),
            &owner,
        );
        let kept = following(
            &committed,
            json!({"updateKeys": [heir]}),
            state.clone(),
            &owner,
        );
        assert!(resolve(&lines(&[first.clone(), committed.clone(), kept]), &did).is_ok());
        let broken = following(
            &committed,
            json!({"updateKeys": [written(&key(3))]}),
            state.clone(),
            &owner,
        );
        assert!(resolve(&lines(&[first.clone(), committed, broken]), &did).is_err());

        let ended = following(&first, json!({"deactivated": true}), state.clone(), &owner);
        assert!(matches!(
            resolve(&lines(&[first.clone(), ended]), &did),
            Err(Error::DidNotFound(_))
        ));
        let witnessed = following(
            &first,
            json!({"witness": {"threshold": 1, "witnesses": [{"id": "did:key:zW"}]}}),
            state,
            &owner,
        );
        assert!(resolve(&lines(&[first, witnessed]), &did).is_err());
    }

    /// A log made by the registry's own code (`api`'s `webvh.py`), signed as
    /// wallets sign — the same one the wallet's resolver is tested with.
    const REGISTRY_LOG: &str = include_str!("../../tests/webvh/registry-did.jsonl");
    const REGISTRY_DID: &str =
        "did:webvh:QmQi5rPBEy17S5sNgnpM8dFZdSdqrbt3JF4t2G1bDP9kn1:almena.id:ids:idn_club";

    #[test]
    fn a_log_the_registry_wrote_resolves() {
        let doc = resolve(REGISTRY_LOG, REGISTRY_DID).unwrap();
        assert_eq!(
            doc.assertion_method,
            [format!(
                "{REGISTRY_DID}#z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH"
            )]
        );
        let lines: Vec<&str> = REGISTRY_LOG.lines().collect();
        assert!(resolve(&lines[..2].join("\n"), REGISTRY_DID).is_ok());
        assert!(resolve(&lines[1..].join("\n"), REGISTRY_DID).is_err());
    }

    #[test]
    fn a_did_says_where_its_log_is() {
        assert_eq!(
            log_url("did:webvh:QmS:almena.id:ids:idn_club").unwrap(),
            "https://almena.id/ids/idn_club/did.jsonl"
        );
        assert_eq!(
            log_url("did:webvh:QmS:localhost%3A8000").unwrap(),
            "https://localhost:8000/.well-known/did.jsonl"
        );
        assert!(log_url("did:web:almena.id").is_err());
        assert!(log_url("did:webvh:QmS:almena.id::x").is_err());
        assert!(log_url("did:webvh::almena.id").is_err());
    }
}
