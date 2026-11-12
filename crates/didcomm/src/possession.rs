//! Proof of control of a DID: a compact JWT signed with one of the DID's
//! `authentication` keys, bound to who it is for (`aud`), on whose behalf
//! (`sub`) and when (`iat`).
//!
//! Not part of DIDComm. Almena uses it to show a mediator that the DID a
//! wallet registers as a recipient is the wallet's own (SPEC.md §6.2).

use serde::{Deserialize, Serialize};

use crate::crypto::jws::{Compact, sign_compact};
use crate::did::{DidResolver, did_of};
use crate::pack::find_signing_key;
use crate::secrets::SecretsResolver;
use crate::{Error, Result};

/// Claims of a possession proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PossessionProof {
    /// The DID whose control is proven; the signer.
    pub iss: String,
    /// Who the proof is for (e.g. a mediator's DID).
    pub aud: String,
    /// On whose behalf (e.g. the DID of the mediation registering `iss`).
    pub sub: String,
    /// When it was signed (epoch seconds).
    pub iat: u64,
}

impl PossessionProof {
    /// A proof that `did` is controlled by whoever acts as `sub` towards `aud`, issued now.
    pub fn new(did: impl Into<String>, aud: impl Into<String>, sub: impl Into<String>) -> Self {
        Self {
            iss: did.into(),
            aud: aud.into(),
            sub: sub.into(),
            iat: crate::message::now(),
        }
    }

    /// Signs with an `authentication` key of `iss`: `kid` if given, else the
    /// first one we hold a secret for.
    pub async fn pack(
        &self,
        kid: Option<&str>,
        resolver: &dyn DidResolver,
        secrets: &dyn SecretsResolver,
    ) -> Result<String> {
        self.check()?;
        let signer = kid.unwrap_or(&self.iss);
        if did_of(signer) != self.iss {
            return Err(Error::inconsistent("the proof's key is not of its DID"));
        }
        let (kid, key) = find_signing_key(signer, resolver, secrets).await?;
        sign_compact(&serde_json::to_vec(self)?, &kid, &key)
    }

    /// Verifies the signature: it must come from an `authentication` key of
    /// `iss`. Checking `aud`, `sub` and `iat` against what is expected is up
    /// to the caller.
    pub async fn unpack(token: &str, resolver: &dyn DidResolver) -> Result<Self> {
        let jwt = Compact::parse(token)?;
        let claims: Self = serde_json::from_slice(&jwt.payload)?;
        claims.check()?;
        let kid = jwt
            .header
            .kid
            .as_deref()
            .ok_or_else(|| Error::malformed("possession proof without kid"))?;
        if did_of(kid) != claims.iss {
            return Err(Error::inconsistent("the proof's kid is not of its DID"));
        }
        let doc = resolver.resolve(&claims.iss).await?;
        jwt.verify(doc.authentication_key(kid)?)?;
        Ok(claims)
    }

    fn check(&self) -> Result<()> {
        if did_of(&self.iss) != self.iss {
            return Err(Error::malformed("the proof's iss must be a DID"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::peer::{Purpose, peer2};
    use crate::{Curve, InMemorySecrets, LocalResolver, SecretKey};

    fn party() -> (String, InMemorySecrets) {
        let signing = SecretKey::generate(Curve::Ed25519).unwrap();
        let agreement = SecretKey::generate(Curve::X25519).unwrap();
        let did = peer2(
            &[
                (Purpose::Verification, &signing.public_key()),
                (Purpose::Encryption, &agreement.public_key()),
            ],
            &[],
        )
        .unwrap();
        let mut secrets = InMemorySecrets::new();
        secrets.insert(format!("{did}#key-1"), signing);
        secrets.insert(format!("{did}#key-2"), agreement);
        (did, secrets)
    }

    #[tokio::test]
    async fn signs_and_verifies() {
        let (did, secrets) = party();
        let proof = PossessionProof::new(&did, "did:web:mediator.example.com", "did:peer:m");
        let token = proof
            .pack(None, &LocalResolver::new(), &secrets)
            .await
            .unwrap();
        assert_eq!(
            PossessionProof::unpack(&token, &LocalResolver::new())
                .await
                .unwrap(),
            proof
        );
    }

    #[tokio::test]
    async fn another_dids_key_does_not_prove_anything() {
        let (victim, _) = party();
        let (attacker, attacker_secrets) = party();
        // Signed by the attacker but claiming the victim's DID.
        let forged = PossessionProof::new(&victim, "did:web:m", "did:peer:m");
        let token = PossessionProof::new(&attacker, "did:web:m", "did:peer:m")
            .pack(None, &LocalResolver::new(), &attacker_secrets)
            .await
            .unwrap();
        let (header, _) = token.split_once('.').unwrap();
        let (_, signature) = token.rsplit_once('.').unwrap();
        let payload = crate::b64::encode(serde_json::to_vec(&forged).unwrap());
        let tampered = format!("{header}.{payload}.{signature}");
        assert!(
            PossessionProof::unpack(&tampered, &LocalResolver::new())
                .await
                .is_err()
        );
        // Nor can the victim's DID be signed for with the attacker's secrets.
        assert!(
            forged
                .pack(None, &LocalResolver::new(), &attacker_secrets)
                .await
                .is_err()
        );
    }
}
