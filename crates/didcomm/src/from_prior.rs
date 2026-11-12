//! DID rotation: the `from_prior` header (spec: "DID Rotation").

use serde::{Deserialize, Serialize};

use crate::crypto::jws::{Compact, sign_compact};
use crate::did::{DidResolver, did_of};
use crate::pack::find_signing_key;
use crate::secrets::SecretsResolver;
use crate::{Error, Result};

/// Claims of a `from_prior` JWT: `iss` is the prior DID, `sub` the new one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FromPrior {
    pub iss: String,
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Time of the rotation (not of the message carrying it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl FromPrior {
    /// A rotation from `prior` to `new`, issued now.
    pub fn new(prior: impl Into<String>, new: impl Into<String>) -> Self {
        Self {
            iss: prior.into(),
            sub: new.into(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(crate::message::now()),
            jti: None,
        }
    }

    /// Signs the JWT with an `authentication` key of the prior DID: `issuer_kid`
    /// if given, else the first one we hold a secret for.
    pub async fn pack(
        &self,
        issuer_kid: Option<&str>,
        resolver: &dyn DidResolver,
        secrets: &dyn SecretsResolver,
    ) -> Result<String> {
        self.check()?;
        let signer = issuer_kid.unwrap_or(&self.iss);
        if did_of(signer) != self.iss {
            return Err(Error::inconsistent(
                "from_prior issuer key is not of the prior DID",
            ));
        }
        let (kid, key) = find_signing_key(signer, resolver, secrets).await?;
        sign_compact(&serde_json::to_vec(self)?, &kid, &key)
    }

    /// Verifies a `from_prior` JWT: the signing key must be an
    /// `authentication` key of `iss`. Returns the claims and the issuer kid.
    pub async fn unpack(token: &str, resolver: &dyn DidResolver) -> Result<(Self, String)> {
        let jwt = Compact::parse(token)?;
        let claims: Self = serde_json::from_slice(&jwt.payload)?;
        claims.check()?;
        let kid = jwt
            .header
            .kid
            .clone()
            .ok_or_else(|| Error::malformed("from_prior without kid"))?;
        if did_of(&kid) != claims.iss {
            return Err(Error::inconsistent(
                "from_prior kid is not of the issuer DID",
            ));
        }
        let doc = resolver.resolve(&claims.iss).await?;
        jwt.verify(doc.authentication_key(&kid)?)?;
        claims.in_force(crate::message::now())?;
        Ok((claims, kid))
    }

    /// Refuses a rotation whose `exp` has passed or whose `nbf` has not
    /// come, give or take [`Self::LEEWAY_SECS`] of clock difference.
    fn in_force(&self, now: u64) -> Result<()> {
        if self
            .exp
            .is_some_and(|exp| exp.saturating_add(Self::LEEWAY_SECS) < now)
        {
            return Err(Error::malformed("from_prior has expired"));
        }
        if self
            .nbf
            .is_some_and(|nbf| nbf > now.saturating_add(Self::LEEWAY_SECS))
        {
            return Err(Error::malformed("from_prior is not valid yet"));
        }
        Ok(())
    }

    /// Clock difference allowed on `exp` and `nbf`.
    const LEEWAY_SECS: u64 = 300;

    fn check(&self) -> Result<()> {
        if self.iss == self.sub {
            return Err(Error::malformed("from_prior iss and sub are the same DID"));
        }
        if did_of(&self.iss) != self.iss || did_of(&self.sub) != self.sub {
            return Err(Error::malformed("from_prior iss and sub must be DIDs"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rotation_is_taken_only_while_in_force() {
        let mut claims = FromPrior::new("did:example:old", "did:example:new");
        assert!(claims.in_force(1_000).is_ok());
        claims.exp = Some(1_000);
        assert!(claims.in_force(1_000 + FromPrior::LEEWAY_SECS).is_ok());
        assert!(claims.in_force(1_001 + FromPrior::LEEWAY_SECS).is_err());
        claims.exp = Some(u64::MAX);
        claims.nbf = Some(10_000);
        assert!(claims.in_force(10_000 - FromPrior::LEEWAY_SECS).is_ok());
        assert!(claims.in_force(9_999 - FromPrior::LEEWAY_SECS).is_err());
    }
}
