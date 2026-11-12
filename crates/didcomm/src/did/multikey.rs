//! Multikey encoding: `z` + base58btc(multicodec varint || raw key), as used
//! by `did:key`, `did:peer` and `publicKeyMultibase`.

use crate::{Curve, Error, PublicKey, Result};

/// Multicodec code for each curve's public key.
fn codec(curve: Curve) -> u64 {
    match curve {
        Curve::Ed25519 => 0xed,
        Curve::X25519 => 0xec,
        Curve::P256 => 0x1200,
        Curve::P384 => 0x1201,
        Curve::P521 => 0x1202,
        Curve::Secp256k1 => 0xe7,
    }
}

fn curve(codec: u64) -> Result<Curve> {
    Ok(match codec {
        0xed => Curve::Ed25519,
        0xec => Curve::X25519,
        0x1200 => Curve::P256,
        0x1201 => Curve::P384,
        0x1202 => Curve::P521,
        0xe7 => Curve::Secp256k1,
        other => return Err(Error::unsupported(format!("multicodec 0x{other:x}"))),
    })
}

pub(crate) fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub(crate) fn decode_varint(bytes: &[u8]) -> Result<(u64, &[u8])> {
    let mut value = 0u64;
    for (i, byte) in bytes.iter().enumerate().take(9) {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value, &bytes[i + 1..]));
        }
    }
    Err(Error::malformed("multicodec varint"))
}

/// Longest base58btc text decoded: decoding takes time that grows with the
/// square of its length, and the text often comes from a stranger's DID. A
/// key is about 50 characters; a long-form `did:peer:4` document a few
/// hundred to a few thousand.
pub(crate) const MAX_BASE58_CHARS: usize = 8 * 1024;

/// Decodes a multibase base58btc (`z…`) string.
pub(crate) fn decode_base58btc(text: &str) -> Result<Vec<u8>> {
    let body = text
        .strip_prefix('z')
        .ok_or_else(|| Error::unsupported("multibase other than base58btc"))?;
    if body.len() > MAX_BASE58_CHARS {
        return Err(Error::malformed("base58btc text too long"));
    }
    bs58::decode(body)
        .into_vec()
        .map_err(|_| Error::malformed("base58btc"))
}

pub(crate) fn encode_base58btc(bytes: &[u8]) -> String {
    format!("z{}", bs58::encode(bytes).into_string())
}

/// Encodes a public key as a Multikey string (EC points compressed).
pub fn encode(key: &PublicKey) -> String {
    let mut bytes = Vec::new();
    encode_varint(codec(key.curve()), &mut bytes);
    bytes.extend_from_slice(&key.to_bytes());
    encode_base58btc(&bytes)
}

/// Decodes a Multikey string.
pub fn decode(text: &str) -> Result<PublicKey> {
    let bytes = decode_base58btc(text)?;
    let (codec, key) = decode_varint(&bytes)?;
    PublicKey::from_bytes(curve(codec)?, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;

    #[test]
    fn round_trips() {
        for curve in [
            Curve::Ed25519,
            Curve::X25519,
            Curve::P256,
            Curve::P384,
            Curve::P521,
            Curve::Secp256k1,
        ] {
            let key = SecretKey::generate(curve).unwrap().public_key();
            assert_eq!(decode(&encode(&key)).unwrap(), key);
        }
    }

    #[test]
    fn overlong_base58_is_not_decoded() {
        let long = format!("z{}", "2".repeat(MAX_BASE58_CHARS + 1));
        assert!(decode_base58btc(&long).is_err());
        let fits = format!("z{}", "2".repeat(64));
        assert!(decode_base58btc(&fits).is_ok());
    }

    #[test]
    fn known_prefixes() {
        let ed = SecretKey::generate(Curve::Ed25519).unwrap().public_key();
        let x = SecretKey::generate(Curve::X25519).unwrap().public_key();
        assert!(encode(&ed).starts_with("z6Mk"));
        assert!(encode(&x).starts_with("z6LS"));
    }
}
