//! P2PK (NUT-11 / NUT-12) key handling.
//!
//! In P2PK mode the module locks Cashu proofs to a public key and later signs
//! with the corresponding private key to melt them. If the public key we publish
//! (in NUT-18 payment requests) and the private key we sign with ever disagree,
//! the locked proofs become permanently unspendable. To make that impossible we
//! derive *both* from a single parse here, and pin the derivation with well-known
//! secp256k1 golden vectors.

use cdk::nuts::SecretKey;
use std::fmt;

/// The configured P2PK private key was not a valid secp256k1 secret key (bad
/// hex, wrong length, zero, or out of range). Returned instead of proceeding
/// with a key that cannot lock/unlock proofs.
#[derive(Debug, Clone)]
pub struct InvalidP2pkKey(String);

impl fmt::Display for InvalidP2pkKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid P2PK private key: {}", self.0)
    }
}

impl std::error::Error for InvalidP2pkKey {}

/// Parse a hex-encoded secp256k1 private key for Cashu P2PK and return both the
/// parsed key (kept for signing during melt) and its compressed public-key hex
/// (published in NUT-18 payment requests). Both come from the SAME parse so the
/// signing key and the locking public key can never disagree. Surrounding
/// whitespace is ignored.
pub fn parse_p2pk_secret_key(secret_hex: &str) -> Result<(SecretKey, String), InvalidP2pkKey> {
    let secret_key =
        SecretKey::from_hex(secret_hex.trim()).map_err(|e| InvalidP2pkKey(format!("{}", e)))?;
    let public_key_hex = secret_key.public_key().to_string();
    Ok((secret_key, public_key_hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Well-known secp256k1 vectors: a private key `k` maps to the compressed
    // public key of `k*G`. k = 1 is the generator point G; k = 2 is 2G. These are
    // stable across every correct secp256k1 implementation, so they pin both the
    // curve math and the compressed-hex encoding cdk uses for NUT-11.
    const PRIV_ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const PUB_ONE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const PRIV_TWO: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const PUB_TWO: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    #[test]
    fn derives_known_public_keys() {
        let (_, pub1) = parse_p2pk_secret_key(PRIV_ONE).expect("valid key");
        assert_eq!(pub1, PUB_ONE);
        let (_, pub2) = parse_p2pk_secret_key(PRIV_TWO).expect("valid key");
        assert_eq!(pub2, PUB_TWO);
    }

    #[test]
    fn public_key_is_33_byte_compressed_hex() {
        let (_, pubkey) = parse_p2pk_secret_key(PRIV_ONE).unwrap();
        assert_eq!(pubkey.len(), 66); // 33 bytes, hex-encoded
        assert!(pubkey.starts_with("02") || pubkey.starts_with("03"));
    }

    /// The returned signing key and the returned public key must always be
    /// consistent — this is the property that prevents unspendable locked proofs.
    #[test]
    fn returned_key_matches_returned_pubkey() {
        let (sk, pubkey) = parse_p2pk_secret_key(PRIV_ONE).unwrap();
        assert_eq!(sk.public_key().to_string(), pubkey);
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        let (_, a) = parse_p2pk_secret_key(PRIV_ONE).unwrap();
        let (_, b) = parse_p2pk_secret_key(&format!("  {}\n", PRIV_ONE)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn invalid_keys_are_rejected() {
        assert!(parse_p2pk_secret_key("").is_err());
        assert!(parse_p2pk_secret_key("xyz").is_err());
        assert!(parse_p2pk_secret_key("01").is_err()); // too short
        // Zero scalar is not a valid secp256k1 secret key.
        assert!(parse_p2pk_secret_key(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
        // A value >= the curve order n is invalid.
        assert!(parse_p2pk_secret_key(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        .is_err());
    }
}
