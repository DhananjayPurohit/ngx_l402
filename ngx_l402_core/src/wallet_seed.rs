//! Wallet-seed derivation — the Cashu / NUT-13 standard.
//!
//! Every Cashu proof the module stores is bound to the wallet seed derived here,
//! following the de-facto Cashu standard so a wallet is restorable in any NUT-13
//! wallet (nutshell, cashu-ts, cdk-cli, ...):
//!
//!   1. The backup artifact is a **BIP39 mnemonic** (12 or 24 English words).
//!   2. The 64-byte seed is `BIP39_to_seed(mnemonic, passphrase = "")`, i.e.
//!      `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048 rounds)`.
//!   3. `cdk` feeds that 64-byte seed to `Xpriv::new_master` (v00 keysets) or the
//!      `Cashu_KDF_HMAC_SHA256` KDF (v01) to derive deterministic secrets — see
//!      `cashu`'s `nut13.rs`.
//!
//! Changing the derivation (different passphrase, a non-BIP39 KDF, truncating the
//! seed) makes the *same* mnemonic yield a *different* seed and strands every
//! existing wallet. The golden vector below — a published BIP39 test vector —
//! exists to make such a change impossible to merge silently.

use bip39::Mnemonic;
use std::fmt;

/// Length, in bytes, of the wallet seed consumed by `cdk` wallets.
pub const WALLET_SEED_LEN: usize = 64;

/// The configured mnemonic was not a valid BIP39 phrase (bad word, wrong length,
/// or failed checksum), or generation was asked for an invalid word count.
/// Returned instead of silently producing a wrong/empty seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidMnemonic(String);

impl fmt::Display for InvalidMnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid BIP39 mnemonic: {}", self.0)
    }
}

impl std::error::Error for InvalidMnemonic {}

/// Derive the deterministic 64-byte Cashu wallet seed from a BIP39 mnemonic, per
/// NUT-13, using an empty passphrase. Surrounding whitespace is ignored and the
/// phrase is Unicode-normalized before validation.
///
/// **The derivation is a frozen contract.** Do not change the passphrase, the
/// KDF, or the output length without a deliberate, reviewed wallet-migration
/// plan — doing so strands every existing user's funds.
pub fn derive_wallet_seed(mnemonic: &str) -> Result<[u8; WALLET_SEED_LEN], InvalidMnemonic> {
    let parsed = Mnemonic::parse(mnemonic.trim()).map_err(|e| InvalidMnemonic(e.to_string()))?;
    // Empty passphrase == `to_seed("")`; `to_seed_normalized` needs no extra
    // crate feature and an empty passphrase needs no normalization.
    Ok(parsed.to_seed_normalized(""))
}

/// Generate a fresh English BIP39 mnemonic. `words` must be a valid BIP39 length
/// (12, 15, 18, 21, or 24). Used when no mnemonic is configured so the operator
/// gets a real, restorable backup phrase instead of an opaque random blob.
pub fn generate_mnemonic(words: usize) -> Result<String, InvalidMnemonic> {
    Mnemonic::generate(words)
        .map(|m| m.to_string())
        .map_err(|e| InvalidMnemonic(e.to_string()))
}

/// Return `true` if `mnemonic` is a parseable, checksum-valid BIP39 phrase. Used
/// at startup to fail closed on a misconfigured `CASHU_WALLET_MNEMONIC` rather
/// than silently starting an empty wallet over real funds.
pub fn is_valid_mnemonic(mnemonic: &str) -> bool {
    Mnemonic::parse(mnemonic.trim()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical BIP39 test vector: all-zero 128-bit entropy, the empty
    /// passphrase we use. The seed below was computed independently via
    /// PBKDF2-HMAC-SHA512 and cross-checked against the published
    /// "TREZOR"-passphrase spec vector (c55257c3…7463b04), so it pins our
    /// derivation against the BIP39 standard itself.
    const VECTOR_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const VECTOR_SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    #[test]
    fn derives_canonical_bip39_seed() {
        let seed = derive_wallet_seed(VECTOR_MNEMONIC).expect("valid mnemonic");
        assert_eq!(hex::encode(seed), VECTOR_SEED_HEX);
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            derive_wallet_seed(VECTOR_MNEMONIC).unwrap(),
            derive_wallet_seed(VECTOR_MNEMONIC).unwrap()
        );
    }

    #[test]
    fn seed_is_64_bytes() {
        assert_eq!(derive_wallet_seed(VECTOR_MNEMONIC).unwrap().len(), WALLET_SEED_LEN);
    }

    #[test]
    fn generated_mnemonic_round_trips() {
        let m = generate_mnemonic(12).expect("generate");
        assert_eq!(m.split_whitespace().count(), 12);
        assert!(is_valid_mnemonic(&m));
        assert!(derive_wallet_seed(&m).is_ok());
    }

    /// Different mnemonics must map to different wallets; a collision would let
    /// one operator's phrase unlock another's funds.
    #[test]
    fn distinct_mnemonics_yield_distinct_seeds() {
        let other = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_ne!(
            derive_wallet_seed(VECTOR_MNEMONIC).unwrap(),
            derive_wallet_seed(other).unwrap()
        );
    }

    /// Leading/trailing whitespace (e.g. a stray newline in an env var or the
    /// persisted file) must not select a different wallet.
    #[test]
    fn surrounding_whitespace_is_ignored() {
        let clean = derive_wallet_seed(VECTOR_MNEMONIC).unwrap();
        let padded = derive_wallet_seed(&format!("  {}\n", VECTOR_MNEMONIC)).unwrap();
        assert_eq!(clean, padded);
    }

    /// Invalid input must error, never silently produce a seed — that would
    /// quietly create a *different* empty wallet over the operator's funds.
    #[test]
    fn invalid_mnemonic_is_rejected() {
        assert!(derive_wallet_seed("").is_err());
        assert!(derive_wallet_seed("not a real mnemonic phrase at all").is_err());
        assert!(derive_wallet_seed("abandon abandon abandon").is_err()); // wrong length
        assert!(!is_valid_mnemonic(""));
        assert!(!is_valid_mnemonic("nonsense words here"));
    }

    /// Valid words in a valid length but with a wrong final word → checksum
    /// failure must be rejected (catches a single-word typo in a backup phrase).
    #[test]
    fn bad_checksum_is_rejected() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(derive_wallet_seed(bad).is_err());
        assert!(!is_valid_mnemonic(bad));
    }

    #[test]
    fn generates_valid_24_word_mnemonic() {
        let m = generate_mnemonic(24).expect("generate 24");
        assert_eq!(m.split_whitespace().count(), 24);
        assert!(derive_wallet_seed(&m).is_ok());
    }

    /// Fresh mnemonics must not repeat — proves the RNG is actually exercised.
    #[test]
    fn generated_mnemonics_are_unique() {
        assert_ne!(generate_mnemonic(12).unwrap(), generate_mnemonic(12).unwrap());
    }

    #[test]
    fn generate_rejects_invalid_word_count() {
        assert!(generate_mnemonic(13).is_err());
        assert!(generate_mnemonic(0).is_err());
    }

    #[test]
    fn is_valid_mnemonic_agrees_with_derive() {
        assert!(is_valid_mnemonic(VECTOR_MNEMONIC));
        assert!(derive_wallet_seed(VECTOR_MNEMONIC).is_ok());
    }
}
