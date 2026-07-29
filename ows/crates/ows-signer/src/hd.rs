use crate::curve::Curve;
use crate::mnemonic::Mnemonic;
use crate::zeroizing::SecretBytes;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

const HARDENED_THRESHOLD: u32 = 0x80000000;

/// Errors from HD key derivation.
#[derive(Debug, thiserror::Error)]
pub enum HdError {
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    #[error("derivation failed: {0}")]
    DerivationFailed(String),

    #[error("ed25519 requires hardened-only derivation")]
    Ed25519NonHardened,

    #[error("invalid seed length: expected 16-64 bytes, got {0}")]
    InvalidSeedLength(usize),
}

/// HD key deriver supporting BIP-32 (secp256k1), SLIP-10 (ed25519), and Ed25519-BIP32.
pub struct HdDeriver;

impl HdDeriver {
    /// Derive a child private key from a seed and derivation path.
    ///
    /// Seed must be 16-64 bytes (BIP-32 §2) for secp256k1 and ed25519, and 96 bytes for ed25519-bip32.
    /// For Ed25519-BIP32, the seed must be the master extended private key.
    pub fn derive(seed: &[u8], path: &str, curve: Curve) -> Result<SecretBytes, HdError> {
        if curve != Curve::Ed25519Bip32 && (seed.len() < 16 || seed.len() > 64) {
            return Err(HdError::InvalidSeedLength(seed.len()));
        }
        Self::validate_path(path)?;

        match curve {
            Curve::Secp256k1 => Self::derive_secp256k1(seed, path),
            Curve::Ed25519 => Self::derive_ed25519(seed, path),
            Curve::Ed25519Bip32 => {
                if seed.len() != ed25519_bip32::XPRV_SIZE {
                    return Err(HdError::InvalidSeedLength(seed.len()));
                }

                Self::derive_ed25519_bip32(seed, path)
            }
        }
    }

    /// Convenience: derive from a mnemonic + passphrase + path + curve.
    pub fn derive_from_mnemonic(
        mnemonic: &Mnemonic,
        passphrase: &str,
        path: &str,
        curve: Curve,
    ) -> Result<SecretBytes, HdError> {
        match curve {
            Curve::Ed25519Bip32 => {
                let entropy = mnemonic.entropy();
                let seed = Self::ed25519_bip32_master_xprv_from_entropy(entropy.expose());
                Self::derive(seed.as_ref(), path, curve)
            }
            _ => {
                let seed = mnemonic.to_seed(passphrase);
                Self::derive(seed.expose(), path, curve)
            }
        }
    }

    /// Like `derive_from_mnemonic`, but checks the global key cache first.
    /// On cache miss, derives the key and inserts it into the cache.
    pub fn derive_from_mnemonic_cached(
        mnemonic: &Mnemonic,
        passphrase: &str,
        path: &str,
        curve: Curve,
    ) -> Result<SecretBytes, HdError> {
        use digest::Digest;

        // Build a cache key by hashing all inputs (avoids storing sensitive material in the key).
        let phrase = mnemonic.phrase();
        let mut hasher = sha2::Sha256::new();
        hasher.update(phrase.expose());
        hasher.update(b":");
        hasher.update(passphrase.as_bytes());
        hasher.update(b":");
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(match curve {
            Curve::Secp256k1 => b"secp256k1" as &[u8],
            Curve::Ed25519 => b"ed25519",
            Curve::Ed25519Bip32 => b"ed25519_bip32",
        });
        let cache_key = hex::encode(hasher.finalize());

        let cache = crate::global_key_cache();
        if let Some(cached) = cache.get(&cache_key) {
            return Ok(cached);
        }

        let key = Self::derive_from_mnemonic(mnemonic, passphrase, path, curve)?;
        cache.insert(&cache_key, key.clone());
        Ok(key)
    }

    /// Derive one [`DerivedKey`] per path on the given `curve`, preserving order.
    ///
    /// The non-cached sibling of [`Self::derive_keys_from_mnemonic_cached`]:
    /// every path goes through the non-cached singular, so no derived secret is
    /// retained in the global key cache. Address derivation uses this — it only
    /// needs the public address, not to warm the cache — while the signing path
    /// uses the cached variant.
    pub fn derive_keys_from_mnemonic(
        mnemonic: &Mnemonic,
        passphrase: &str,
        paths: Vec<String>,
        curve: Curve,
    ) -> Result<Vec<DerivedKey>, HdError> {
        paths
            .into_iter()
            .map(|path| {
                let secret = Self::derive_from_mnemonic(mnemonic, passphrase, &path, curve)?;
                Ok(DerivedKey { path, secret })
            })
            .collect()
    }

    /// Derive one [`DerivedKey`] per path on the given `curve`, preserving order.
    ///
    /// Same interface as [`Self::derive_from_mnemonic_cached`] but plural in the
    /// path: every path goes through the cached singular under the hood, and the
    /// returned bundle pairs each secret with the path it came from so chains
    /// that bind several keys per account (e.g. Midnight) can tell roles apart
    /// by path instead of position.
    pub fn derive_keys_from_mnemonic_cached(
        mnemonic: &Mnemonic,
        passphrase: &str,
        paths: Vec<String>,
        curve: Curve,
    ) -> Result<Vec<DerivedKey>, HdError> {
        paths
            .into_iter()
            .map(|path| {
                let secret = Self::derive_from_mnemonic_cached(mnemonic, passphrase, &path, curve)?;
                Ok(DerivedKey { path, secret })
            })
            .collect()
    }

    /// Parse a derivation path into `(index, hardened)` pairs.
    ///
    /// The single parser behind [`Self::validate_path`] and the per-curve derivation
    /// functions, so every curve agrees on what a path means. `"m"` yields no components.
    fn parse_path_components(path: &str) -> Result<Vec<(u32, bool)>, HdError> {
        if path == "m" {
            return Ok(vec![]);
        }
        if !path.starts_with("m/") {
            return Err(HdError::InvalidPath(format!(
                "path must start with 'm/', got '{}'",
                path
            )));
        }
        path[2..]
            .split('/')
            .map(|component| {
                let (index_str, hardened) = match component.strip_suffix('\'') {
                    Some(stripped) => (stripped, true),
                    None => (component, false),
                };
                if index_str.is_empty() {
                    return Err(HdError::InvalidPath(format!(
                        "empty component in path '{}'",
                        path
                    )));
                }
                let index: u32 = index_str.parse().map_err(|_| {
                    HdError::InvalidPath(format!(
                        "invalid index '{}' in path '{}'",
                        component, path
                    ))
                })?;
                if index >= HARDENED_THRESHOLD {
                    return Err(HdError::InvalidPath(format!(
                        "index '{}' in path '{}' must be below {}",
                        component, path, HARDENED_THRESHOLD
                    )));
                }
                Ok((index, hardened))
            })
            .collect()
    }

    /// Validate a derivation path. Must start with "m/" and contain valid indices.
    pub fn validate_path(path: &str) -> Result<(), HdError> {
        Self::parse_path_components(path).map(|_| ())
    }

    /// BIP-32 derivation for secp256k1 using coins-bip32.
    fn derive_secp256k1(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        use coins_bip32::derived::DerivedXPriv;
        use coins_bip32::xkeys::Parent;
        use std::str::FromStr;

        let xpriv = DerivedXPriv::root_from_seed(seed, None)
            .map_err(|e| HdError::DerivationFailed(e.to_string()))?;

        let derivation_path = coins_bip32::path::DerivationPath::from_str(path)
            .map_err(|e| HdError::InvalidPath(e.to_string()))?;

        let derived = xpriv
            .derive_path(&derivation_path)
            .map_err(|e: coins_bip32::Bip32Error| HdError::DerivationFailed(e.to_string()))?;

        let signing_key: &k256::ecdsa::SigningKey = derived.as_ref();
        let key_bytes = signing_key.to_bytes();
        Ok(SecretBytes::new(key_bytes.to_vec()))
    }

    /// SLIP-10 derivation for ed25519 (hardened-only, HMAC-SHA512 chain).
    fn derive_ed25519(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        use zeroize::Zeroize;

        // Parse path components (hardened only)
        let components = Self::parse_path_components(path)?;
        if components.iter().any(|(_, hardened)| !hardened) {
            return Err(HdError::Ed25519NonHardened);
        }

        // SLIP-10: Master key generation
        type HmacSha512 = Hmac<Sha512>;
        let mut mac =
            HmacSha512::new_from_slice(b"ed25519 seed").expect("HMAC can take key of any size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut key = result[..32].to_vec();
        let mut chain_code = result[32..].to_vec();

        // Derive each component (hardened only)
        let mut data = Vec::new();
        for (index, _) in components {
            // `parse_path_components` bounds `index` below HARDENED_THRESHOLD, so this cannot overflow
            let child_index = index.checked_add(HARDENED_THRESHOLD).ok_or_else(|| {
                HdError::InvalidPath(format!("invalid hardened index: {}", index))
            })?;

            data.zeroize();
            data.clear();
            data.push(0u8); // 0x00 prefix for private key derivation
            data.extend_from_slice(&key);
            data.extend_from_slice(&child_index.to_be_bytes());

            let mut mac =
                HmacSha512::new_from_slice(&chain_code).expect("HMAC can take key of any size");
            mac.update(&data);
            let result = mac.finalize().into_bytes();

            key.zeroize();
            chain_code.zeroize();
            key = result[..32].to_vec();
            chain_code = result[32..].to_vec();
        }

        data.zeroize();
        chain_code.zeroize();
        Ok(SecretBytes::new(key))
    }

    /// Build the Ed25519-BIP32 master extended private key (96-byte `XPrv`) from raw BIP-39 entropy
    fn ed25519_bip32_master_xprv_from_entropy(
        entropy: &[u8],
    ) -> Zeroizing<[u8; ed25519_bip32::XPRV_SIZE]> {
        let mut out = Zeroizing::new([0u8; ed25519_bip32::XPRV_SIZE]);
        // password slot stays empty on purpose to keep compatibility with Cardano software wallets
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>("".as_bytes(), entropy, 4096, out.as_mut());
        Zeroizing::new(ed25519_bip32::XPrv::normalize_bytes_force3rd(*out).into())
    }

    /// Ed25519-BIP32 path derivation (V2) from an existing seed (master extended private key).
    fn derive_ed25519_bip32(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        let mut xprv = ed25519_bip32::XPrv::from_slice_verified(seed)
            .map_err(|e| HdError::DerivationFailed(e.to_string()))?;

        for (index, hardened) in Self::parse_path_components(path)? {
            // `parse_path_components` bounds `index` below HARDENED_THRESHOLD, so this cannot overflow
            let child_index = if hardened {
                index.checked_add(HARDENED_THRESHOLD).ok_or_else(|| {
                    HdError::InvalidPath(format!("invalid hardened index: {}", index))
                })?
            } else {
                index
            };
            xprv = xprv.derive(ed25519_bip32::DerivationScheme::V2, child_index);
        }
        Ok(SecretBytes::new(xprv.as_ref().to_vec()))
    }
}

/// A derived secret paired with the path it was derived from.
///
/// Most chains bind one key per account; chains that bind several (e.g.
/// Midnight's unshielded / shielded / dust roles) get one `DerivedKey` per
/// path, and the carried `path` is what tells them apart — callers select a
/// key by its path, not by position in the bundle. The first entry is the
/// primary (address / signing) key.
pub struct DerivedKey {
    pub path: String,
    pub secret: SecretBytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_seed() -> SecretBytes {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        mnemonic.to_seed("")
    }

    #[test]
    fn test_derive_evm_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_solana_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/501'/0'/0'", Curve::Ed25519).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_bitcoin_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/84'/0'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_cosmos_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/118'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_tron_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/195'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_convenience_matches_two_step() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let seed = mnemonic.to_seed("");

        let key1 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key2 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();

        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_path_validation_valid() {
        assert!(HdDeriver::validate_path("m/44'/60'/0'/0/0").is_ok());
        assert!(HdDeriver::validate_path("m/44'/501'/0'/0'").is_ok());
        assert!(HdDeriver::validate_path("m").is_ok());
    }

    #[test]
    fn test_path_validation_invalid() {
        assert!(HdDeriver::validate_path("44'/60'/0'/0/0").is_err());
        assert!(HdDeriver::validate_path("").is_err());
        assert!(HdDeriver::validate_path("x/44'/60'").is_err());
    }

    #[test]
    fn test_path_validation_rejects_index_at_or_above_hardened_threshold() {
        // A bare 2147483648 would alias the hardened 0' (both are child index 0x80000000),
        // and 2147483648' would overflow the hardening offset.
        for path in [
            "m/2147483648",
            "m/2147483648'",
            "m/4294967295",
            "m/44'/0/2147483648",
        ] {
            assert!(
                HdDeriver::validate_path(path).is_err(),
                "expected '{path}' to be rejected"
            );
        }
        // The largest legal index is still accepted.
        assert!(HdDeriver::validate_path("m/2147483647'").is_ok());
        assert!(HdDeriver::validate_path("m/2147483647").is_ok());
    }

    #[test]
    fn test_path_validation_rejects_repeated_hardened_marker() {
        assert!(HdDeriver::validate_path("m/44''").is_err());
        assert!(HdDeriver::validate_path("m/44'/0''''").is_err());
    }

    #[test]
    fn test_derive_rejects_out_of_range_index_on_every_curve() {
        let seed = test_seed();
        let xprv = HdDeriver::ed25519_bip32_master_xprv_from_entropy(&[0u8; 32]);

        for path in ["m/2147483648", "m/2147483648'"] {
            for (curve, seed) in [
                (Curve::Secp256k1, seed.expose()),
                (Curve::Ed25519, seed.expose()),
                (Curve::Ed25519Bip32, &xprv[..]),
            ] {
                let err = HdDeriver::derive(seed, path, curve)
                    .expect_err("expected '{path}' on {curve:?} to be rejected");
                match err {
                    HdError::InvalidPath(_) => {}
                    other => {
                        panic!("expected InvalidPath for '{path}' on {curve:?}, got {other:?}")
                    }
                }
            }
        }
    }

    /// `m/2147483648` and `m/0'` are the same child index (0x80000000); rejecting the
    /// former is what keeps two spellings of one path from being two paths.
    #[test]
    fn test_ed25519_bip32_no_longer_aliases_hardened_zero() {
        let xprv = HdDeriver::ed25519_bip32_master_xprv_from_entropy(&[0u8; 32]);
        assert!(HdDeriver::derive(&xprv[..], "m/0'", Curve::Ed25519Bip32).is_ok());
        assert!(HdDeriver::derive(&xprv[..], "m/2147483648", Curve::Ed25519Bip32).is_err());
    }

    #[test]
    fn test_slip10_rejects_non_hardened_ed25519() {
        let seed = test_seed();
        let result = HdDeriver::derive(seed.expose(), "m/44'/501'/0'/0", Curve::Ed25519);
        assert!(result.is_err());
        match result.unwrap_err() {
            HdError::Ed25519NonHardened => {}
            other => panic!("expected Ed25519NonHardened, got {:?}", other),
        }
    }

    // === BIP-32 spec test vectors (secp256k1) ===
    // Source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors

    #[test]
    fn test_bip32_vector1_chain() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        let cases = [
            (
                "m/0'",
                "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            ),
            (
                "m/0'/1",
                "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            ),
            (
                "m/0'/1/2'",
                "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
            ),
            (
                "m/0'/1/2'/2",
                "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
            ),
            (
                "m/0'/1/2'/2/1000000000",
                "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive(&seed, path, Curve::Secp256k1)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "BIP-32 vector 1 mismatch at {}",
                path
            );
        }
    }

    #[test]
    fn test_bip32_vector2_chain() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        )
        .unwrap();

        let cases = [
            (
                "m/0",
                "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
            ),
            (
                "m/0/2147483647'",
                "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
            ),
            (
                "m/0/2147483647'/1",
                "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive(&seed, path, Curve::Secp256k1)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "BIP-32 vector 2 mismatch at {}",
                path
            );
        }
    }

    // === SLIP-10 spec test vectors (ed25519) ===
    // Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vectors

    #[test]
    fn test_slip10_vector1_chain() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        let cases = [
            (
                "m/0'",
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            ),
            (
                "m/0'/1'",
                "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
            ),
            (
                "m/0'/1'/2'",
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            ),
            (
                "m/0'/1'/2'/2'",
                "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
            ),
            (
                "m/0'/1'/2'/2'/1000000000'",
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive(&seed, path, Curve::Ed25519)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "SLIP-10 vector 1 mismatch at {}",
                path
            );
        }
    }

    #[test]
    fn test_slip10_vector2_chain() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        )
        .unwrap();

        let cases = [
            (
                "m/0'",
                "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
            ),
            (
                "m/0'/2147483647'",
                "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
            ),
            (
                "m/0'/2147483647'/1'",
                "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
            ),
            (
                "m/0'/2147483647'/1'/2147483646'",
                "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
            ),
            (
                "m/0'/2147483647'/1'/2147483646'/2'",
                "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive(&seed, path, Curve::Ed25519)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "SLIP-10 vector 2 mismatch at {}",
                path
            );
        }
    }

    // === Seed length validation ===

    #[test]
    fn test_seed_length_too_short() {
        let seed = [0u8; 15];
        let result = HdDeriver::derive(&seed, "m/0'", Curve::Secp256k1);
        assert!(matches!(result, Err(HdError::InvalidSeedLength(15))));
    }

    #[test]
    fn test_seed_length_too_long() {
        let seed = [0u8; 65];
        let result = HdDeriver::derive(&seed, "m/0'", Curve::Secp256k1);
        assert!(matches!(result, Err(HdError::InvalidSeedLength(65))));
    }

    #[test]
    fn test_seed_length_minimum_accepted() {
        let seed = [0u8; 16];
        assert!(HdDeriver::derive(&seed, "m/0'", Curve::Secp256k1).is_ok());
    }

    #[test]
    fn test_seed_length_maximum_accepted() {
        let seed = [0u8; 64];
        assert!(HdDeriver::derive(&seed, "m/0'", Curve::Secp256k1).is_ok());
    }

    // === Characterization tests: lock down current behavior before refactoring ===

    #[test]
    fn test_abandon_mnemonic_evm_address() {
        // Known test vector: "abandon" mnemonic → known EVM address
        // This address is well-documented across the ecosystem
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();

        // Derive the EVM address from the key
        let signer = crate::chains::EvmSigner;
        use crate::traits::ChainSigner;
        let address = signer.derive_address(key.expose()).unwrap();
        assert_eq!(
            address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "abandon mnemonic should derive to known EVM address"
        );
    }

    #[test]
    fn test_same_mnemonic_same_path_same_curve_same_key() {
        // Multiple independent derivations must produce identical results
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let path = "m/44'/60'/0'/0/0";
        let curve = Curve::Secp256k1;

        let key1 = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();
        let key2 = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();
        let key3 = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();

        assert_eq!(key1.expose(), key2.expose());
        assert_eq!(key2.expose(), key3.expose());
    }

    #[test]
    fn test_different_index_different_key_evm() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key0 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();
        let key1 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/1", Curve::Secp256k1)
                .unwrap();
        let key2 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/2", Curve::Secp256k1)
                .unwrap();

        assert_ne!(key0.expose(), key1.expose());
        assert_ne!(key1.expose(), key2.expose());
        assert_ne!(key0.expose(), key2.expose());
    }

    #[test]
    fn test_different_index_different_key_ed25519() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key0 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/501'/0'/0'", Curve::Ed25519)
                .unwrap();
        let key1 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/501'/1'/0'", Curve::Ed25519)
                .unwrap();

        assert_ne!(key0.expose(), key1.expose());
    }

    #[test]
    fn test_cached_derivation_matches_uncached() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let path = "m/44'/60'/0'/0/0";
        let curve = Curve::Secp256k1;

        let uncached = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();
        let cached = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", path, curve).unwrap();

        assert_eq!(uncached.expose(), cached.expose());
    }

    #[test]
    fn test_key_length_32_bytes_all_curves() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        let secp_key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();
        assert_eq!(secp_key.len(), 32);

        let ed_key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/501'/0'/0'", Curve::Ed25519)
                .unwrap();
        assert_eq!(ed_key.len(), 32);
    }

    #[test]
    fn test_deterministic() {
        let seed = test_seed();
        let key1 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key2 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_different_indices_different_keys() {
        let seed = test_seed();
        let key0 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key1 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/1", Curve::Secp256k1).unwrap();
        assert_ne!(key0.expose(), key1.expose());
    }

    // === Ed25519-BIP32 master key vectors (entropy + PBKDF2 root) ===

    #[test]
    fn test_ed25519_bip32_master() {
        let phrase = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", "m", Curve::Ed25519Bip32).unwrap();
        let expected = "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620";
        assert_eq!(hex::encode(key.expose()), expected);
        assert_eq!(key.len(), ed25519_bip32::XPRV_SIZE);
    }

    /// "abandon … about" (zero entropy) — root `XPrv` bytes.
    #[test]
    fn test_ed25519_bip32_abandon_mnemonic_root_vector() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", "m", Curve::Ed25519Bip32).unwrap();
        let expected = "60ce7dbec3616e9fc17e0c32578b3f380337b1b61a1f3cb9651aee30670e6f53970419a23a2e4e4082d12bf78faa8645dfc882cee2ae7179e2b07fe88098abb2072310084784c7308182dbbdb1449b2706586f1ff5cbf13d15e9b6e78c15f067";
        assert_eq!(hex::encode(key.expose()), expected);
    }

    // === Ed25519-BIP32 child derivation (V2) ===
    // Parent XPrv from ed25519-bip32 crate tests: src/tests.rs

    #[test]
    fn test_ed25519_bip32_derive_hardened_zero_from_test_vector_xprv() {
        // ed25519-bip32 0.4.1 `src/tests.rs` constants D1, D1_H0
        let d1_hex = "f8a29231ee38d6c5bf715d5bac21c750577aa3798b22d79d65bf97d6fadea15adcd1ee1abdf78bd4be64731a12deb94d3671784112eb6f364b871851fd1c9a247384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b331262eddfad0d";
        let d1_h0_hex = "60d399da83ef80d8d4f8d223239efdc2b8fef387e1b5219137ffb4e8fbdea15adc9366b7d003af37c11396de9a83734e30e05e851efa32745c9cd7b42712c890608763770eddf77248ab652984b21b849760d1da74a6f5bd633ce41adceef07a";

        let d1_bytes: [u8; ed25519_bip32::XPRV_SIZE] =
            hex::decode(d1_hex).unwrap().try_into().unwrap();
        let derived = HdDeriver::derive_ed25519_bip32(&d1_bytes, "m/0'").unwrap();
        assert_eq!(hex::encode(derived.expose()), d1_h0_hex);
    }

    #[test]
    fn test_derive_rejects_bip39_seed_for_ed25519_bip32() {
        let seed = test_seed();
        let r = HdDeriver::derive(seed.expose(), "m/0'", Curve::Ed25519Bip32);
        assert!(matches!(r, Err(HdError::InvalidSeedLength(64))));
    }

    #[test]
    fn test_derive_ed25519_bip32_from_master_xprv_matches_from_mnemonic() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let path = "m/1852'/1815'/0'/0/0";
        let from_mnemonic =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", path, Curve::Ed25519Bip32).unwrap();
        let master =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m", Curve::Ed25519Bip32).unwrap();
        let from_derive = HdDeriver::derive(master.expose(), path, Curve::Ed25519Bip32).unwrap();
        assert_eq!(from_mnemonic.expose(), from_derive.expose());
    }
}
