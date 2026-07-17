use bech32::{Bech32m, Hrp};
use k256::schnorr::SigningKey;
use sha2::Digest;

use crate::curve::Curve;
use crate::hd::DerivedKey;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use crate::zeroizing::SecretBytes;
use ows_core::ChainType;

/// Midnight network selection. Each network uses the same keys but
/// network-specific Bech32m HRPs for unshielded and shielded addresses
/// (the dust HRP is network-agnostic).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MidnightNetwork {
    Mainnet,
    Preview,
    Preprod,
}

impl MidnightNetwork {
    fn unshielded_hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "mn_addr",
            Self::Preview => "mn_addr_preview",
            Self::Preprod => "mn_addr_preprod",
        }
    }

}

/// Midnight signing support.
///
/// Implements the unshielded (Night) address as specified in the Midnight
/// WalletEngine specification, plus the multi-role bundle plumbing
/// (`default_derivation_paths`, `encode_keys`, `decode_keys`) that lets the
/// shielded (Zswap) and dust roles ride the single-key signing channel.
pub struct MidnightSigner {
    network: MidnightNetwork,
}

/// Midnight role seeds decoded from a [`MidnightSigner::encode_keys`] signing key.
pub struct MidnightSeeds {
    pub unshielded: SecretBytes,
    pub shielded: SecretBytes,
    pub dust: SecretBytes,
}

impl MidnightSigner {
    /// SLIP-44 coin type for Midnight.
    const COIN_TYPE: u32 = 2400;
    /// BIP-44 hardened account. OWS uses one account per wallet (single-address
    /// model), so this is fixed; per-address selection is the address index.
    const DEFAULT_ACCOUNT: u32 = 0;
    /// WalletEngine roles under `m/44'/COIN_TYPE'/DEFAULT_ACCOUNT'/role/index`.
    const ROLE_UNSHIELDED: u32 = 0;
    const ROLE_DUST: u32 = 2;
    const ROLE_SHIELDED: u32 = 3;

    /// Magic prefix tagging a packed Midnight signing key, so arbitrary bytes
    /// (e.g. a raw-imported private key) aren't silently split into role seeds.
    const SIGNING_KEY_MAGIC: &[u8] = b"MNK1";

    pub fn mainnet() -> Self {
        Self {
            network: MidnightNetwork::Mainnet,
        }
    }

    pub fn preview() -> Self {
        Self {
            network: MidnightNetwork::Preview,
        }
    }

    pub fn preprod() -> Self {
        Self {
            network: MidnightNetwork::Preprod,
        }
    }

    /// Resolve a network from a CAIP-2 chain id. Panics on an unrecognized id:
    /// `signer_for_chain` only builds this from a registered Midnight `Chain`, so
    /// an unknown id here is a registry/programming error, never user input — and
    /// silently defaulting to mainnet would mint wrong-but-valid-looking addresses.
    pub fn from_chain_id(chain_id: &str) -> Self {
        if chain_id.eq_ignore_ascii_case("midnight:mainnet") {
            Self::mainnet()
        } else if chain_id.eq_ignore_ascii_case("midnight:preview") {
            Self::preview()
        } else if chain_id.eq_ignore_ascii_case("midnight:preprod") {
            Self::preprod()
        } else {
            panic!("unsupported Midnight chain id: {chain_id}")
        }
    }

    /// Build a Wallet SDK derivation path for a `role` and address `index`.
    /// The coin type and hardened account live here as the single source of truth.
    fn derivation_path(role: u32, index: u32) -> String {
        let (coin, account) = (Self::COIN_TYPE, Self::DEFAULT_ACCOUNT);
        format!("m/44'/{coin}'/{account}'/{role}/{index}")
    }

    /// Extract the WalletEngine role from a Midnight derivation path
    /// (`m/44'/{coin}'/{account}'/{role}/{index}`) — the 5th segment. Inverse of
    /// the `role` embedded by [`Self::derivation_path`].
    fn role_from_path(path: &str) -> Option<u32> {
        path.split('/').nth(4).and_then(|s| s.parse().ok())
    }

    /// Resolve the 32-byte seed for `role` from a derived-key bundle. Returns a
    /// borrow — nothing is copied — so the caller can validate every role before
    /// building any owned secret buffer.
    fn seed_for_role(keys: &[DerivedKey], role: u32) -> Result<&[u8], SignerError> {
        let key = keys
            .iter()
            .find(|k| Self::role_from_path(&k.path) == Some(role))
            .ok_or_else(|| {
                SignerError::InvalidPrivateKey(format!("missing Midnight role {role} seed"))
            })?;
        let seed = key.secret.expose();
        if seed.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32-byte Midnight seed for role {role}, got {} bytes",
                seed.len()
            )));
        }
        Ok(seed)
    }

    /// Decode the `signing_key` produced by [`Self::encode_keys`] (i.e. what
    /// ows-lib's `secret_to_signing_key` hands back for Midnight) into the
    /// three role seeds.
    ///
    /// Layout: [`Self::SIGNING_KEY_MAGIC`] followed by the three 32-byte seeds
    /// concatenated in `default_derivation_paths` order — `MAGIC || unshielded ||
    /// shielded || dust`; split back here by position. The magic guards against
    /// decoding arbitrary bytes (e.g. a raw-imported key) as role seeds.
    pub fn decode_keys(signing_key: &[u8]) -> Result<MidnightSeeds, SignerError> {
        let seeds = signing_key
            .strip_prefix(Self::SIGNING_KEY_MAGIC)
            .filter(|rest| rest.len() == 96)
            .ok_or_else(|| {
                SignerError::InvalidPrivateKey(format!(
                    "not a Midnight signing key: expected {}-byte magic + three 32-byte seeds, got {} bytes",
                    Self::SIGNING_KEY_MAGIC.len(),
                    signing_key.len()
                ))
            })?;
        Ok(MidnightSeeds {
            unshielded: SecretBytes::from_slice(&seeds[..32]),
            shielded: SecretBytes::from_slice(&seeds[32..64]),
            dust: SecretBytes::from_slice(&seeds[64..]),
        })
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32-byte secp256k1 key, got {} bytes",
                private_key.len()
            )));
        }
        SigningKey::from_bytes(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(format!("invalid secp256k1 key: {e}")))
    }

    fn bech32m_encode(hrp: &str, payload: &[u8]) -> Result<String, SignerError> {
        let hrp = Hrp::parse(hrp)
            .map_err(|e| SignerError::AddressDerivationFailed(format!("invalid hrp: {e}")))?;
        bech32::encode::<Bech32m>(hrp, payload)
            .map_err(|e| SignerError::AddressDerivationFailed(format!("bech32m encode: {e}")))
    }

    fn derive_unshielded_address_with_hrp(
        &self,
        private_key: &[u8],
        hrp: &str,
    ) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let pk_xonly = sk.verifying_key().to_bytes(); // 32-byte BIP-340 x-only schnorr pubkey
        let hash = sha2::Sha256::digest(pk_xonly);
        Self::bech32m_encode(hrp, &hash)
    }

}

impl ChainSigner for MidnightSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Midnight
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        Self::COIN_TYPE
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        self.derive_unshielded_address_with_hrp(private_key, self.network.unshielded_hrp())
    }

    fn sign(&self, _private_key: &[u8], _message: &[u8]) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed(
            "Midnight signing is not implemented yet".into(),
        ))
    }

    fn sign_message(
        &self,
        _private_key: &[u8],
        _message: &[u8],
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed(
            "Midnight message signing is not implemented yet".into(),
        ))
    }

    fn sign_transaction(
        &self,
        _private_key: &[u8],
        _tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed(
            "Midnight transaction signing is not implemented yet".into(),
        ))
    }

    fn default_derivation_path(&self, index: u32) -> String {
        Self::derivation_path(Self::ROLE_UNSHIELDED, index)
    }

    fn default_derivation_paths(&self, index: u32) -> Vec<String> {
        // One key per Midnight role; the unshielded role is primary (address /
        // signing). Consumers tell the roles apart by the path on each DerivedKey.
        [Self::ROLE_UNSHIELDED, Self::ROLE_SHIELDED, Self::ROLE_DUST]
            .into_iter()
            .map(|role| Self::derivation_path(role, index))
            .collect()
    }

    /// Pack the three role seeds into one signing key so the single-key signing
    /// channel can carry all of Midnight's keys. Layout: [`Self::SIGNING_KEY_MAGIC`]
    /// followed by the seeds in canonical role order — `MAGIC || unshielded ||
    /// shielded || dust`; [`Self::decode_keys`] is the inverse.
    fn encode_keys(&self, keys: &[DerivedKey]) -> Result<SecretBytes, SignerError> {
        // Resolve + length-check all three seeds first (these are borrows — no
        // owned secret buffer exists yet), looking each up by its path role so the
        // packed order is independent of the order the keys arrive in. Then
        // concatenate with no error path left, so a partially-filled buffer can
        // never drop un-zeroed; on success the buffer becomes the SecretBytes.
        let unshielded = Self::seed_for_role(keys, Self::ROLE_UNSHIELDED)?;
        let shielded = Self::seed_for_role(keys, Self::ROLE_SHIELDED)?;
        let dust = Self::seed_for_role(keys, Self::ROLE_DUST)?;

        let mut blob = Vec::with_capacity(Self::SIGNING_KEY_MAGIC.len() + 96);
        blob.extend_from_slice(Self::SIGNING_KEY_MAGIC);
        blob.extend_from_slice(unshielded);
        blob.extend_from_slice(shielded);
        blob.extend_from_slice(dust);
        Ok(SecretBytes::new(blob))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unshielded role 0 seed for the abandon-phrase wallet at index 0
    // (path m/44'/2400'/0'/0/0). Hardcoded so tests don't depend on
    // HdDeriver / Mnemonic — matches the EVM / Bitcoin / etc. signer
    // test pattern.
    const UNSHIELDED_KEY_HEX: &str =
        "822fa63c57f6317cd51d12d80f0e64c2bc2164088dec1c71ca34a87a890190aa";

    fn unshielded_key() -> Vec<u8> {
        hex::decode(UNSHIELDED_KEY_HEX).unwrap()
    }

    #[test]
    fn midnight_unshielded_mainnet_address_vector() {
        let signer = MidnightSigner::mainnet();
        let key = unshielded_key();
        assert_eq!(
            signer.derive_address(&key).unwrap(),
            "mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"
        );
    }

    // Role seeds for the abandon-phrase wallet at index 0
    // (paths m/44'/2400'/0'/{0,3,2}/0). Hardcoded so the round-trip test
    // doesn't depend on HdDeriver / Mnemonic — matches the pattern other
    // signers use.
    const SHIELDED_KEY_HEX: &str =
        "92933dd3dff04c57c9f8950d6e08bd5c6f295655c03627a658e09b0726558cad";
    const DUST_KEY_HEX: &str = "7bb19a43ffccad92ca25d52dac163c92967b53ff17dda1bbf9061db6a47b09b2";

    #[test]
    fn encode_decode_keys_round_trip() {
        let signer = MidnightSigner::mainnet();
        let bundle: Vec<DerivedKey> = signer
            .default_derivation_paths(0)
            .into_iter()
            .zip([UNSHIELDED_KEY_HEX, SHIELDED_KEY_HEX, DUST_KEY_HEX])
            .map(|(path, seed_hex)| DerivedKey {
                path,
                secret: SecretBytes::from_slice(&hex::decode(seed_hex).unwrap()),
            })
            .collect();

        let signing_key = signer.encode_keys(&bundle).unwrap();
        let seeds = MidnightSigner::decode_keys(signing_key.expose()).unwrap();

        // Bundle order matches default_derivation_paths: [unshielded, shielded, dust].
        assert_eq!(seeds.unshielded.expose(), bundle[0].secret.expose());
        assert_eq!(seeds.shielded.expose(), bundle[1].secret.expose());
        assert_eq!(seeds.dust.expose(), bundle[2].secret.expose());
    }

    #[test]
    fn encode_keys_concatenates_seeds_in_order() {
        // Pin the wire layout: the three seeds concatenated raw in
        // default_derivation_paths order (unshielded || shielded || dust). A
        // regression here also breaks decode_keys and every downstream consumer.
        let signer = MidnightSigner::mainnet();
        let bundle: Vec<DerivedKey> = signer
            .default_derivation_paths(0)
            .into_iter()
            .zip([UNSHIELDED_KEY_HEX, SHIELDED_KEY_HEX, DUST_KEY_HEX])
            .map(|(path, seed_hex)| DerivedKey {
                path,
                secret: SecretBytes::from_slice(&hex::decode(seed_hex).unwrap()),
            })
            .collect();
        let signing_key = signer.encode_keys(&bundle).unwrap();
        assert_eq!(signing_key.expose(), signing_key_blob().as_slice());
    }

    // The Midnight signing key for the abandon-phrase wallet at index 0 — magic
    // prefix + the three role seeds in default_derivation_paths order, exactly
    // what encode_keys / ows-lib's secret_to_signing_key hands out.
    fn signing_key_blob() -> Vec<u8> {
        let mut blob = MidnightSigner::SIGNING_KEY_MAGIC.to_vec();
        for h in [UNSHIELDED_KEY_HEX, SHIELDED_KEY_HEX, DUST_KEY_HEX] {
            blob.extend_from_slice(&hex::decode(h).unwrap());
        }
        blob
    }

    #[test]
    fn midnight_preview_unshielded_address_uses_preview_hrp() {
        let addr = MidnightSigner::preview()
            .derive_address(&unshielded_key())
            .unwrap();
        assert!(addr.starts_with("mn_addr_preview1"));
    }

    #[test]
    fn midnight_from_chain_id_maps_networks() {
        assert_eq!(
            MidnightSigner::from_chain_id("midnight:mainnet").network,
            MidnightNetwork::Mainnet
        );
        assert_eq!(
            MidnightSigner::from_chain_id("midnight:preview").network,
            MidnightNetwork::Preview
        );
        assert_eq!(
            MidnightSigner::from_chain_id("midnight:preprod").network,
            MidnightNetwork::Preprod
        );
    }

    #[test]
    #[should_panic(expected = "unsupported Midnight chain id")]
    fn midnight_from_chain_id_panics_on_unknown() {
        // No silent mainnet fallback: an unregistered id is a programming error.
        let _ = MidnightSigner::from_chain_id("midnight:bogus");
    }

    #[test]
    fn midnight_decode_keys_rejects_non_midnight_blobs() {
        // Needs the magic prefix plus exactly three 32-byte seeds.
        assert!(MidnightSigner::decode_keys(&[0u8; 100]).is_err()); // right length, no magic
        let mut short = signing_key_blob();
        short.pop(); // magic present, one seed byte missing
        assert!(MidnightSigner::decode_keys(&short).is_err());
        assert!(MidnightSigner::decode_keys(b"too short").is_err());
    }

    #[test]
    fn midnight_default_paths_lists_three_roles() {
        let signer = MidnightSigner::mainnet();
        let paths = signer.default_derivation_paths(0);
        assert_eq!(
            paths,
            vec![
                "m/44'/2400'/0'/0/0".to_string(), // unshielded (role 0)
                "m/44'/2400'/0'/3/0".to_string(), // shielded (role 3)
                "m/44'/2400'/0'/2/0".to_string(), // dust (role 2)
            ]
        );
        // The primary (first) path matches the single-key default for the same index.
        assert_eq!(paths[0], signer.default_derivation_path(0));
    }
}
