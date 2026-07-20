//! Shared serialization for the shielded on-disk snapshot: the zswap-state hex codec used by the
//! `vk_hidden` cursor snapshot. The seed fingerprint is computed by
//! `MidnightCryptoProvider::shielded_key_fingerprint`.

use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::db::InMemoryDB;
use midnight_zswap::local::State as ZswapLocalState;

/// Tagged-serialize the full spendable `ZswapLocalState` to hex for a snapshot.
pub(super) fn encode_zswap_state(
    state: &ZswapLocalState<InMemoryDB>,
) -> Result<String, std::io::Error> {
    let mut out = Vec::new();
    tagged_serialize(state, &mut out).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(hex::encode(out))
}

/// Decode a snapshot's `zswap_state_hex` back into a spendable `ZswapLocalState`. An empty string
/// means "no wallet persisted" and is an error, so a resume falls back to a fresh sync.
pub(super) fn decode_zswap_state(
    state_hex: &str,
) -> Result<ZswapLocalState<InMemoryDB>, std::io::Error> {
    let bytes = hex::decode(state_hex.strip_prefix("0x").unwrap_or(state_hex))
        .map_err(|e| std::io::Error::other(format!("invalid zswap state hex: {e}")))?;
    let mut reader: &[u8] = &bytes;
    tagged_deserialize(&mut reader)
        .map_err(|e| std::io::Error::other(format!("decode zswap state: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zswap_state_hex_roundtrips_through_snapshot_encoding() {
        let state = ZswapLocalState::<InMemoryDB>::new();
        let hex = encode_zswap_state(&state).expect("encode empty zswap state");
        let back = decode_zswap_state(&hex).expect("decode empty zswap state");
        assert_eq!(back.first_free, state.first_free);
        assert_eq!(back.coins.iter().count(), 0);
    }

    #[test]
    fn blank_state_hex_is_not_a_spendable_wallet() {
        // An empty `zswap_state_hex` means "no wallet persisted"; a resume must sync afresh
        // rather than treat the blank as a valid (empty-balance) state.
        assert!(decode_zswap_state("").is_err());
    }

    /// Pin that `MidnightCryptoProvider::shielded_key_fingerprint()` and the old local formula
    /// (SHA-256 of the shielded seed, first 16 bytes as hex) agree on the same value, so cached
    /// snapshots written under the old fingerprint stay valid.
    ///
    /// The old formula: `hex::encode(Sha256::digest(seed_32)[..16])`.
    /// The new formula: `hex::encode(&provider.shielded_key_fingerprint().unwrap()[..16])`.
    ///
    /// `shielded_key_fingerprint()` returns the full 32-byte SHA-256 digest; the snapshot code
    /// takes the first 16 bytes of that as a hex string — identical to the old formula.
    #[test]
    fn shielded_key_fingerprint_matches_old_sha256_formula() {
        use sha2::{Digest, Sha256};

        let shielded_seed = [0x11u8; 32]; // stable test seed
        let old_fp = hex::encode(Sha256::digest(shielded_seed)[..16].as_ref());

        // Build a packed signing key (MNK1 magic + unshielded + shielded + dust seeds).
        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&[0xAAu8; 32]); // unshielded seed (dummy)
        blob.extend_from_slice(&shielded_seed);
        blob.extend_from_slice(&[0xBBu8; 32]); // dust seed (dummy)
        let key = ows_signer::SecretBytes::new(blob);

        let provider = ows_signer::chains::MidnightSigner::mainnet()
            .crypto_provider(&key)
            .expect("build provider");
        let new_fp = hex::encode(&provider.shielded_key_fingerprint().expect("fingerprint")[..16]);

        assert_eq!(
            new_fp, old_fp,
            "provider fingerprint must match the old local SHA-256 formula"
        );
        // Golden value — pin it so this test catches any formula drift.
        assert_eq!(new_fp, "02d449a31fbb267c8f352e9968a79e3e");
    }
}
