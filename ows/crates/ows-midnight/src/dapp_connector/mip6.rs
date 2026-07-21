//! MIP-0005 `zswapoffer` bech32 codec, used by `balanceSealedTransaction` to complete a maker's
//! swap offer supplied as a bare proven Zswap offer rather than a full transaction.
//!
//! (MIP-0006 offer-file JSON validation builds on this module.)

use bech32::Bech32m;
use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_ledger::structure::{ProofMarker, StandardTransaction, Transaction};
use midnight_serialize::{tagged_serialize, Deserializable as _};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::Offer as ZswapOffer;
use ows_signer::chains::MidnightSigner;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::Proof as ZswapProof;

use super::build::err;

/// A proven Zswap offer as carried in a maker swap (MIP-0005 wire form).
type ProvenZswapOffer = ZswapOffer<ZswapProof, InMemoryDB>;
type TxProven = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

/// MIP-0005 bech32 human-readable part for a bare Zswap offer (`zswapoffer1…` on the wire).
pub const ZSWAP_OFFER_BECH32_HRP: &str = "zswapoffer";

/// Default fallible segment for a bare `zswapoffer` offer that doesn't belong in the guaranteed
/// section (MIP-0005).
pub const DEFAULT_ZSWAP_OFFER_SEGMENT: u16 = 1;

/// Whether a proven Zswap offer belongs in the guaranteed section (segment 0). A pure-output offer
/// (a deposit, or a shielded swap carrying both inputs and outputs) is guaranteed; an inputs-only
/// offer (a withdraw whose coins settle later) is not.
pub(super) fn zswap_offer_belongs_in_guaranteed(offer: &ProvenZswapOffer) -> bool {
    let has_inputs = offer.inputs.iter_deref().next().is_some();
    let has_outputs = offer.outputs.iter_deref().next().is_some();
    let shielded_swap = has_inputs && has_outputs;
    has_outputs && (shielded_swap || !has_inputs)
}

/// Serialize a proven Zswap offer per MIP-0005 (raw ledger bytes, no tag prefix). The encode side of
/// the codec — currently only the round-trip tests exercise it (offers arrive already encoded).
#[cfg(test)]
pub(super) fn serialize_zswap_offer_raw(
    offer: &ProvenZswapOffer,
) -> Result<Vec<u8>, std::io::Error> {
    use midnight_serialize::Serializable as _;
    let mut buf = Vec::new();
    offer
        .serialize(&mut buf)
        .map_err(|e| err(format!("failed to serialize zswap offer: {e}")))?;
    Ok(buf)
}

/// Deserialize a proven Zswap offer from MIP-0005 raw ledger bytes (no tag prefix).
pub(super) fn deserialize_zswap_offer_raw(
    bytes: &[u8],
) -> Result<ProvenZswapOffer, std::io::Error> {
    let mut r: &[u8] = bytes;
    ProvenZswapOffer::deserialize(&mut r, 0)
        .map_err(|e| err(format!("failed to parse zswap offer: {e}")))
}

/// Encode a proven Zswap offer as MIP-0005 `zswapoffer…` bech32.
///
/// Uses the primitives encoder without the crate-level `bech32::encode` length cap: proven offers
/// (~10k+ raw bytes) exceed bech32's 90-character limit, which MIP-0005 requires implementations not
/// to enforce.
#[cfg(test)]
pub(super) fn encode_zswap_offer_bech32(
    offer: &ProvenZswapOffer,
) -> Result<String, std::io::Error> {
    use bech32::{ByteIterExt as _, Fe32IterExt as _, Hrp};
    let buf = serialize_zswap_offer_raw(offer)?;
    let hrp = Hrp::parse(ZSWAP_OFFER_BECH32_HRP)
        .map_err(|e| err(format!("invalid zswap offer HRP: {e}")))?;
    Ok(buf
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .chars()
        .collect())
}

/// Decode a MIP-0005 `zswapoffer…` bech32 string into a proven Zswap offer (no length cap).
pub(super) fn decode_zswap_offer_bech32(s: &str) -> Result<ProvenZswapOffer, std::io::Error> {
    use bech32::primitives::checksum;
    use bech32::primitives::decode::UncheckedHrpstring;
    use bech32::{Checksum, Fe32};

    let unchecked = UncheckedHrpstring::new(s.trim())
        .map_err(|e| err(format!("invalid zswap offer bech32: {e}")))?;
    if unchecked.hrp().as_str() != ZSWAP_OFFER_BECH32_HRP {
        return Err(err(format!(
            "expected zswapoffer bech32 HRP, got {}",
            unchecked.hrp().as_str()
        )));
    }
    // Verify the Bech32m checksum by hand — the crate's checked decoder enforces the 90-char cap
    // that MIP-0005 forbids, so we drive the checksum engine directly over the (large) data part.
    if Bech32m::CHECKSUM_LENGTH > 0 {
        if unchecked.data_part_ascii().len() < Bech32m::CHECKSUM_LENGTH {
            return Err(err(
                "invalid zswap offer bech32: data too short for checksum",
            ));
        }
        let mut eng = checksum::Engine::<Bech32m>::new();
        eng.input_hrp(unchecked.hrp());
        for &b in unchecked.data_part_ascii() {
            eng.input_fe(Fe32::from_char_unchecked(b));
        }
        if eng.residue() != &Bech32m::TARGET_RESIDUE {
            return Err(err("invalid zswap offer bech32 checksum"));
        }
    }
    let checked = unchecked.remove_checksum::<Bech32m>();
    let bytes: Vec<u8> = checked.byte_iter().collect();
    deserialize_zswap_offer_raw(&bytes)
}

/// Wrap a bare `zswapoffer` bech32 into proven zswap-only transaction bytes the balancing tail can
/// consume. The offer lands in the guaranteed section or the default fallible segment per its I/O
/// shape (see [`zswap_offer_belongs_in_guaranteed`]).
pub(super) fn wrap_zswap_offer_as_proven_tx(
    chain_id: &str,
    bech32_offer: &str,
) -> Result<Vec<u8>, std::io::Error> {
    let offer = decode_zswap_offer_bech32(bech32_offer)?;
    let (guaranteed_coins, fallible_coins) = if zswap_offer_belongs_in_guaranteed(&offer) {
        (Some(Sp::new(offer)), MnHashMap::new())
    } else {
        (
            None,
            MnHashMap::new().insert(DEFAULT_ZSWAP_OFFER_SEGMENT, offer),
        )
    };
    let stx = StandardTransaction {
        network_id: MidnightSigner::from_chain_id(chain_id)
            .ledger_network_id()
            .to_string(),
        intents: MnHashMap::new(),
        guaranteed_coins,
        fallible_coins,
        binding_randomness: Default::default(),
    };
    let tx: TxProven = Transaction::Standard(stx);
    let mut out = Vec::new();
    tagged_serialize(&tx, &mut out).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_storage::storage::Array;
    use midnight_zswap::Delta;

    /// A deltas-only Zswap offer (no proofs needed) — enough to exercise the codec and section-shape
    /// classification without building real ZK proofs.
    fn sample_offer(gives: i128, wants: i128) -> ProvenZswapOffer {
        let token_give = midnight_coin_structure::coin::ShieldedTokenType(
            midnight_base_crypto::hash::HashOutput([1u8; 32]),
        );
        let token_want = midnight_coin_structure::coin::ShieldedTokenType(
            midnight_base_crypto::hash::HashOutput([2u8; 32]),
        );
        let mut deltas = Vec::new();
        if gives != 0 {
            deltas.push(Delta {
                token_type: token_give,
                value: gives,
            });
        }
        if wants != 0 {
            deltas.push(Delta {
                token_type: token_want,
                value: -wants,
            });
        }
        ZswapOffer {
            inputs: Array::new(),
            outputs: Array::new(),
            transient: Array::new(),
            deltas: deltas.into(),
        }
    }

    #[test]
    fn zswapoffer_bech32_round_trips() {
        let offer = sample_offer(100, 50);
        let encoded = encode_zswap_offer_bech32(&offer).expect("encode");
        assert!(encoded.starts_with("zswapoffer1"));
        let decoded = decode_zswap_offer_bech32(&encoded).expect("decode");
        assert_eq!(
            decoded.deltas.iter_deref().count(),
            offer.deltas.iter_deref().count()
        );
    }

    #[test]
    fn decode_rejects_wrong_hrp_and_bad_checksum() {
        // A valid bech32m string under a different HRP is rejected.
        let other =
            bech32::encode::<Bech32m>(bech32::Hrp::parse("mn_addr").unwrap(), &[1, 2, 3]).unwrap();
        assert!(decode_zswap_offer_bech32(&other).is_err());
        // A corrupted checksum is rejected.
        let mut good = encode_zswap_offer_bech32(&sample_offer(1, 0)).unwrap();
        good.pop();
        good.push('q');
        assert!(decode_zswap_offer_bech32(&good).is_err());
    }

    #[test]
    fn deltas_only_offer_is_not_guaranteed() {
        // No inputs and no outputs (deltas only) -> fallible segment.
        assert!(!zswap_offer_belongs_in_guaranteed(&sample_offer(100, 50)));
    }

    #[test]
    fn wrapped_zswapoffer_classifies_as_proven() {
        let offer = sample_offer(100, 50);
        let bech32 = encode_zswap_offer_bech32(&offer).unwrap();
        let bytes = wrap_zswap_offer_as_proven_tx("midnight:preview", &bech32).unwrap();
        assert_eq!(
            super::super::classify_unsealed_payload(&bytes),
            Some(super::super::UnsealedKind::Proven)
        );
    }
}
