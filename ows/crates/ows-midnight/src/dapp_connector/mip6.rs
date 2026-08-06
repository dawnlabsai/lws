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

// ---------------------------------------------------------------------------------------------
// MIP-0006 offer-file (JSON) validation
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
struct Mip6TokenAmountJson {
    token: String,
    amount: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Mip6AuthJson {
    #[serde(rename = "signerPublicKey")]
    signer_public_key: String,
    signature: String,
    scheme: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Mip6OfferPayloadJson {
    version: u32,
    transaction: String,
    wants: Vec<Mip6TokenAmountJson>,
    gives: Vec<Mip6TokenAmountJson>,
    #[serde(default)]
    auth: Option<Mip6AuthJson>,
}

/// Whether a JSON value looks like a MIP-0006 offer payload (has the four required fields).
pub(super) fn is_mip6_offer_payload(v: &serde_json::Value) -> bool {
    v.get("version").is_some()
        && v.get("transaction").is_some()
        && v.get("gives").is_some()
        && v.get("wants").is_some()
}

fn shielded_token_wire(token: midnight_coin_structure::coin::ShieldedTokenType) -> String {
    crate::parse_token_type(Some(&format!("0x{}", hex::encode(token.0 .0))))
        .map(|t| t.to_wire_token_type())
        .unwrap_or_else(|_| hex::encode(token.0 .0))
}

fn normalize_token_wire(token: &str) -> Result<String, std::io::Error> {
    Ok(crate::parse_token_type(Some(token))
        .map_err(|e| err(e.to_string()))?
        .to_wire_token_type())
}

fn parse_amount_string(amount: &str) -> Result<u128, std::io::Error> {
    amount
        .trim()
        .parse::<u128>()
        .map_err(|e| err(format!("invalid MIP-0006 amount {amount:?}: {e}")))
}

/// Sum a MIP-0006 gives/wants list into a per-token map (tokens normalized to their wire form).
fn advertised_token_map(
    entries: &[Mip6TokenAmountJson],
    label: &str,
) -> Result<std::collections::BTreeMap<String, u128>, std::io::Error> {
    let mut out = std::collections::BTreeMap::new();
    for entry in entries {
        let token = normalize_token_wire(&entry.token)?;
        let amount = parse_amount_string(&entry.amount)?;
        if amount == 0 {
            return Err(err(format!(
                "MIP-0006 {label} entry for token {token} must be non-zero"
            )));
        }
        let slot = out.entry(token).or_insert(0u128);
        *slot = slot
            .checked_add(amount)
            .ok_or_else(|| err(format!("MIP-0006 {label} amount overflow")))?;
    }
    Ok(out)
}

/// Extract the maker's actual gives/wants from a Zswap offer's deltas: a positive delta means the
/// maker spends (gives) that token, a negative delta means it receives (wants) it.
fn deltas_to_gives_wants(
    offer: &ProvenZswapOffer,
) -> (
    std::collections::BTreeMap<String, u128>,
    std::collections::BTreeMap<String, u128>,
) {
    let mut gives = std::collections::BTreeMap::new();
    let mut wants = std::collections::BTreeMap::new();
    for delta in offer.deltas.iter_deref() {
        let token = shielded_token_wire(delta.token_type);
        if delta.value > 0 {
            *gives.entry(token).or_insert(0) += delta.value as u128;
        } else if delta.value < 0 {
            *wants.entry(token).or_insert(0) += delta.value.unsigned_abs();
        }
    }
    (gives, wants)
}

fn compare_token_maps(
    advertised: &std::collections::BTreeMap<String, u128>,
    actual: &std::collections::BTreeMap<String, u128>,
    label: &str,
) -> Result<(), std::io::Error> {
    if advertised == actual {
        return Ok(());
    }
    Err(err(format!(
        "MIP-0006 {label} does not match offer deltas (advertised={advertised:?}, actual={actual:?})"
    )))
}

/// Canonicalize a JSON value per RFC 8785 (JCS) for the MIP-0006 offer payload: object keys sorted
/// (ASCII order equals the UTF-16 code-unit order JCS mandates for these keys), no insignificant
/// whitespace, arrays in order, and leaf strings/small integers via serde_json's escaping. Sufficient
/// and faithful for the offer shape (strings, string amounts, one small version integer).
fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            let mut s = String::from("{");
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&serde_json::to_string(k).unwrap_or_default());
                s.push(':');
                s.push_str(&canonical_json(val));
            }
            s.push('}');
            s
        }
        Value::Array(arr) => {
            let mut s = String::from("[");
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&canonical_json(e));
            }
            s.push(']');
            s
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Verify the optional MIP-0006 `auth`: a BIP-340 Schnorr signature by `signerPublicKey` over the
/// SHA-256 of the canonical JSON offer with `auth` removed.
fn verify_auth(payload: &serde_json::Value, auth: &Mip6AuthJson) -> Result<(), std::io::Error> {
    use k256::schnorr::signature::Verifier as _;
    use sha2::{Digest as _, Sha256};

    if auth.scheme != "schnorr-bip340" {
        return Err(err(format!(
            "unsupported MIP-0006 auth scheme {:?} (expected schnorr-bip340)",
            auth.scheme
        )));
    }

    let mut unsigned = payload.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("auth");
    }
    let digest: [u8; 32] = Sha256::digest(canonical_json(&unsigned).as_bytes()).into();

    let pk_hex = auth
        .signer_public_key
        .strip_prefix("0x")
        .unwrap_or(&auth.signer_public_key);
    let pk_bytes =
        hex::decode(pk_hex).map_err(|e| err(format!("invalid auth signerPublicKey hex: {e}")))?;
    let pk: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| {
        err(format!(
            "auth signerPublicKey must be 32 bytes, got {}",
            pk_bytes.len()
        ))
    })?;
    let vk = k256::schnorr::VerifyingKey::from_bytes(&pk)
        .map_err(|e| err(format!("invalid auth signerPublicKey: {e}")))?;

    let sig_hex = auth.signature.strip_prefix("0x").unwrap_or(&auth.signature);
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| err(format!("invalid auth signature hex: {e}")))?;
    let sig = k256::schnorr::Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| err(format!("invalid auth signature: {e}")))?;

    vk.verify(&digest, &sig)
        .map_err(|_| err("MIP-0006 auth signature verification failed"))
}

/// Validate a MIP-0006 offer payload and return proven maker transaction bytes for balancing. The
/// `transaction` field must be a `zswapoffer` bech32; the advertised gives/wants must match the
/// offer's actual deltas; and the optional `auth` signature (if present) must verify.
pub(super) fn materialize_validated_offer(
    chain_id: &str,
    v: &serde_json::Value,
) -> Result<Vec<u8>, std::io::Error> {
    let payload: Mip6OfferPayloadJson = serde_json::from_value(v.clone())
        .map_err(|e| err(format!("invalid MIP-0006 offer JSON: {e}")))?;
    if payload.version != 1 {
        return Err(err(format!(
            "unsupported MIP-0006 version {} (expected 1)",
            payload.version
        )));
    }
    let transaction = payload.transaction.trim();
    if !transaction.starts_with(ZSWAP_OFFER_BECH32_HRP) {
        return Err(err(
            "MIP-0006 transaction field must be a zswapoffer… bech32 string (MIP-0005); use \
             balanceSealedTransaction with proven hex for a full maker transaction",
        ));
    }

    let offer = decode_zswap_offer_bech32(transaction)?;
    let (actual_gives, actual_wants) = deltas_to_gives_wants(&offer);
    let advertised_gives = advertised_token_map(&payload.gives, "gives")?;
    let advertised_wants = advertised_token_map(&payload.wants, "wants")?;
    compare_token_maps(&advertised_gives, &actual_gives, "gives")?;
    compare_token_maps(&advertised_wants, &actual_wants, "wants")?;

    if let Some(auth) = &payload.auth {
        verify_auth(v, auth)?;
    }

    wrap_zswap_offer_as_proven_tx(chain_id, transaction)
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

    fn mip6_json(bech32: &str, give_amount: &str, want_amount: &str) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "transaction": bech32,
            "gives": [{"token": hex::encode([1u8; 32]), "amount": give_amount}],
            "wants": [{"token": hex::encode([2u8; 32]), "amount": want_amount}],
        })
    }

    #[test]
    fn mip6_offer_matching_deltas_materializes_to_proven() {
        let bech32 = encode_zswap_offer_bech32(&sample_offer(100, 50)).unwrap();
        let bytes =
            materialize_validated_offer("midnight:preview", &mip6_json(&bech32, "100", "50"))
                .unwrap();
        assert_eq!(
            super::super::classify_unsealed_payload(&bytes),
            Some(super::super::UnsealedKind::Proven)
        );
    }

    #[test]
    fn mip6_rejects_mismatch_bad_version_and_non_zswapoffer() {
        let bech32 = encode_zswap_offer_bech32(&sample_offer(100, 50)).unwrap();
        // Advertised gives (99) does not match the offer's actual deltas (100).
        assert!(
            materialize_validated_offer("midnight:preview", &mip6_json(&bech32, "99", "50"))
                .is_err()
        );
        // Wrong version.
        let mut bad_version = mip6_json(&bech32, "100", "50");
        bad_version["version"] = serde_json::json!(2);
        assert!(materialize_validated_offer("midnight:preview", &bad_version).is_err());
        // transaction is not a zswapoffer bech32.
        let mut not_offer = mip6_json(&bech32, "100", "50");
        not_offer["transaction"] = serde_json::json!("0x010203");
        assert!(materialize_validated_offer("midnight:preview", &not_offer).is_err());
    }

    #[test]
    fn mip6_auth_signature_verifies_and_rejects_tampering() {
        use k256::schnorr::signature::Signer as _;
        use sha2::{Digest as _, Sha256};

        let bech32 = encode_zswap_offer_bech32(&sample_offer(100, 50)).unwrap();
        let unsigned = mip6_json(&bech32, "100", "50");

        // Sign the SHA-256 of the canonical (auth-free) offer with a BIP-340 key.
        let sk = k256::schnorr::SigningKey::from_bytes(&[0x11u8; 32]).unwrap();
        let digest: [u8; 32] = Sha256::digest(canonical_json(&unsigned).as_bytes()).into();
        let sig: k256::schnorr::Signature = sk.sign(&digest);

        let mut signed = unsigned.clone();
        signed["auth"] = serde_json::json!({
            "signerPublicKey": hex::encode(sk.verifying_key().to_bytes()),
            "signature": hex::encode(sig.to_bytes()),
            "scheme": "schnorr-bip340",
        });
        assert!(materialize_validated_offer("midnight:preview", &signed).is_ok());

        // A tampered signature is rejected.
        let mut tampered = signed.clone();
        let mut bad_sig = sig.to_bytes();
        bad_sig[0] ^= 0xff;
        tampered["auth"]["signature"] = serde_json::json!(hex::encode(bad_sig));
        assert!(materialize_validated_offer("midnight:preview", &tampered).is_err());
    }
}
