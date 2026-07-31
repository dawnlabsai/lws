//! The contract actions a transaction carries, read off the ledger structure for the policy seam.
//!
//! The companion of the wallet-relative effects, and deliberately disjoint from them: the effects say
//! how much *the wallet* moves, these say *who* the transaction talks to and how much value each
//! contract declares it takes in and pays out. Identity and counterparty amounts live only here.

use std::collections::BTreeMap;

use midnight_coin_structure::coin::TokenType as LedgerTokenType;
use midnight_ledger::structure::{ContractAction, ProofKind};
use midnight_storage::db::DB;
use midnight_storage::storage::HashMap as MnHashMap;
use onchain_runtime::context::Effects;

/// The guaranteed section, executed before every fallible one. A call's guaranteed transcript runs
/// here whichever intent carried it; only its fallible transcript runs in that intent's own segment.
const GUARANTEED_SEGMENT: u16 = 0;

/// What a transaction does to a contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractActionKind {
    /// Invokes an entry point on an already-deployed contract.
    Call,
    /// Deploys a new contract.
    Deploy,
    /// Applies a maintenance update (authority / verifier keys) to an existing contract.
    Maintain,
}

/// One contract action a transaction performs, keyed by the segment it executes in — `0` guaranteed
/// (always executed), non-zero fallible (executed in segment order, allowed to fail). A call declaring
/// both a guaranteed and a fallible transcript yields one entry per transcript, each at its own
/// segment, so a policy reads a single record's segment rather than inferring it from where the record
/// sits. A fallible segment id is whatever `u16` the transaction's author picked for that intent — it
/// is an identifier, not a sequence number, so guaranteed-versus-fallible is `== 0` versus `!= 0`.
///
/// The amounts are the ones the **contract's transcript declares**, not proven wallet movement: they
/// equal what the wallet sends and receives only when the wallet is the contract's sole counterparty
/// in that segment (the normal shape for a wallet-authored connector transaction), and they are only
/// as trustworthy as the transcript is — meaningful for a proven or sealed transaction. For what the
/// wallet itself moves, read the effects.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContractInteraction {
    pub segment: u16,
    pub kind: ContractActionKind,
    /// The contract's hex-encoded address (a deploy's is derived from its initial state).
    pub address: String,
    /// The entry point a call invokes, as its UTF-8 name (hex when the name is not UTF-8). Absent for
    /// a deploy or a maintenance update, neither of which targets one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,
    /// Per token, the value the contract declares it takes IN — i.e. what the wallet sends it.
    pub sent_to: Vec<(String, u128)>,
    /// Per token, the value the contract declares it pays OUT — i.e. what the wallet receives from it.
    pub received_from: Vec<(String, u128)>,
}

/// The contract actions of a transaction's intents, one entry per executing segment. Pure over the
/// ledger structure (no key, no network), so it is the unit-tested core behind every plan's
/// `contracts()`; callers pass `StandardTransaction::actions()`, whose `u16` is the intent's segment.
pub(crate) fn contract_interactions<P: ProofKind<D>, D: DB>(
    actions: impl Iterator<Item = (u16, ContractAction<P, D>)>,
) -> Vec<ContractInteraction> {
    let mut out = Vec::new();
    for (intent_segment, action) in actions {
        match action {
            ContractAction::Call(call) => {
                let address = hex::encode(call.address.0 .0);
                let entry_point = entry_point_label(&call.entry_point);
                let guaranteed = call.guaranteed_transcript.as_ref();
                let fallible = call.fallible_transcript.as_ref();
                if let Some(transcript) = guaranteed {
                    out.push(call_interaction(
                        GUARANTEED_SEGMENT,
                        &address,
                        &entry_point,
                        &transcript.effects,
                    ));
                }
                if let Some(transcript) = fallible {
                    out.push(call_interaction(
                        intent_segment,
                        &address,
                        &entry_point,
                        &transcript.effects,
                    ));
                }
                if guaranteed.is_none() && fallible.is_none() {
                    // A call declaring no transcript moves nothing, but a policy keyed on which
                    // contracts a transaction touches still has to see it.
                    out.push(call_interaction(
                        intent_segment,
                        &address,
                        &entry_point,
                        &Effects::<D>::default(),
                    ));
                }
            }
            // A deploy and a maintenance update carry no transcript — the ledger skips both in the
            // guaranteed pass — so they declare no value movement and ride their intent's segment.
            ContractAction::Deploy(deploy) => out.push(ContractInteraction {
                segment: intent_segment,
                kind: ContractActionKind::Deploy,
                address: hex::encode(deploy.address().0 .0),
                entry_point: None,
                sent_to: Vec::new(),
                received_from: Vec::new(),
            }),
            ContractAction::Maintain(update) => out.push(ContractInteraction {
                segment: intent_segment,
                kind: ContractActionKind::Maintain,
                address: hex::encode(update.address.0 .0),
                entry_point: None,
                sent_to: Vec::new(),
                received_from: Vec::new(),
            }),
        }
    }
    out
}

fn call_interaction<D: DB>(
    segment: u16,
    address: &str,
    entry_point: &str,
    effects: &Effects<D>,
) -> ContractInteraction {
    ContractInteraction {
        segment,
        kind: ContractActionKind::Call,
        address: address.to_string(),
        entry_point: Some(entry_point.to_string()),
        sent_to: token_amounts(&effects.unshielded_inputs),
        received_from: token_amounts(&effects.unshielded_outputs),
    }
}

/// A transcript's declared per-token amounts on the wire, sorted by token and with zeros dropped.
fn token_amounts<D: DB>(amounts: &MnHashMap<LedgerTokenType, u128, D>) -> Vec<(String, u128)> {
    let mut by_token: BTreeMap<String, u128> = BTreeMap::new();
    for (token, value) in amounts.clone() {
        let total = by_token.entry(wire_token_type(token)).or_default();
        *total = total.saturating_add(value);
    }
    by_token.into_iter().filter(|(_, v)| *v != 0).collect()
}

/// A ledger token type as the wire string the policy context uses elsewhere: the 32-byte hex of the
/// token (all-zeros for NIGHT), or `dust` for the DUST dimension. The transcript fields these come
/// from are unshielded, so the hex is never ambiguous in practice; the shielded arm only keeps the
/// mapping total.
fn wire_token_type(token: LedgerTokenType) -> String {
    match token {
        LedgerTokenType::Unshielded(tt) => hex::encode(tt.0 .0),
        LedgerTokenType::Shielded(tt) => hex::encode(tt.0 .0),
        LedgerTokenType::Dust => "dust".to_string(),
    }
}

/// A call's entry point as its UTF-8 name — how Compact declares them — falling back to hex for a name
/// that is not valid UTF-8.
fn entry_point_label(entry_point: &[u8]) -> String {
    std::str::from_utf8(entry_point)
        .map(str::to_string)
        .unwrap_or_else(|_| hex::encode(entry_point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_coin_structure::coin::UnshieldedTokenType;
    use midnight_coin_structure::contract::ContractAddress;
    use midnight_ledger::structure::{ContractDeploy, MaintenanceUpdate};
    use midnight_storage::arena::Sp;
    use midnight_storage::db::InMemoryDB;
    use onchain_runtime::state::{
        ContractMaintenanceAuthority, ContractState, EntryPointBuf, StateValue,
    };
    use onchain_runtime::transcript::Transcript;

    /// The proof-free marker instantiation: the extraction reads only addresses and transcripts, both
    /// proof-independent, so a test never needs a prover.
    type Call = midnight_ledger::structure::ContractCall<(), InMemoryDB>;
    type Action = ContractAction<(), InMemoryDB>;

    fn address(byte: u8) -> ContractAddress {
        ContractAddress(HashOutput([byte; 32]))
    }

    fn token(byte: u8) -> LedgerTokenType {
        LedgerTokenType::Unshielded(UnshieldedTokenType(HashOutput([byte; 32])))
    }

    /// A transcript declaring `inputs` taken in and `outputs` paid out by the contract.
    fn transcript(
        inputs: &[(LedgerTokenType, u128)],
        outputs: &[(LedgerTokenType, u128)],
    ) -> Sp<Transcript<InMemoryDB>, InMemoryDB> {
        let mut effects = Effects::<InMemoryDB>::default();
        for (token, value) in inputs {
            effects.unshielded_inputs = effects.unshielded_inputs.insert(*token, *value);
        }
        for (token, value) in outputs {
            effects.unshielded_outputs = effects.unshielded_outputs.insert(*token, *value);
        }
        Sp::new(Transcript {
            gas: Default::default(),
            effects,
            program: vec![].into(),
            version: None,
        })
    }

    fn call(
        contract: u8,
        entry_point: &str,
        guaranteed: Option<Sp<Transcript<InMemoryDB>, InMemoryDB>>,
        fallible: Option<Sp<Transcript<InMemoryDB>, InMemoryDB>>,
    ) -> Action {
        ContractAction::Call(Sp::new(Call {
            address: address(contract),
            entry_point: EntryPointBuf(entry_point.as_bytes().to_vec()),
            guaranteed_transcript: guaranteed,
            fallible_transcript: fallible,
            communication_commitment: Default::default(),
            proof: (),
        }))
    }

    #[test]
    fn a_call_yields_one_entry_per_transcript_at_its_own_segment() {
        // One call carried by intent segment 3, declaring both transcripts: the guaranteed one runs in
        // segment 0, the fallible one in the intent's segment.
        let action = call(
            0xAB,
            "swap",
            Some(transcript(&[(token(0x11), 100)], &[])),
            Some(transcript(&[], &[(token(0x22), 250)])),
        );

        let out = contract_interactions([(3u16, action)].into_iter());

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].segment, GUARANTEED_SEGMENT);
        assert_eq!(out[0].kind, ContractActionKind::Call);
        assert_eq!(out[0].address, hex::encode([0xABu8; 32]));
        assert_eq!(out[0].entry_point.as_deref(), Some("swap"));
        assert_eq!(out[0].sent_to, vec![(hex::encode([0x11u8; 32]), 100)]);
        assert!(out[0].received_from.is_empty());

        assert_eq!(out[1].segment, 3);
        assert_eq!(out[1].address, hex::encode([0xABu8; 32]));
        assert!(out[1].sent_to.is_empty());
        assert_eq!(out[1].received_from, vec![(hex::encode([0x22u8; 32]), 250)]);
    }

    #[test]
    fn a_call_declaring_no_transcript_is_still_reported() {
        let out = contract_interactions([(1u16, call(0x07, "noop", None, None))].into_iter());

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].segment, 1);
        assert_eq!(out[0].entry_point.as_deref(), Some("noop"));
        assert!(out[0].sent_to.is_empty());
        assert!(out[0].received_from.is_empty());
    }

    #[test]
    fn a_deploy_and_a_maintenance_update_ride_their_intent_segment_with_no_amounts() {
        let deploy = ContractDeploy::<InMemoryDB> {
            initial_state: ContractState::new(
                StateValue::Null,
                Default::default(),
                ContractMaintenanceAuthority::default(),
            ),
            nonce: HashOutput([0x42; 32]),
        };
        // A deploy names no address of its own — the ledger derives it from the deploy itself.
        let deployed_address = hex::encode(deploy.address().0 .0);
        let update = MaintenanceUpdate::<InMemoryDB> {
            address: address(0x99),
            updates: vec![].into(),
            counter: 0,
            signatures: vec![].into(),
        };

        let out = contract_interactions(
            [
                (2u16, Action::Deploy(Sp::new(deploy))),
                (5u16, Action::Maintain(update)),
            ]
            .into_iter(),
        );

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kind, ContractActionKind::Deploy);
        assert_eq!(out[0].segment, 2);
        assert_eq!(out[0].address, deployed_address);
        assert_eq!(out[0].entry_point, None);
        assert!(out[0].sent_to.is_empty() && out[0].received_from.is_empty());

        assert_eq!(out[1].kind, ContractActionKind::Maintain);
        assert_eq!(out[1].segment, 5);
        assert_eq!(out[1].address, hex::encode([0x99u8; 32]));
        assert_eq!(out[1].entry_point, None);
    }

    /// A real, settled preprod contract call, read from the bytes the chain actually carries.
    ///
    /// Fixture: tx `9d506439b5ffe3942ec0592e262b864cc2c64a2b865354b64679b5e9fea824fd`, block
    /// 1851195 on `midnight:preprod`, status SUCCESS — refetch with
    /// `{ transactions(offset:{hash:"9d5064…"}) { raw } }` against
    /// `https://indexer.preprod.midnight.network/api/v4/graphql`.
    ///
    /// The indexer reports this call independently as address
    /// `3b477afdd03085630c0afca689ba0cd5fab475bcfd9e021f47e9c0e8699164ce`, entry point
    /// `addUnshieldedLiquidity` — so the address and entry point below are cross-checked against a
    /// source other than our own decoding, and the amounts are what a real dapp's transcript declares.
    #[test]
    fn a_real_preprod_contract_call_is_read_from_the_chain_bytes() {
        use midnight_base_crypto::signatures::Signature as MnSig;
        use midnight_ledger::structure::{ProofMarker, Transaction};
        use midnight_serialize::tagged_deserialize;
        use transient_crypto::commitment::PureGeneratorPedersen;

        let hex_str = include_str!("testdata/contract_call_preprod.hex").trim();
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();
        let mut reader: &[u8] = &bytes;
        let tx: Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB> =
            tagged_deserialize(&mut reader).unwrap();
        let Transaction::Standard(base) = &tx else {
            panic!("the fixture is a Standard transaction");
        };

        let out = contract_interactions(base.actions());

        assert_eq!(
            out.len(),
            1,
            "the fixture carries exactly one contract action"
        );
        let call = &out[0];
        assert_eq!(call.kind, ContractActionKind::Call);
        assert_eq!(
            call.address,
            "3b477afdd03085630c0afca689ba0cd5fab475bcfd9e021f47e9c0e8699164ce"
        );
        assert_eq!(call.entry_point.as_deref(), Some("addUnshieldedLiquidity"));

        // The call declares only a fallible transcript, so it is keyed by its intent's own segment —
        // and a real segment id is an arbitrary `u16` the author picked (this tx's intents are 2260
        // and 15441), not a small sequential number. Guaranteed-vs-fallible is `== 0` vs `!= 0`.
        assert_eq!(call.segment, 15441);
        assert_ne!(call.segment, GUARANTEED_SEGMENT);

        // Adding liquidity pays value IN and takes none out: NIGHT plus the pool's other token.
        assert_eq!(
            call.sent_to,
            vec![
                (hex::encode([0u8; 32]), 5_000_000),
                (
                    "86590203209b68bf2d422c7e76a0e4daf6ebef6b229bb3d6efec5d359e883142".to_string(),
                    27_388_373
                ),
            ]
        );
        assert!(call.received_from.is_empty());
    }

    #[test]
    fn dust_and_zero_amounts_render_as_the_policy_expects() {
        let action = call(
            0x01,
            "fee",
            Some(transcript(
                &[(LedgerTokenType::Dust, 42), (token(0x33), 0)],
                &[],
            )),
            None,
        );

        let out = contract_interactions([(1u16, action)].into_iter());

        // The DUST dimension keeps the `dust` wire name the effects use; a zero amount is dropped.
        assert_eq!(out[0].sent_to, vec![("dust".to_string(), 42)]);
    }
}
