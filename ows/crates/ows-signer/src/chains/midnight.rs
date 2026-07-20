use bech32::{Bech32m, Hrp};
use k256::schnorr::SigningKey;
use midnight_base_crypto::signatures::{
    Signature as MnSignature, SigningKey as MidnightSigningKey,
};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin;
use midnight_coin_structure::coin::{Info as CoinInfo, QualifiedInfo, ShieldedTokenType};
use midnight_coin_structure::transfer;
use midnight_ledger::dust::{
    DustActions, DustLocalState, DustOutput, DustPublicKey, DustRegistration, DustSecretKey,
    DustSpend,
};
use midnight_ledger::semantics::ZswapLocalStateExt as _;
use midnight_ledger::structure::{
    Intent, LedgerParameters, ProofMarker, ProofPreimageMarker, StandardTransaction, Transaction,
};
use midnight_serialize::{
    tagged_deserialize, tagged_serialize, Deserializable, ScaleBigInt, Serializable,
};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_zswap::keys::{SecretKeys as ZswapSecretKeys, Seed as ZswapSeed};
use midnight_zswap::local::State as ZswapLocalState;
use midnight_zswap::{Offer as ZswapOffer, Output as ZswapOutput};
use num_bigint::BigUint;
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng as _;
use sha2::Digest;
use std::ops::Deref as _;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::{Proof as ZswapProof, ProofPreimage, ProvingProvider};

use crate::curve::Curve;
use crate::hd::DerivedKey;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use crate::zeroizing::SecretBytes;
use ows_core::ChainType;

/// A proven-but-unsealed Midnight Standard transaction (`proof,embedded-fr`).
type TxProvenUnsealed = Transaction<MnSignature, ProofMarker, PedersenRandomness, InMemoryDB>;
type StdTxProvenUnsealed =
    StandardTransaction<MnSignature, ProofMarker, PedersenRandomness, InMemoryDB>;
type IntentProvenUnsealed = Intent<MnSignature, ProofMarker, PedersenRandomness, InMemoryDB>;

/// Midnight network selection. Each network uses the same keys but a
/// network-specific Bech32m HRP suffix — the unshielded, shielded, and dust
/// addresses all carry the network id in their HRP.
///
/// A network is identified by its CAIP-2 *reference* (the part after
/// `midnight:`), preserved verbatim. Any reference is accepted — `mainnet`,
/// `preview`, `preprod`, and ad-hoc feature testnets like `feature-x` — so an
/// unregistered id is never cast to mainnet. The reference is validated for
/// Bech32m HRP compatibility when an address is derived and rejected, not
/// coerced, if malformed. Only `mainnet` gets the empty HRP suffix; every other
/// reference carries `_{reference}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MidnightNetwork {
    reference: String,
}

impl MidnightNetwork {
    /// The CAIP-2 reference that denotes mainnet — the only network with an empty HRP suffix.
    const MAINNET_REFERENCE: &str = "mainnet";

    pub fn mainnet() -> Self {
        Self::from_reference(Self::MAINNET_REFERENCE)
    }

    pub fn preview() -> Self {
        Self::from_reference("preview")
    }

    pub fn preprod() -> Self {
        Self::from_reference("preprod")
    }

    /// Build a network from a CAIP-2 reference (the part after `midnight:`), preserved verbatim —
    /// no mapping to a fixed set — so ad-hoc feature testnets work end to end. The reference is
    /// validated when an address is derived, not here.
    pub fn from_reference(reference: &str) -> Self {
        Self {
            reference: reference.to_string(),
        }
    }

    /// Resolve a network from a CAIP-2 chain id (`midnight:<reference>`), preserving the
    /// reference. Lenient at construction: an unregistered id is kept as-is (feature testnets),
    /// never cast to mainnet and never a panic. A malformed reference is rejected — not coerced —
    /// as an address-derivation error when its HRP is built.
    pub fn from_chain_id(chain_id: &str) -> Self {
        let reference = chain_id.split_once(':').map_or(chain_id, |(_, r)| r);
        Self::from_reference(reference)
    }

    /// This network's CAIP-2 reference (the part after `midnight:`).
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Bech32m HRP for the unshielded (Night) address, validating the reference first.
    fn unshielded_hrp(&self) -> Result<String, SignerError> {
        validate_network_reference(&self.reference)?;
        Ok(hrp_for_network("mn_addr", &self.reference))
    }

    /// Bech32m HRP for the shielded (Zswap) address, validating the reference first.
    fn shielded_hrp(&self) -> Result<String, SignerError> {
        validate_network_reference(&self.reference)?;
        Ok(hrp_for_network("mn_shield-addr", &self.reference))
    }

    /// Bech32m HRP for the dust address, validating the reference first.
    fn dust_hrp(&self) -> Result<String, SignerError> {
        validate_network_reference(&self.reference)?;
        Ok(hrp_for_network("mn_dust", &self.reference))
    }

    /// Bech32m HRP for the viewing (encryption-secret) key sent to the indexer in the
    /// shielded viewing-key session path, validating the reference first.
    pub fn viewing_key_hrp(&self) -> Result<String, SignerError> {
        validate_network_reference(&self.reference)?;
        Ok(hrp_for_network("mn_shield-esk", &self.reference))
    }
}

/// Bech32m HRP bases used for Midnight addresses; network references must produce valid
/// combined HRPs for each (`mn_addr_{network}`, …).
const MIDNIGHT_ADDRESS_BASE_HRPS: &[&str] = &["mn_addr", "mn_shield-addr", "mn_dust"];

/// True when the network reference is mainnet (no Bech32m HRP suffix).
fn is_mainnet_network_reference(network_ref: &str) -> bool {
    network_ref.eq_ignore_ascii_case("mainnet")
}

/// Build a Bech32m HRP for a Midnight address type on the given network.
///
/// Mainnet uses the base HRP with no suffix (`mn_addr`). Every other network appends
/// `_{network}` (`mn_addr_preview`, `mn_addr_my-feature`, …).
fn hrp_for_network(base_hrp: &str, network_ref: &str) -> String {
    if is_mainnet_network_reference(network_ref) {
        base_hrp.to_string()
    } else {
        format!("{base_hrp}_{network_ref}")
    }
}

/// Reject network references that are not safe Midnight network id strings or would produce
/// invalid Bech32m HRPs when suffixed. Validation runs at address-derivation time so
/// construction stays infallible; a malformed reference is rejected, never coerced.
fn validate_network_reference(network_ref: &str) -> Result<(), SignerError> {
    if network_ref.is_empty() {
        return Err(SignerError::AddressDerivationFailed(
            "midnight chain id must include a network reference after 'midnight:'".into(),
        ));
    }
    if !network_ref
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(SignerError::AddressDerivationFailed(format!(
            "invalid midnight network reference {network_ref:?}: must contain only lowercase letters, digits, and hyphens"
        )));
    }
    if network_ref.starts_with('-') || network_ref.ends_with('-') {
        return Err(SignerError::AddressDerivationFailed(format!(
            "invalid midnight network reference {network_ref:?}: must not start or end with a hyphen"
        )));
    }
    validate_network_reference_for_bech32_hrp(network_ref)
}

/// Reject network references that would produce invalid Bech32m HRPs when suffixed.
fn validate_network_reference_for_bech32_hrp(network_ref: &str) -> Result<(), SignerError> {
    for base in MIDNIGHT_ADDRESS_BASE_HRPS {
        let hrp = hrp_for_network(base, network_ref);
        Hrp::parse(&hrp).map_err(|e| {
            SignerError::AddressDerivationFailed(format!(
                "invalid midnight network reference {network_ref:?} (Bech32m HRP {hrp:?}): {e}"
            ))
        })?;
    }
    Ok(())
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

/// The full set of Midnight addresses for one account on one network.
pub struct MidnightAddresses {
    pub unshielded: String,
    pub shielded: String,
    pub dust: String,
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
            network: MidnightNetwork::mainnet(),
        }
    }

    pub fn preview() -> Self {
        Self {
            network: MidnightNetwork::preview(),
        }
    }

    pub fn preprod() -> Self {
        Self {
            network: MidnightNetwork::preprod(),
        }
    }

    /// Resolve a signer from a CAIP-2 chain id, preserving the network reference. Any
    /// `midnight:<reference>` is accepted verbatim — no cast to mainnet, no panic — so ad-hoc
    /// feature testnets sign and address correctly. A malformed reference surfaces later as an
    /// address-derivation error, not here.
    pub fn from_chain_id(chain_id: &str) -> Self {
        Self {
            network: MidnightNetwork::from_chain_id(chain_id),
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

    /// Shielded address payload: Wallet SDK Zswap derives the secret key set from
    /// the 32-byte seed; the address is `coinPublicKey || encryptionPublicKey` (64
    /// bytes), Bech32m-encoded under the given network HRP.
    fn derive_shielded_address_with_hrp(
        &self,
        seed: &[u8],
        hrp: &str,
    ) -> Result<String, SignerError> {
        let seed_arr: [u8; 32] = seed.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!(
                "expected 32-byte shielded seed, got {} bytes",
                seed.len()
            ))
        })?;
        let keys = ZswapSecretKeys::from(ZswapSeed::from(seed_arr));

        let coin_public = keys.coin_public_key().0 .0;
        let mut enc_public = Vec::new();
        keys.enc_public_key()
            .serialize(&mut enc_public)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;
        if enc_public.len() != 32 {
            return Err(SignerError::AddressDerivationFailed(format!(
                "unexpected encryption public key length: {}",
                enc_public.len()
            )));
        }

        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&coin_public);
        payload.extend_from_slice(&enc_public);
        Self::bech32m_encode(hrp, &payload)
    }

    /// Dust address: Wallet SDK / ledger-v8 derives the dust public key (a field
    /// element) from the 32-byte seed, SCALE-encodes it as a BigInt, and Bech32m-
    /// encodes that payload under the network's `mn_dust{suffix}` HRP.
    fn derive_dust_address_from_seed(&self, seed: &[u8]) -> Result<String, SignerError> {
        let seed_arr: [u8; 32] = seed.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!(
                "expected 32-byte dust seed, got {} bytes",
                seed.len()
            ))
        })?;
        let dsk = DustSecretKey::derive_secret_key(&seed_arr);
        let dpk = DustPublicKey::from(dsk);

        // JS `fr_to_bigint`: little-endian bytes reversed, interpreted as big-endian
        // hex. The numeric value is the same; we build it from big-endian bytes.
        let mut be = dpk.0.as_le_bytes();
        be.reverse();
        let dust_pk = BigUint::from_bytes_be(&be);

        let payload = scale_bigint_encode_biguint(&dust_pk)?;
        Self::bech32m_encode(&self.network.dust_hrp()?, &payload)
    }

    /// Derive all three Midnight addresses (unshielded / shielded / dust) from
    /// the OWS `signing_key` produced by `encode_keys` / `secret_to_signing_key`.
    pub fn derive_addresses(&self, signing_key: &[u8]) -> Result<MidnightAddresses, SignerError> {
        let seeds = Self::decode_keys(signing_key)?;
        Ok(MidnightAddresses {
            unshielded: self.derive_unshielded_address_with_hrp(
                seeds.unshielded.expose(),
                &self.network.unshielded_hrp()?,
            )?,
            shielded: self.derive_shielded_address_with_hrp(
                seeds.shielded.expose(),
                &self.network.shielded_hrp()?,
            )?,
            dust: self.derive_dust_address_from_seed(seeds.dust.expose())?,
        })
    }

    /// Derive the Zswap (shielded) secret keys from the 32-byte shielded role seed. The keys are
    /// held inside a [`MidnightCryptoProvider`]; balance code holds only `&MidnightCryptoProvider`.
    fn zswap_secret_keys_from_seed(seed: &[u8]) -> Result<ZswapSecretKeys, SignerError> {
        let seed_arr: [u8; 32] = seed.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!(
                "expected 32-byte shielded seed, got {} bytes",
                seed.len()
            ))
        })?;
        Ok(ZswapSecretKeys::from(ZswapSeed::from(seed_arr)))
    }

    /// Decode the `credential` (a packed Midnight signing key) into a [`MidnightCryptoProvider`]
    /// that holds the account seeds and the keys derived from them. All key material stays inside
    /// the provider — balance call sites in `ows-midnight` hold only `&MidnightCryptoProvider`.
    pub fn crypto_provider(
        &self,
        credential: &SecretBytes,
    ) -> Result<MidnightCryptoProvider, SignerError> {
        MidnightCryptoProvider::from_credential(credential)
    }

    /// Re-encode a Bech32m unshielded address under this network's HRP. The
    /// payload (pubkey hash) is network-independent; only the HRP differs.
    pub fn reencode_unshielded_address(&self, address: &str) -> Result<String, SignerError> {
        use bech32::primitives::decode::CheckedHrpstring;

        let checked = CheckedHrpstring::new::<Bech32m>(address).map_err(|e| {
            SignerError::AddressDerivationFailed(format!("invalid midnight address bech32m: {e}"))
        })?;
        let payload = checked.byte_iter().collect::<Vec<u8>>();
        Self::bech32m_encode(&self.network.unshielded_hrp()?, &payload)
    }
}

fn scale_bigint_encode_biguint(n: &BigUint) -> Result<Vec<u8>, SignerError> {
    // Midnight uses its own SCALE-compatible BigInt encoding (`ScaleBigInt`),
    // matching wallet-sdk / ledger-v8.
    let bytes_le = n.to_bytes_le();
    if bytes_le.len() > 67 {
        return Err(SignerError::AddressDerivationFailed(
            "ScaleBigInt: integer too large".into(),
        ));
    }
    let mut sb = ScaleBigInt::default();
    sb.0[..bytes_le.len()].copy_from_slice(&bytes_le);
    let mut out = Vec::new();
    sb.serialize(&mut out)
        .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;
    Ok(out)
}

/// A shielded input/change spend to authorize for one intent segment: the coins to spend and the
/// self-change to mint per token. A keyless balancer plans this — selection needs the spending key
/// only to *detect* coins (via nullifiers), which is non-authorizing — and the authorizing witness is
/// built from it here, in the signer.
pub struct ShieldedSpendPlan {
    pub segment: u16,
    pub coins: Vec<QualifiedInfo>,
    pub change: Vec<(ShieldedTokenType, u128)>,
}

/// The proven shielded fragments the balancer merges into the transaction's guaranteed offer, plus the
/// summed Pedersen binding randomness to add to the transaction (a proven tx can't recompute its own).
pub struct ShieldedAuthorized {
    pub proven: Vec<(u16, ZswapOffer<ZswapProof, InMemoryDB>)>,
    pub binding_delta: PedersenRandomness,
}

/// Proof-preimage shielded offers built by [`MidnightCryptoProvider::build_preimage_shielded_offers`]:
/// one offer per segment (tagged by segment id) plus the summed Pedersen binding-randomness delta.
type ShieldedPreimages = (
    Vec<(u16, ZswapOffer<ProofPreimage, InMemoryDB>)>,
    PedersenRandomness,
);

/// Holds the decoded Midnight account seeds plus the keys derived from them once at construction.
/// Created via [`MidnightSigner::crypto_provider`]. Keys never leave the provider — callers get
/// public outputs only (addresses, the dust public key, a fingerprint), so balance code can hold
/// `&MidnightCryptoProvider` instead of raw seed bytes.
pub struct MidnightCryptoProvider {
    seeds: MidnightSeeds,
    shielded_keys: ZswapSecretKeys,
    dust_sk: DustSecretKey,
}

impl MidnightCryptoProvider {
    fn from_credential(credential: &SecretBytes) -> Result<Self, SignerError> {
        let seeds = MidnightSigner::decode_keys(credential.expose())?;
        let shielded_keys = MidnightSigner::zswap_secret_keys_from_seed(seeds.shielded.expose())?;
        let dust_seed: [u8; 32] = seeds
            .dust
            .expose()
            .try_into()
            .map_err(|_| SignerError::InvalidPrivateKey("dust seed must be 32 bytes".into()))?;
        let dust_sk = DustSecretKey::derive_secret_key(&dust_seed);
        Ok(Self {
            seeds,
            shielded_keys,
            dust_sk,
        })
    }

    /// Derive all three Midnight addresses (unshielded / shielded / dust) for `network` from the
    /// seeds held in this provider — equivalent to [`MidnightSigner::derive_addresses`] on the
    /// packed blob, but the seeds are used directly.
    pub fn addresses(&self, network: &MidnightNetwork) -> Result<MidnightAddresses, SignerError> {
        let signer = MidnightSigner {
            network: network.clone(),
        };
        Ok(MidnightAddresses {
            unshielded: signer.derive_unshielded_address_with_hrp(
                self.seeds.unshielded.expose(),
                &network.unshielded_hrp()?,
            )?,
            shielded: signer.derive_shielded_address_with_hrp(
                self.seeds.shielded.expose(),
                &network.shielded_hrp()?,
            )?,
            dust: signer.derive_dust_address_from_seed(self.seeds.dust.expose())?,
        })
    }

    /// Verifying key for the unshielded (Night) role — the counterpart to the signing key stored
    /// in `seeds.unshielded`. The ledger `UtxoSpend.owner` field is this key.
    pub fn unshielded_verifying_key(
        &self,
    ) -> Result<midnight_base_crypto::signatures::VerifyingKey, SignerError> {
        midnight_base_crypto::signatures::SigningKey::from_bytes(self.seeds.unshielded.expose())
            .map(|sk| sk.verifying_key())
            .map_err(|e| {
                SignerError::InvalidPrivateKey(format!("invalid midnight signing key: {e}"))
            })
    }

    /// Public key for the dust (registration/fee) role derived from the dust secret key.
    pub fn dust_public_key(&self) -> Result<DustPublicKey, SignerError> {
        Ok(DustPublicKey::from(self.dust_sk.clone()))
    }

    /// Fold a batch of decoded dust ledger events into the dust wallet state in a single
    /// `replay_events` call. Each replay ends with a Merkle rehash + generation-collapse over the
    /// whole state, so folding many events per call amortizes that fixed cost. The dust secret key
    /// stays inside the provider; the caller receives the updated state.
    pub fn fold_dust(
        &self,
        state: DustLocalState<InMemoryDB>,
        evs: &[midnight_ledger::events::Event<InMemoryDB>],
    ) -> Result<DustLocalState<InMemoryDB>, SignerError> {
        state
            .replay_events(&self.dust_sk, evs.iter())
            .map_err(|e| SignerError::SigningFailed(format!("replay dust events failed: {e:?}")))
    }

    /// A 32-byte fingerprint of the shielded seed — the first 32 bytes of SHA-256(seed). Stable
    /// across sessions, so a snapshot is only reused for the same key material; consumers take
    /// `[..16]` and hex-encode for a compact string cache key.
    pub fn shielded_key_fingerprint(&self) -> Result<[u8; 32], SignerError> {
        let digest = sha2::Sha256::digest(self.seeds.shielded.expose());
        Ok(digest.into())
    }

    /// Detect an owned shielded output from a zswap ledger event's preimage evidence, returning
    /// the owned coin together with its nullifier — the only key-bearing step of the VK-free
    /// replay. The shielded keys stay inside the provider; the caller does the keyless owned-set
    /// bookkeeping (insert on output, remove on the matching input).
    pub fn detect_shielded_output(
        &self,
        evidence: &midnight_ledger::events::ZswapPreimageEvidence,
    ) -> Option<(coin::Nullifier, coin::Info)> {
        let ci = evidence.try_with_keys(&self.shielded_keys)?;
        let nul = ci.nullifier(&transfer::SenderEvidence::User(std::borrow::Cow::Borrowed(
            &self.shielded_keys.coin_secret_key,
        )));
        Some((nul, ci))
    }

    /// Fold one decoded zswap ledger event into the shielded wallet state, building the full
    /// spendable `ZswapLocalState` (commitment Merkle tree + qualified coins). The coin detection
    /// (spending key) stays inside the provider; the caller receives the updated state.
    pub fn fold_shielded(
        &self,
        state: ZswapLocalState<InMemoryDB>,
        ev: &midnight_ledger::events::Event<InMemoryDB>,
    ) -> Result<ZswapLocalState<InMemoryDB>, SignerError> {
        state
            .replay_events(&self.shielded_keys, std::iter::once(ev))
            .map_err(|e| SignerError::SigningFailed(format!("replay zswap event failed: {e:?}")))
    }

    /// Build the proof-preimage shielded input offers for each segment (the key-bearing spend-witness
    /// construction) WITHOUT proving. Shared by `authorize_shielded` (which proves each) and the offline
    /// fee-sizing path (which mock-proves + discards each). The preimage is for a throwaway sizing tx or
    /// the real authorization; either way the spend witnesses are built here from `self.shielded_keys`.
    pub fn build_preimage_shielded_offers(
        &self,
        plans: &[ShieldedSpendPlan],
        tree: &ZswapLocalState<InMemoryDB>,
    ) -> Result<ShieldedPreimages, SignerError> {
        use rand::Rng as _;
        let mut rng = OsRng;
        let keys = &self.shielded_keys;
        let cpk = keys.coin_public_key();

        let mut preimages = Vec::with_capacity(plans.len());
        let mut binding_delta = PedersenRandomness::from(0);

        for plan in plans {
            // Fresh clone per segment: each spend sees the prior spends' pending nullifiers (mirroring
            // the signer), while the plan's tree stays pristine for the real authorization.
            let mut working = tree.clone();
            let mut inputs = Vec::with_capacity(plan.coins.len());
            for coin in &plan.coins {
                let (next, input) = working
                    .spend(&mut rng, keys, coin, Some(plan.segment))
                    .map_err(|e| {
                        SignerError::SigningFailed(format!("shielded spend build failed: {e:?}"))
                    })?;
                working = next;
                inputs.push(input);
            }

            let mut outputs = Vec::with_capacity(plan.change.len());
            for (token, amount) in &plan.change {
                let coin = CoinInfo {
                    nonce: rng.r#gen(),
                    type_: *token,
                    value: *amount,
                };
                let out = ZswapOutput::new(
                    &mut rng,
                    &coin,
                    Some(plan.segment),
                    &cpk,
                    Some(keys.enc_public_key()),
                )
                .map_err(|e| {
                    SignerError::SigningFailed(format!("shielded change output failed: {e:?}"))
                })?;
                outputs.push(out);
            }

            let offer = ZswapOffer::new(inputs, outputs, vec![]).ok_or_else(|| {
                SignerError::SigningFailed("failed to build the shielded input offer".into())
            })?;
            binding_delta = binding_delta + offer.binding_randomness();
            preimages.push((plan.segment, offer));
        }

        Ok((preimages, binding_delta))
    }

    /// Authorize the wallet's shielded inputs. For each segment, builds the proof-preimage spend
    /// witnesses (the authorizing key operation) using the already-held `shielded_keys` and the
    /// self-change against the synced `tree`, then proves the fragment. The bearer preimage is
    /// born and consumed here — only the proven `Offer` leaves — so this must run **after** any
    /// policy check.
    ///
    /// `async` because proving is; the caller drives it with its own executor. Each segment's
    /// proof draws from an independent RNG via `prover.split()` — cloning the prover would duplicate
    /// its RNG state and correlate the segments' proof randomness.
    pub async fn authorize_shielded<P: ProvingProvider>(
        &self,
        segments: &[ShieldedSpendPlan],
        tree: &ZswapLocalState<InMemoryDB>,
        mut prover: P,
    ) -> Result<ShieldedAuthorized, SignerError> {
        let (preimages, binding_delta) = self.build_preimage_shielded_offers(segments, tree)?;
        let mut proven = Vec::with_capacity(preimages.len());
        for (segment, preimage) in preimages {
            let (_segment, proven_offer) =
                preimage.prove(prover.split(), segment).await.map_err(|e| {
                    SignerError::SigningFailed(format!("prove shielded inputs failed: {e:?}"))
                })?;
            proven.push((segment, proven_offer));
        }
        Ok(ShieldedAuthorized {
            proven,
            binding_delta,
        })
    }

    /// Build proof-preimage dust spends sufficient to cover `fee_dust`. Offline — no proving, no
    /// network. The balancer uses this to size the fee; [`Self::authorize_dust`] uses it again to
    /// produce the real, proved spends. The dust secret key stays inside the provider.
    pub fn build_preimage_dust_spends(
        &self,
        st: DustLocalState<InMemoryDB>,
        fee_dust: u128,
        dust_ctime: Timestamp,
    ) -> Result<Vec<DustSpend<ProofPreimageMarker, InMemoryDB>>, SignerError> {
        select_dust_spends_preimage(st, &self.dust_sk, fee_dust, dust_ctime)
    }

    /// Authorize the wallet's DUST fee. Builds proof-preimage dust spends using the already-held
    /// `dust_sk` and proves them into a submittable `DustActions` section. The bearer preimage is
    /// born and consumed here — only the proven section leaves — so this runs **after** the policy
    /// seam.
    ///
    /// `async` because proving is; the caller drives it with its own executor.
    pub async fn authorize_dust<P: ProvingProvider>(
        &self,
        dust_state: &DustLocalState<InMemoryDB>,
        plan: &DustSpendPlan,
        ledger_params: &LedgerParameters,
        prover: P,
    ) -> Result<DustActions<MnSignature, ProofMarker, InMemoryDB>, SignerError> {
        let spends = select_dust_spends_preimage(
            dust_state.clone(),
            &self.dust_sk,
            plan.fee_dust,
            plan.dust_ctime,
        )?;

        let dust_preimage: DustActions<MnSignature, ProofPreimageMarker, InMemoryDB> =
            DustActions {
                spends: spends.into_iter().collect(),
                registrations: vec![].into(),
                ctime: plan.dust_ctime,
            };
        let prove_intent: Intent<MnSignature, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
            Intent {
                guaranteed_unshielded_offer: None,
                fallible_unshielded_offer: None,
                actions: vec![].into(),
                dust_actions: Some(Sp::new(dust_preimage)),
                ttl: plan.intent_ttl,
                binding_commitment: plan.binding_commitment,
            };
        let (_seg, proven_intent) = prove_intent
            .prove(
                plan.seg_id,
                prover,
                &ledger_params.cost_model.runtime_cost_model,
            )
            .await
            .map_err(|e| SignerError::SigningFailed(format!("prove dust spends failed: {e:?}")))?;
        proven_intent
            .dust_actions
            .as_ref()
            .map(|sp| sp.deref().clone())
            .ok_or_else(|| {
                SignerError::SigningFailed("proven dust intent has no dust actions".into())
            })
    }
}

/// Select just enough of the wallet's generated dust notes to pay `fee_dust`, building each spend's
/// proof-preimage against the synced state. Targets a headroom over the fee (the spends themselves
/// add to the fee, so the caller re-runs this with a higher target when needed).
fn select_dust_spends_preimage(
    mut st: DustLocalState<InMemoryDB>,
    dsk: &DustSecretKey,
    fee_dust: u128,
    dust_ctime: Timestamp,
) -> Result<Vec<DustSpend<ProofPreimageMarker, InMemoryDB>>, SignerError> {
    let mut need = fee_dust.saturating_mul(2).saturating_add(100_000);
    let mut spends = Vec::new();
    for qdo in st.utxos().collect::<Vec<_>>() {
        if need == 0 {
            break;
        }
        let Some(gen_info) = st.generation_info(&qdo) else {
            continue;
        };
        let value = DustOutput::from(qdo).updated_value(&gen_info, dust_ctime, &st.params);
        if value == 0 {
            continue;
        }
        let v_fee = u128::min(value, need);
        let (st2, spend) = st
            .spend(dsk, &qdo, v_fee, dust_ctime)
            .map_err(|e| SignerError::SigningFailed(format!("dust spend build failed: {e}")))?;
        st = st2;
        spends.push(spend);
        need = need.saturating_sub(v_fee);
    }
    if need > 0 {
        return Err(SignerError::SigningFailed(
            "insufficient DUST balance to pay fees via a proof-bearing dust spend".into(),
        ));
    }
    Ok(spends)
}

/// The wallet's DUST fee plan for one intent segment: the converged fee target plus the timing/segment
/// context the signer needs to build and prove the fee section. Sized by the balancer offline; the
/// signer realizes it into a submittable section. `binding_commitment` is copied from the
/// transaction's real intent so the proved section splices back in.
pub struct DustSpendPlan {
    pub fee_dust: u128,
    pub dust_ctime: Timestamp,
    pub intent_ttl: Timestamp,
    pub seg_id: u16,
    pub binding_commitment: PedersenRandomness,
}

/// Deserialize a balanced proven (`proof,embedded-fr`) Midnight Standard transaction and locate the
/// one intent the wallet must sign. The balancer folds all of the wallet's balancing unshielded inputs
/// and its dust fee into a single chosen intent, so at most one intent carries guaranteed unshielded
/// inputs or dust fee registrations. Returns the Standard body plus that segment id + intent, or `None`
/// when nothing needs the wallet's key (e.g. a purely shielded, dust-spend-paid tx). Shared by the sign
/// and seal steps so both agree on which intent to sign; every other intent carries through untouched.
fn parse_balanced_standard(
    tx_bytes: &[u8],
) -> Result<(StdTxProvenUnsealed, Option<(u16, IntentProvenUnsealed)>), SignerError> {
    let mut r: &[u8] = tx_bytes;
    let tx: TxProvenUnsealed = tagged_deserialize(&mut r).map_err(|e| {
        SignerError::InvalidTransaction(format!("failed to parse balanced proven tx bytes: {e}"))
    })?;
    let Transaction::Standard(stx) = tx else {
        return Err(SignerError::InvalidTransaction(
            "expected Standard transaction".into(),
        ));
    };
    let mut signing: Option<(u16, IntentProvenUnsealed)> = None;
    for pair_sp in stx.intents.iter() {
        let (seg_id_sp, intent_sp) = pair_sp.deref();
        let intent = intent_sp.deref().clone();
        if intent.guaranteed_inputs().is_empty() && dust_registration_count(&intent) == 0 {
            continue;
        }
        if signing.is_some() {
            return Err(SignerError::InvalidTransaction(
                "expected at most one intent to sign; the balancer folds the wallet's inputs and \
                 dust into a single intent"
                    .into(),
            ));
        }
        signing = Some((*seg_id_sp.deref(), intent));
    }
    Ok((stx, signing))
}

/// Count the intent's dust fee registrations — the signature path the wallet signs with its Night
/// key. Dust *spends* are authorized by their own ZK proof (built and proved by the balancer) and
/// carry no signature, so they pass through untouched and are not counted here.
fn dust_registration_count(intent: &IntentProvenUnsealed) -> usize {
    intent
        .dust_actions
        .as_ref()
        .map(|da| da.deref().registrations.len())
        .unwrap_or(0)
}

/// Sign the unshielded intent of a balanced proven (`proof,embedded-fr`) Midnight Standard
/// transaction with the wallet's Night key. The dapp has already proven the contract calls / zswap
/// offers, so this is pure key work — one signature per guaranteed unshielded input and one per dust
/// fee registration, all over the intent's signing message — with no proving, no seal, and no
/// network. The signatures are returned tagged-serialized in that order (inputs, then registrations);
/// [`seal_signed_proven`] reattaches and seals them.
fn sign_proven_intent(private_key: &[u8], tx_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
    let (_stx, signing) = parse_balanced_standard(tx_bytes)?;
    let Some((seg_id, intent)) = signing else {
        // Nothing carries the wallet's key (no guaranteed unshielded inputs, no dust registration).
        return Ok(Vec::new());
    };
    let n_regs = dust_registration_count(&intent);

    let seeds = MidnightSigner::decode_keys(private_key)?;
    let signing_key = MidnightSigningKey::from_bytes(seeds.unshielded.expose()).map_err(|e| {
        SignerError::InvalidPrivateKey(format!("invalid midnight signing key: {e}"))
    })?;
    let vk = signing_key.verifying_key();

    // Every guaranteed unshielded input must be owned by the signing key — the ledger appends one
    // signature per guaranteed input, each verified against that input's owner.
    let inputs = intent.guaranteed_inputs();
    for inp in &inputs {
        if inp.owner != vk {
            return Err(SignerError::SigningFailed(
                "all guaranteed unshielded inputs must be owned by the signing key".into(),
            ));
        }
    }
    // Each dust fee registration is likewise keyed to (and signed by) the wallet's Night key.
    if let Some(da) = intent.dust_actions.as_ref() {
        for reg in da.deref().registrations.iter() {
            if reg.night_key != vk {
                return Err(SignerError::SigningFailed(
                    "dust fee registration must be owned by the signing key".into(),
                ));
            }
        }
    }

    // The signing message is the proof- and signature-erased intent — computable without the key,
    // and identical for every input and registration in the segment (this is what `Intent::sign`
    // signs internally).
    let data = intent
        .erase_proofs()
        .erase_signatures()
        .data_to_sign(seg_id);

    let mut rng = OsRng;
    let mut out = Vec::new();
    for _ in 0..(inputs.len() + n_regs) {
        let sig = signing_key.sign(&mut rng, &data);
        // Plain (untagged) serialization: tagged_deserialize insists on consuming the whole buffer,
        // so it can't read a concatenation of signatures back one at a time — `seal_signed_proven`
        // reads exactly `inputs + registrations` of them.
        sig.serialize(&mut out)
            .map_err(|e| SignerError::SigningFailed(format!("serialize signature: {e}")))?;
    }
    Ok(out)
}

/// Reattach the [`sign_proven_intent`] signatures to the balanced proven transaction and seal it.
/// Keyless: `add_signatures` and `.seal()` take no key, only an RNG. Returns the sealed tx bytes.
fn seal_signed_proven(tx_bytes: &[u8], signatures: &[u8]) -> Result<Vec<u8>, SignerError> {
    let (stx, signing) = parse_balanced_standard(tx_bytes)?;

    // Reattach the signatures to the one signed intent (if any); every other intent carries through
    // untouched.
    let intents = match signing {
        None => stx.intents.clone(),
        Some((seg_id, mut intent)) => {
            let n_regs = dust_registration_count(&intent);
            let n_inputs = intent.guaranteed_inputs().len();
            let mut r: &[u8] = signatures;
            let mut sigs: Vec<MnSignature> = Vec::with_capacity(n_inputs + n_regs);
            for _ in 0..(n_inputs + n_regs) {
                sigs.push(MnSignature::deserialize(&mut r, 0).map_err(|e| {
                    SignerError::InvalidTransaction(format!("parse signature: {e}"))
                })?);
            }
            // Signatures are ordered inputs-then-registrations, matching `sign_proven_intent`.
            let (input_sigs, reg_sigs) = sigs.split_at(n_inputs);

            if let Some(offer_sp) = intent.guaranteed_unshielded_offer.as_ref() {
                let mut offer = offer_sp.deref().clone();
                offer.add_signatures(input_sigs.to_vec());
                intent.guaranteed_unshielded_offer = Some(Sp::new(offer));
            }

            // Attach one signature to each dust fee registration, in order.
            if let Some(da_sp) = intent.dust_actions.as_ref() {
                let da = da_sp.deref().clone();
                let registrations: Vec<DustRegistration<MnSignature, InMemoryDB>> = da
                    .registrations
                    .iter()
                    .zip(reg_sigs)
                    .map(|(reg, sig)| {
                        let mut reg = (*reg).clone();
                        reg.signature = Some(Sp::new(sig.clone()));
                        reg
                    })
                    .collect();
                intent.dust_actions = Some(Sp::new(DustActions {
                    spends: da.spends.clone(),
                    registrations: registrations.into(),
                    ctime: da.ctime,
                }));
            }

            // Replace only the signed intent; the dapp's other intents carry through.
            stx.intents.insert(seg_id, intent)
        }
    };
    let stx_signed = StandardTransaction {
        network_id: stx.network_id.clone(),
        intents,
        guaranteed_coins: stx.guaranteed_coins.clone(),
        fallible_coins: stx.fallible_coins.clone(),
        binding_randomness: stx.binding_randomness,
    };
    let tx_signed: TxProvenUnsealed = Transaction::Standard(stx_signed);

    let sealed = tx_signed.seal(StdRng::from_entropy());

    let mut out = Vec::new();
    tagged_serialize(&sealed, &mut out)
        .map_err(|e| SignerError::SigningFailed(format!("serialize sealed tx: {e}")))?;
    Ok(out)
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

    /// Midnight has no raw private-key import. Its account is the three role seeds
    /// packed into an `MNK1` bundle, which only mnemonic derivation produces; a
    /// single imported curve key cannot represent it. Universal-wallet import skips
    /// Midnight rather than deriving a meaningless account from a bare key.
    fn supports_private_key_import(&self) -> bool {
        false
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        // Address derivation is routed through the multi-key bundle (`encode_keys` ->
        // `derive_address`), so `private_key` is the packed `MNK1` signing key. Decode it to
        // the unshielded seed and build the Night address.
        let seeds = Self::decode_keys(private_key)?;
        self.derive_unshielded_address_with_hrp(
            seeds.unshielded.expose(),
            &self.network.unshielded_hrp()?,
        )
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
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let signature = sign_proven_intent(private_key, tx_bytes)?;
        Ok(SignOutput {
            signature,
            recovery_id: None,
            public_key: None,
        })
    }

    /// Reattach the [`sign_proven_intent`] signatures and seal the transaction. Keyless — the
    /// `signature` blob carries everything the seal needs.
    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        seal_signed_proven(tx_bytes, &signature.signature)
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

    #[test]
    fn midnight_unshielded_mainnet_address_vector() {
        let signer = MidnightSigner::mainnet();
        assert_eq!(
            signer.derive_address(&signing_key_blob()).unwrap(),
            "mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"
        );
    }

    #[test]
    fn crypto_provider_addresses_equals_derive_addresses() {
        let blob = signing_key_blob();
        let provider = MidnightSigner::mainnet()
            .crypto_provider(&SecretBytes::from_slice(&blob))
            .unwrap();
        let expected = MidnightSigner::mainnet().derive_addresses(&blob).unwrap();
        let got = provider.addresses(&MidnightNetwork::mainnet()).unwrap();
        assert_eq!(got.unshielded, expected.unshielded);
        assert_eq!(got.shielded, expected.shielded);
        assert_eq!(got.dust, expected.dust);
    }

    #[test]
    fn crypto_provider_dust_key_and_fingerprint_derive_from_seeds() {
        let provider = MidnightSigner::mainnet()
            .crypto_provider(&SecretBytes::from_slice(&signing_key_blob()))
            .unwrap();
        // Dust public key equals deriving it straight from the role seed.
        let dust_seed: [u8; 32] = hex::decode(DUST_KEY_HEX).unwrap().try_into().unwrap();
        let expect_dpk = DustPublicKey::from(DustSecretKey::derive_secret_key(&dust_seed));
        assert_eq!(provider.dust_public_key().unwrap(), expect_dpk);
        // The shielded key never leaves the provider; its fingerprint is stable and non-zero.
        assert_ne!(provider.shielded_key_fingerprint().unwrap(), [0u8; 32]);
    }

    /// With an empty dust state (no generated dust notes) the spend selection can cover nothing and
    /// errors before ever touching the prover — the reachable slice of the proof-bearing dust path
    /// without real dust notes or proving keys.
    #[test]
    fn build_preimage_dust_spends_errors_when_the_wallet_has_no_dust() {
        let provider = MidnightSigner::mainnet()
            .crypto_provider(&SecretBytes::from_slice(&signing_key_blob()))
            .unwrap();
        let st = DustLocalState::new(midnight_ledger::dust::INITIAL_DUST_PARAMETERS);
        let e = provider
            .build_preimage_dust_spends(st, 10_000, Timestamp::from_secs(2_000))
            .unwrap_err();
        assert!(
            format!("{e}").contains("insufficient DUST balance"),
            "unexpected error: {e}"
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
    fn midnight_derive_addresses_mainnet_vector() {
        let signer = MidnightSigner::mainnet();
        let addrs = signer.derive_addresses(&signing_key_blob()).unwrap();
        assert_eq!(
            addrs.unshielded,
            "mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"
        );
        assert_eq!(
            addrs.shielded,
            "mn_shield-addr1ywxc2p9986usecc9xert79afzq4m9x35u62sx0a4e2tc5w6mta5ulwhc432vhrlpnvygfep3pxcdt8tgzfstesrm6tf7hjc5jgpl20gcwvwgz"
        );
        assert_eq!(
            addrs.dust,
            "mn_dust1wwcff2ckd4n5hfj43055td8glwtzkhhf6z88xwf0rpftvgstr7zpxpl07jx"
        );
    }

    #[test]
    fn midnight_preview_unshielded_address_uses_preview_hrp() {
        let addr = MidnightSigner::preview()
            .derive_address(&signing_key_blob())
            .unwrap();
        assert!(addr.starts_with("mn_addr_preview1"));
    }

    #[test]
    fn midnight_derive_addresses_preview_uses_preview_hrps() {
        let addrs = MidnightSigner::preview()
            .derive_addresses(&signing_key_blob())
            .unwrap();
        assert!(addrs.unshielded.starts_with("mn_addr_preview1"));
        assert!(addrs.shielded.starts_with("mn_shield-addr_preview1"));
        assert!(addrs.dust.starts_with("mn_dust_preview1"));
    }

    #[test]
    fn midnight_preview_unshielded_address_matches_reencode() {
        let key = signing_key_blob();
        let mainnet_addr = MidnightSigner::mainnet().derive_address(&key).unwrap();
        let preview_addr = MidnightSigner::preview().derive_address(&key).unwrap();
        let reencoded = MidnightSigner::preview()
            .reencode_unshielded_address(&mainnet_addr)
            .unwrap();
        assert_eq!(reencoded, preview_addr);
    }

    #[test]
    fn midnight_from_chain_id_maps_networks() {
        assert_eq!(
            MidnightSigner::from_chain_id("midnight:mainnet").network,
            MidnightNetwork::mainnet()
        );
        assert_eq!(
            MidnightSigner::from_chain_id("midnight:preview").network,
            MidnightNetwork::preview()
        );
        assert_eq!(
            MidnightSigner::from_chain_id("midnight:preprod").network,
            MidnightNetwork::preprod()
        );
    }

    #[test]
    fn midnight_from_chain_id_preserves_arbitrary_reference() {
        // No cast to mainnet and no panic: an unregistered id is preserved verbatim as an
        // ad-hoc feature testnet.
        let net = MidnightSigner::from_chain_id("midnight:feature-x").network;
        assert_eq!(net.reference(), "feature-x");
        assert_ne!(net, MidnightNetwork::mainnet());

        // Its address HRPs carry the reference, so a feature-net address can't be mistaken for
        // a mainnet one.
        let addrs = MidnightSigner::from_chain_id("midnight:feature-x")
            .derive_addresses(&signing_key_blob())
            .unwrap();
        assert!(addrs.unshielded.starts_with("mn_addr_feature-x1"));
        assert!(addrs.shielded.starts_with("mn_shield-addr_feature-x1"));
        assert!(addrs.dust.starts_with("mn_dust_feature-x1"));
    }

    #[test]
    fn midnight_rejects_malformed_network_reference() {
        // Rejected, not coerced: a mixed-case, structurally invalid, or empty reference surfaces
        // as an address-derivation error instead of minting a wrong-but-valid-looking address.
        for chain_id in [
            "midnight:Preview", // uppercase is not lowercased
            "midnight:foo/bar", // illegal HRP character
            "midnight:-bad",    // leading hyphen
            "midnight:bad-",    // trailing hyphen
            "midnight:",        // empty reference
        ] {
            let result =
                MidnightSigner::from_chain_id(chain_id).derive_addresses(&signing_key_blob());
            assert!(
                matches!(result, Err(SignerError::AddressDerivationFailed(_))),
                "{chain_id} should be rejected"
            );
        }
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

    #[test]
    fn midnight_opts_out_of_private_key_import() {
        // A single raw curve key can't represent the three-seed MNK1 bundle, so
        // universal-wallet import skips Midnight rather than deriving from a bare key.
        assert!(!MidnightSigner::mainnet().supports_private_key_import());
    }
}
