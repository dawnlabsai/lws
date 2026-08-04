use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use crate::{DerivedKey, SecretBytes};
use cardano_serialization_lib::{
    make_vkey_witness, Address, AddressKind, BaseAddress, Bip32PrivateKey, Certificate,
    CertificateKind, Credential, Ed25519KeyHashes, EnterpriseAddress, FixedTransaction,
    NetworkInfo, RewardAddress, TransactionBody, Vkeywitnesses,
};
use emurgo_cardano_message_signing::builders::{AlgorithmId, COSESign1Builder, EdDSA25519Key};
use emurgo_cardano_message_signing::cbor::CBORValue;
use emurgo_cardano_message_signing::utils::ToBytes as EmurgoToBytes;
use emurgo_cardano_message_signing::{
    HeaderMap, Headers, Label, ProtectedHeaderMap, SignedMessage,
};
use ows_core::policy::{TransactionContext, TransactionEffect};
use ows_core::{CardanoRpcProvider, ChainType};
use std::collections::{BTreeMap, BTreeSet};

pub struct CardanoSigner {
    network_id: u8,
}

const LOVELACE_ASSET_ID: &str = "lovelace";

type AssetBalanceMap = BTreeMap<String, u64>;

struct Asset {
    policy_id: String,
    asset_name: String,
    quantity: u64,
}

struct Utxo {
    #[allow(dead_code)]
    tx_hash: String,
    #[allow(dead_code)]
    tx_index: u32,
    address: String,
    lovelace: u64,
    assets: Vec<Asset>,
}

impl CardanoSigner {
    pub fn mainnet() -> Self {
        Self {
            network_id: NetworkInfo::mainnet().network_id(),
        }
    }

    pub fn preprod() -> Self {
        Self {
            network_id: NetworkInfo::testnet_preprod().network_id(),
        }
    }

    pub fn preview() -> Self {
        Self {
            network_id: NetworkInfo::testnet_preview().network_id(),
        }
    }

    pub fn from_chain_id(chain_id: &str) -> Self {
        match chain_id {
            "cip34:0-1" => Self::preprod(),
            "cip34:0-2" => Self::preview(),
            _ => Self::mainnet(),
        }
    }

    /// CIP-1852 payment key path where index is the account index: `m/1852'/1815'/{index}'/0/0`.
    pub fn payment_derivation_path(index: u32) -> String {
        format!("m/1852'/1815'/{index}'/0/0")
    }

    /// CIP-1852 stake key path where index is the account index: `m/1852'/1815'/{index}'/2/0`.
    pub fn stake_derivation_path(index: u32) -> String {
        format!("m/1852'/1815'/{index}'/2/0")
    }

    fn decode_keys(
        key_material: &[u8],
    ) -> Result<(Bip32PrivateKey, Option<Bip32PrivateKey>), SignerError> {
        match key_material.len() {
            ed25519_bip32::XPRV_SIZE => {
                let pay = Bip32PrivateKey::from_bytes(key_material)
                    .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
                Ok((pay, None))
            }
            len if len == ed25519_bip32::XPRV_SIZE * 2 => {
                let pay = Bip32PrivateKey::from_bytes(&key_material[..ed25519_bip32::XPRV_SIZE])
                    .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
                let stake = Bip32PrivateKey::from_bytes(&key_material[ed25519_bip32::XPRV_SIZE..])
                    .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
                Ok((pay, Some(stake)))
            }
            _ => Err(SignerError::InvalidPrivateKey(format!(
                "Cardano key material must be 96 (payment) or 192 (payment||stake) bytes, got {}",
                key_material.len()
            ))),
        }
    }

    fn base_address_bech32(
        &self,
        pay: &Bip32PrivateKey,
        stake: &Bip32PrivateKey,
    ) -> Result<String, SignerError> {
        let network_id = self.network_id;
        let pay_cred = Credential::from_keyhash(&pay.to_public().to_raw_key().hash());
        let stake_cred = Credential::from_keyhash(&stake.to_public().to_raw_key().hash());
        let base = BaseAddress::new(network_id, &pay_cred, &stake_cred);
        base.to_address()
            .to_bech32(None)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))
    }

    fn enterprise_address_bech32(&self, pay: &Bip32PrivateKey) -> Result<String, SignerError> {
        let network_id = self.network_id;
        let pay_cred = Credential::from_keyhash(&pay.to_public().to_raw_key().hash());
        let ent = EnterpriseAddress::new(network_id, &pay_cred);
        ent.to_address()
            .to_bech32(None)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))
    }

    /// Adds the vkey hashes `cert` needs a signature from, limited to the credential
    /// kinds that can be a CIP-1852 stake key. Mirrors the stake-credential arms of
    /// the ledger's `witsVKeyNeeded`.
    fn add_cert_key_hashes(cert: &Certificate, hashes: &mut Ed25519KeyHashes) {
        let stake_credential = match cert.kind() {
            // A legacy `stake_registration` needs no witness; a Conway `reg_cert`
            // (registration with an explicit deposit) does. `as_reg_cert` returns
            // `Some` only for the latter.
            CertificateKind::StakeRegistration => cert.as_reg_cert().map(|c| c.stake_credential()),
            CertificateKind::StakeDeregistration => {
                cert.as_stake_deregistration().map(|c| c.stake_credential())
            }
            CertificateKind::StakeDelegation => {
                cert.as_stake_delegation().map(|c| c.stake_credential())
            }
            CertificateKind::StakeAndVoteDelegation => cert
                .as_stake_and_vote_delegation()
                .map(|c| c.stake_credential()),
            CertificateKind::StakeRegistrationAndDelegation => cert
                .as_stake_registration_and_delegation()
                .map(|c| c.stake_credential()),
            CertificateKind::StakeVoteRegistrationAndDelegation => cert
                .as_stake_vote_registration_and_delegation()
                .map(|c| c.stake_credential()),
            CertificateKind::VoteDelegation => {
                cert.as_vote_delegation().map(|c| c.stake_credential())
            }
            CertificateKind::VoteRegistrationAndDelegation => cert
                .as_vote_registration_and_delegation()
                .map(|c| c.stake_credential()),
            // Pool owners are stake key hashes. The operator is a cold pool key, so
            // it is not collected here.
            CertificateKind::PoolRegistration => {
                if let Some(cert) = cert.as_pool_registration() {
                    let owners = cert.pool_params().pool_owners();
                    for i in 0..owners.len() {
                        hashes.add(&owners.get(i));
                    }
                }
                None
            }
            // Pool cold keys, genesis delegates, committee cold credentials and DRep
            // credentials are never derived at the CIP-1852 stake role, so a stake
            // key can never satisfy them and we do not collect them.
            CertificateKind::PoolRetirement
            | CertificateKind::GenesisKeyDelegation
            | CertificateKind::MoveInstantaneousRewardsCert
            | CertificateKind::CommitteeHotAuth
            | CertificateKind::CommitteeColdResign
            | CertificateKind::DRepRegistration
            | CertificateKind::DRepDeregistration
            | CertificateKind::DRepUpdate => None,
        };

        // Script credentials are witnessed by the script, not by a vkey.
        if let Some(hash) = stake_credential.and_then(|c| c.to_keyhash()) {
            hashes.add(&hash);
        }
    }

    /// Vkey hashes the transaction structurally requires a stake signature from:
    /// certificate stake credentials, pool owners and withdrawal reward accounts.
    ///
    /// `required_signers` is deliberately not folded in here: a hash listed there
    /// routinely belongs to a co-signer rather than to this wallet, so it must not
    /// drive the "we are missing a stake key" error.
    fn stake_key_hashes_required_by_body(body: &TransactionBody) -> Ed25519KeyHashes {
        let mut hashes = Ed25519KeyHashes::new();

        if let Some(certs) = body.certs() {
            for i in 0..certs.len() {
                Self::add_cert_key_hashes(&certs.get(i), &mut hashes);
            }
        }

        if let Some(withdrawals) = body.withdrawals() {
            let reward_addresses = withdrawals.keys();
            for i in 0..reward_addresses.len() {
                if let Some(hash) = reward_addresses.get(i).payment_cred().to_keyhash() {
                    hashes.add(&hash);
                }
            }
        }

        hashes
    }

    fn reward_address_bech32(&self, stake: &Bip32PrivateKey) -> Result<String, SignerError> {
        let network_id = self.network_id;
        let stake_cred = Credential::from_keyhash(&stake.to_public().to_raw_key().hash());
        let rew = RewardAddress::new(network_id, &stake_cred);
        rew.to_address()
            .to_bech32(None)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))
    }

    /// Explicit deposit/refund carried on a certificate, attributed to the
    /// credential's reward address. Legacy Shelley certs without an on-wire
    /// `coin` are skipped (amount comes from protocol parameters).
    ///
    /// Returns `(credential, lovelace, is_deposit)`.
    fn cert_deposit_or_refund(cert: &Certificate) -> Option<(Credential, u64, bool)> {
        match cert.kind() {
            CertificateKind::StakeRegistration => cert.as_reg_cert().and_then(|c| {
                c.coin()
                    .map(|coin| (c.stake_credential(), u64::from(coin), true))
            }),
            CertificateKind::StakeDeregistration => cert.as_unreg_cert().and_then(|c| {
                c.coin()
                    .map(|coin| (c.stake_credential(), u64::from(coin), false))
            }),
            CertificateKind::StakeRegistrationAndDelegation => cert
                .as_stake_registration_and_delegation()
                .map(|c| (c.stake_credential(), u64::from(c.coin()), true)),
            CertificateKind::StakeVoteRegistrationAndDelegation => cert
                .as_stake_vote_registration_and_delegation()
                .map(|c| (c.stake_credential(), u64::from(c.coin()), true)),
            CertificateKind::VoteRegistrationAndDelegation => cert
                .as_vote_registration_and_delegation()
                .map(|c| (c.stake_credential(), u64::from(c.coin()), true)),
            CertificateKind::DRepRegistration => cert
                .as_drep_registration()
                .map(|c| (c.voting_credential(), u64::from(c.coin()), true)),
            CertificateKind::DRepDeregistration => cert
                .as_drep_deregistration()
                .map(|c| (c.voting_credential(), u64::from(c.coin()), false)),
            _ => None,
        }
    }

    fn add_lovelace_balance(
        balances: &mut BTreeMap<String, AssetBalanceMap>,
        address: String,
        amount: u64,
    ) {
        *balances
            .entry(address)
            .or_default()
            .entry(LOVELACE_ASSET_ID.to_string())
            .or_insert(0) += amount;
    }

    /// Fetches UTXOs by retrieving each referenced transaction's CBOR and verifying
    /// that `transaction_hash()` matches the expected hash. This prevents a malicious
    /// RPC provider from returning fabricated UTXO data under a trusted tx hash.
    fn fetch_utxos(
        provider: &dyn CardanoRpcProvider,
        input_refs: &[(String, u32)],
    ) -> Result<Vec<Utxo>, SignerError> {
        if input_refs.is_empty() {
            return Ok(Vec::new());
        }

        let unique_hashes: Vec<String> = input_refs
            .iter()
            .map(|(hash, _)| hash.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let txs_cbor = provider
            .fetch_txs_cbor(&unique_hashes)
            .map_err(|e| SignerError::RpcError(e.to_string()))?;

        for hash in &unique_hashes {
            if !txs_cbor.contains_key(hash) {
                return Err(SignerError::RpcError(format!(
                    "Koios tx_cbor missing transaction {hash}"
                )));
            }
        }

        let mut verified_txs: BTreeMap<String, FixedTransaction> = BTreeMap::new();
        for (expected_hash, cbor_hex) in &txs_cbor {
            let cbor_bytes = hex::decode(cbor_hex).map_err(|e| {
                SignerError::RpcError(format!("invalid CBOR hex for tx {expected_hash}: {e}"))
            })?;
            let tx = FixedTransaction::from_bytes(cbor_bytes).map_err(|e| {
                SignerError::RpcError(format!("invalid CBOR for tx {expected_hash}: {e}"))
            })?;
            let actual_hash = tx.transaction_hash().to_hex();
            if &actual_hash != expected_hash {
                return Err(SignerError::RpcError(format!(
                    "CBOR hash mismatch for tx {expected_hash}: got {actual_hash}"
                )));
            }
            verified_txs.insert(expected_hash.clone(), tx);
        }

        let mut utxos = Vec::with_capacity(input_refs.len());
        for (tx_hash, index) in input_refs {
            let tx = verified_txs
                .get(tx_hash)
                .expect("missing tx already checked above");
            let outputs = tx.body().outputs();
            let index_usize = *index as usize;
            if index_usize >= outputs.len() {
                return Err(SignerError::InvalidTransaction(format!(
                    "input {tx_hash}#{index} out of range (tx has {} outputs)",
                    outputs.len()
                )));
            }

            let output = outputs.get(index_usize);
            let address = output.address().to_bech32(None).map_err(|e| {
                SignerError::InvalidTransaction(format!(
                    "invalid address on input {tx_hash}#{index}: {e}"
                ))
            })?;
            let lovelace: u64 = output.amount().coin().into();

            let assets = match output.amount().multiasset() {
                Some(ma) if ma.keys().len() > 0 => {
                    let mut assets = Vec::new();
                    for policy_id_index in 0..ma.keys().len() {
                        let policy_id = ma.keys().get(policy_id_index);
                        let policy_assets = ma.get(&policy_id).unwrap();
                        for asset_index in 0..policy_assets.len() {
                            let asset_name = policy_assets.keys().get(asset_index);
                            let quantity: u64 = policy_assets.get(&asset_name).unwrap().into();
                            assets.push(Asset {
                                policy_id: policy_id.to_hex(),
                                asset_name: hex::encode(asset_name.name()),
                                quantity,
                            });
                        }
                    }
                    assets
                }
                _ => Vec::new(),
            };

            utxos.push(Utxo {
                tx_hash: tx_hash.clone(),
                tx_index: *index,
                address,
                lovelace,
                assets,
            });
        }

        Ok(utxos)
    }
}

impl ChainSigner for CardanoSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Cardano
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519Bip32
    }

    fn coin_type(&self) -> u32 {
        1815
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let (pay, stake) = Self::decode_keys(private_key)?;
        match stake.as_ref() {
            Some(s) => self.base_address_bech32(&pay, s),
            None => self.enterprise_address_bech32(&pay),
        }
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let (pay, _) = Self::decode_keys(private_key)?;
        let public_key = pay.to_public().to_raw_key().as_bytes();

        let signature = pay.to_raw_key().sign(message).to_bytes();

        Ok(SignOutput {
            signature,
            recovery_id: None,
            public_key: Some(public_key),
        })
    }

    fn sign_message(
        &self,
        private_key: &[u8],
        message: &[u8],
        address: Option<&str>,
    ) -> Result<SignOutput, SignerError> {
        let (pay, stake) = Self::decode_keys(private_key)?;

        let (address_bytes, sk) = match address {
            Some(a) => {
                let addr = Address::from_bech32(a)
                    .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

                let sk = match addr.kind() {
                    AddressKind::Reward => {
                        let stake = stake.map_or_else(
                            || {
                                Err(SignerError::InvalidPrivateKey(
                                    "provided private key does not have a stake key".to_string(),
                                ))
                            },
                            Ok,
                        )?;

                        if self.reward_address_bech32(&stake)? != a {
                            return Err(SignerError::AddressMismatch);
                        }

                        stake
                    }
                    AddressKind::Base => {
                        let stake = stake.map_or_else(
                            || {
                                Err(SignerError::InvalidPrivateKey(
                                    "provided private key does not have a stake key".to_string(),
                                ))
                            },
                            Ok,
                        )?;

                        if self.base_address_bech32(&pay, &stake)? != a {
                            return Err(SignerError::AddressMismatch);
                        }

                        pay
                    }
                    AddressKind::Enterprise => {
                        if self.enterprise_address_bech32(&pay)? != a {
                            return Err(SignerError::AddressMismatch);
                        }

                        pay
                    }
                    _ => {
                        return Err(SignerError::AddressMismatch);
                    }
                };

                (addr.to_bytes(), sk)
            }
            // if the address is not provided, we sign the message with the payment credentials and address derived from the provided private key
            None => {
                let addr = Address::from_bech32(&match stake.as_ref() {
                    Some(s) => self.base_address_bech32(&pay, s)?,
                    None => self.enterprise_address_bech32(&pay)?,
                })
                .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

                (addr.to_bytes(), pay)
            }
        };

        let mut protected_headers = HeaderMap::new();
        protected_headers.set_algorithm_id(&AlgorithmId::EdDSA.into());
        protected_headers
            .set_header(
                &Label::new_text(String::from("address")),
                &CBORValue::new_bytes(address_bytes),
            )
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let protected_headers_serialized = ProtectedHeaderMap::new(&protected_headers);
        let headers: Headers = Headers::new(&protected_headers_serialized, &HeaderMap::new());

        let builder = COSESign1Builder::new(&headers, message.to_vec(), false);
        let sig_structure = builder.make_data_to_sign();
        let sig_bytes = EmurgoToBytes::to_bytes(&sig_structure);

        let sig = sk.to_raw_key().sign(&sig_bytes);

        let cose = builder.build(sig.to_bytes());
        let signed = SignedMessage::new_cose_sign1(&cose);
        let signature = EmurgoToBytes::to_bytes(&signed);
        let cose_key = EdDSA25519Key::new(sk.to_public().to_raw_key().as_bytes()).build();

        Ok(SignOutput {
            signature,
            recovery_id: None,
            public_key: Some(EmurgoToBytes::to_bytes(&cose_key)),
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let (pay, stake) = Self::decode_keys(private_key)?;

        let tx = FixedTransaction::from_bytes(tx_bytes.to_vec())
            .map_err(|e| SignerError::InvalidTransaction(e.to_string()))?;

        let tx_hash = tx.transaction_hash();
        let body = tx.body();
        let stake_hashes = Self::stake_key_hashes_required_by_body(&body);

        let pay_witness = make_vkey_witness(&tx_hash, &pay.to_raw_key());

        let mut witnesses = Vkeywitnesses::new();
        witnesses.add(&pay_witness);

        match stake {
            Some(stake) => {
                let stake_hash = stake.to_public().to_raw_key().hash();
                let needs_stake_signature = stake_hashes.contains(&stake_hash)
                    || body
                        .required_signers()
                        .map(|required_signers| required_signers.contains(&stake_hash))
                        .unwrap_or(false);

                if needs_stake_signature {
                    witnesses.add(&make_vkey_witness(&tx_hash, &stake.to_raw_key()));
                }
            }
            None => {
                // No stake key to offer. If the body needs one for anything other than
                // the payment credential, refuse rather than hand back a transaction
                // that fails phase-1 validation.
                let pay_hash = pay.to_public().to_raw_key().hash();
                let unsatisfied = (0..stake_hashes.len())
                    .map(|i| stake_hashes.get(i))
                    .any(|hash| hash != pay_hash);

                if unsatisfied {
                    return Err(SignerError::InvalidTransaction(
                        "transaction requires a stake key signature but the key material \
                         contains no stake key"
                            .into(),
                    ));
                }
            }
        }

        let signature = witnesses.to_bytes();

        Ok(SignOutput {
            // signature is the CBOR-encoded witness set
            signature,
            recovery_id: None,
            public_key: Some(pay_witness.vkey().public_key().as_bytes()),
        })
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        let mut tx = FixedTransaction::from_bytes(tx_bytes.to_vec())
            .map_err(|e| SignerError::InvalidTransaction(e.to_string()))?;

        let witnesses = Vkeywitnesses::from_bytes(signature.signature.clone())
            .map_err(|e| SignerError::InvalidTransaction(e.to_string()))?;

        for witness in witnesses.into_iter() {
            tx.add_vkey_witness(witness);
        }

        Ok(tx.to_bytes())
    }

    fn make_transaction_context(
        &self,
        tx_bytes: &[u8],
        rpc_url: Option<&str>,
    ) -> Result<TransactionContext, SignerError> {
        let tx_hex = hex::encode(tx_bytes);

        let tx = FixedTransaction::from_bytes(tx_bytes.to_vec())
            .map_err(|e| SignerError::InvalidTransaction(e.to_string()))?;

        let tx_input_refs: Vec<(String, u32)> = tx
            .body()
            .inputs()
            .into_iter()
            .map(|input| (input.transaction_id().to_hex(), input.index()))
            .collect();

        let mut inputs_balances_by_address: BTreeMap<String, AssetBalanceMap> = BTreeMap::new();
        if !tx_input_refs.is_empty() {
            let rpc_url = rpc_url.ok_or_else(|| {
                SignerError::InvalidMessage(
                    "Cardano RPC URL is required to fetch transaction inputs".into(),
                )
            })?;
            let provider = ows_core::resolve_cardano_provider(rpc_url)
                .map_err(|e| SignerError::RpcError(e.to_string()))?;
            let utxos = Self::fetch_utxos(provider.as_ref(), &tx_input_refs)?;

            for utxo in utxos {
                let inputs_balances_for_address =
                    inputs_balances_by_address.entry(utxo.address).or_default();

                *inputs_balances_for_address
                    .entry(LOVELACE_ASSET_ID.to_string())
                    .or_insert(0) += utxo.lovelace;

                for asset in utxo.assets {
                    *inputs_balances_for_address
                        .entry(format!("{}{}", asset.policy_id, asset.asset_name))
                        .or_insert(0) += asset.quantity;
                }
            }
        }

        let mut outputs_balances_by_address: BTreeMap<String, AssetBalanceMap> = BTreeMap::new();
        for output in tx.body().outputs().into_iter() {
            let dest_address = output.address().to_bech32(None).map_err(|e| {
                SignerError::InvalidTransaction(format!("invalid output address: {e}"))
            })?;

            let output_balances_for_address =
                outputs_balances_by_address.entry(dest_address).or_default();

            let lovelace: u64 = output.amount().coin().into();

            *output_balances_for_address
                .entry(LOVELACE_ASSET_ID.to_string())
                .or_insert(0) += lovelace;

            let ma = output.amount().multiasset();
            if ma.is_none() {
                continue;
            }

            let ma = ma.unwrap();

            for policy_id_index in 0..ma.keys().len() {
                let policy_id = ma.keys().get(policy_id_index);
                let assets = ma.get(&policy_id).unwrap();

                for asset_index in 0..assets.len() {
                    let asset_name = assets.keys().get(asset_index);
                    let asset_quantity = assets.get(&asset_name).unwrap();
                    let asset_quantity: u64 = asset_quantity.into();

                    *output_balances_for_address
                        .entry(format!(
                            "{}{}",
                            policy_id.to_hex(),
                            hex::encode(asset_name.name())
                        ))
                        .or_insert(0) += asset_quantity;
                }
            }
        }

        // Withdrawals leave the reward account and enter the transaction, so
        // treat them as inputs from the reward address.
        if let Some(withdrawals) = tx.body().withdrawals() {
            let reward_addresses = withdrawals.keys();
            for i in 0..reward_addresses.len() {
                let reward_address = reward_addresses.get(i);
                let amount: u64 = withdrawals
                    .get(&reward_address)
                    .ok_or_else(|| {
                        SignerError::InvalidTransaction(
                            "withdrawal amount missing for reward address".into(),
                        )
                    })?
                    .into();
                let addr = reward_address.to_address().to_bech32(None).map_err(|e| {
                    SignerError::InvalidTransaction(format!("invalid withdrawal address: {e}"))
                })?;
                Self::add_lovelace_balance(&mut inputs_balances_by_address, addr, amount);
            }
        }

        // Certificate deposits lock lovelace under the credential (like an
        // output to its reward address); refunds unlock it (like an input).
        if let Some(certs) = tx.body().certs() {
            for i in 0..certs.len() {
                let Some((credential, amount, is_deposit)) =
                    Self::cert_deposit_or_refund(&certs.get(i))
                else {
                    continue;
                };
                let addr = RewardAddress::new(self.network_id, &credential)
                    .to_address()
                    .to_bech32(None)
                    .map_err(|e| {
                        SignerError::InvalidTransaction(format!(
                            "invalid certificate reward address: {e}"
                        ))
                    })?;
                if is_deposit {
                    Self::add_lovelace_balance(&mut outputs_balances_by_address, addr, amount);
                } else {
                    Self::add_lovelace_balance(&mut inputs_balances_by_address, addr, amount);
                }
            }
        }

        let mut all_addresses: BTreeSet<&String> = BTreeSet::new();
        for c in inputs_balances_by_address.keys() {
            all_addresses.insert(c);
        }
        for c in outputs_balances_by_address.keys() {
            all_addresses.insert(c);
        }

        let empty_balances = AssetBalanceMap::new();
        let mut effects: Vec<TransactionEffect> = Vec::new();
        for effect_address in all_addresses {
            let input_balances = inputs_balances_by_address
                .get(effect_address)
                .unwrap_or(&empty_balances);
            let output_balances = outputs_balances_by_address
                .get(effect_address)
                .unwrap_or(&empty_balances);

            let mut asset_ids: BTreeSet<&String> = BTreeSet::new();
            for k in input_balances.keys() {
                asset_ids.insert(k);
            }
            for k in output_balances.keys() {
                asset_ids.insert(k);
            }

            let mut diff: Vec<(String, i64)> = Vec::new();
            for asset_id in asset_ids {
                let input_balance = *input_balances.get(asset_id).unwrap_or(&0);
                let output_balance = *output_balances.get(asset_id).unwrap_or(&0);

                let asset_diff = (output_balance as i64) - (input_balance as i64);
                if asset_diff == 0 {
                    continue;
                }

                diff.push((asset_id.clone(), asset_diff));
            }

            if diff.is_empty() {
                continue;
            }

            diff.sort_by(|a, b| a.0.cmp(&b.0));
            effects.push(TransactionEffect {
                address: effect_address.clone(),
                diff,
            });
        }

        effects.sort_by(|a, b| a.address.cmp(&b.address));

        Ok(TransactionContext {
            effects,
            raw_hex: tx_hex,
            data: None,
        })
    }

    fn default_derivation_path(&self, index: u32) -> String {
        Self::payment_derivation_path(index)
    }

    fn default_derivation_paths(&self, index: u32) -> Vec<String> {
        vec![
            Self::payment_derivation_path(index),
            Self::stake_derivation_path(index),
        ]
    }

    fn encode_keys(&self, keys: &[DerivedKey]) -> Result<SecretBytes, SignerError> {
        if keys.is_empty() {
            return Err(SignerError::InvalidPrivateKey(
                "no derived keys to encode".into(),
            ));
        }

        let mut buf = Vec::new();
        for key in keys {
            buf.extend_from_slice(key.secret.expose());
        }

        if buf.len() != ed25519_bip32::XPRV_SIZE && buf.len() != ed25519_bip32::XPRV_SIZE * 2 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "Cardano encoded keys must be 96 (payment) or 192 (payment||stake) bytes, got {}",
                buf.len()
            )));
        }

        Ok(SecretBytes::new(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;
    use cardano_serialization_lib::{
        AssetName, BigNum, Certificates, Ed25519KeyHash, Ed25519KeyHashes, MultiAsset, ScriptHash,
        StakeDelegation, StakeDeregistration, StakeRegistration, TransactionBody, TransactionHash,
        TransactionInput, TransactionInputs, TransactionOutput, TransactionOutputs, Value,
        Withdrawals,
    };
    use hex::FromHex;
    use mockito::Server;

    fn derive_key_material(signer: &CardanoSigner, m: &Mnemonic, index: u32) -> SecretBytes {
        let keys = HdDeriver::derive_keys_from_mnemonic_cached(
            m,
            "",
            signer.default_derivation_paths(index),
            signer.curve(),
        )
        .unwrap();
        signer.encode_keys(&keys).unwrap()
    }

    #[test]
    fn test_cip1852_paths() {
        assert_eq!(
            CardanoSigner::payment_derivation_path(0),
            "m/1852'/1815'/0'/0/0"
        );
        assert_eq!(
            CardanoSigner::stake_derivation_path(0),
            "m/1852'/1815'/0'/2/0"
        );
        assert_eq!(
            CardanoSigner::payment_derivation_path(3),
            "m/1852'/1815'/3'/0/0"
        );
    }

    #[test]
    fn test_chain_type_and_curve() {
        let s = CardanoSigner::mainnet();
        assert_eq!(s.chain_type(), ChainType::Cardano);
        assert_eq!(s.curve(), Curve::Ed25519Bip32);
        assert_eq!(s.coin_type(), 1815);
    }

    #[test]
    fn test_default_derivation_path_is_payment() {
        let s = CardanoSigner::mainnet();
        assert_eq!(s.default_derivation_path(0), "m/1852'/1815'/0'/0/0");
        assert_eq!(s.default_derivation_path(5), "m/1852'/1815'/5'/0/0");
    }

    #[test]
    fn derive_base_address_from_12_words() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = derive_key_material(&s, &m, 0);
        assert_eq!(s.derive_address(key.expose()).unwrap(), "addr1qyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcj04pscfgjxcvtant3cxg7588twyywwm68nglxaqul8xps7np3y0");
    }

    #[test]
    fn derive_base_address_from_24_words() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase("struggle garbage joke erupt hawk write misery fold hobby shoulder speed movie earth tool medal permit fever wage kid fence off wait order state").unwrap();
        let key = derive_key_material(&s, &m, 0);
        assert_eq!(s.derive_address(key.expose()).unwrap(), "addr1q9dfl5qs6jncq6200cxqy7juhw7fm2mk5wm5p0qnx5pmsl80734zn65gc55ecvafkhuxawlnn6wevkmg8dm5kt9vxyys322t44");
    }

    #[test]
    fn derive_enterprise_address_from_12_words() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();

        let payment_path = CardanoSigner::payment_derivation_path(0);
        let payment_key = HdDeriver::derive_from_mnemonic(&m, "", &payment_path, s.curve())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
            .unwrap();

        let address = s.derive_address(&payment_key.expose()).unwrap();
        assert_eq!(
            address,
            "addr1vyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcx2tst3"
        );
    }

    #[test]
    fn derive_enterprise_address_from_24_words() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "struggle garbage joke erupt hawk write misery fold hobby shoulder speed movie earth tool medal permit fever wage kid fence off wait order state",
        )
        .unwrap();

        let payment_path = CardanoSigner::payment_derivation_path(0);
        let payment_key = HdDeriver::derive_from_mnemonic(&m, "", &payment_path, s.curve())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
            .unwrap();

        let address = s.derive_address(&payment_key.expose()).unwrap();
        assert_eq!(
            address,
            "addr1v9dfl5qs6jncq6200cxqy7juhw7fm2mk5wm5p0qnx5pmslqy6xjzf"
        );
    }

    #[test]
    fn sign_message_with_none_address() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = derive_key_material(&s, &m, 0);
        let msg = <Vec<u8>>::from_hex("cafe").unwrap();
        let sig = s.sign_message(key.expose(), &msg, None).unwrap();

        assert_eq!(hex::encode(sig.signature), "845846a20127676164647265737358390106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303127d430c25123618becd71c191ea1ceb7108e76f479a3e6e839f3983a166686173686564f442cafe5840a16c4eb2e963ebd2555292d3dd51bb6ede526ade7e127a8815c940c51a29029931bf5f1b7ce842f12efe25a8aa28037bc9fcb834501aef79ba3df9c0b80ab009");
        assert_eq!(
            hex::encode(sig.public_key.unwrap()),
            "a401010327200621582065a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128"
        );
    }

    #[test]
    fn sign_message_with_base_address() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = derive_key_material(&s, &m, 0);
        let msg = <Vec<u8>>::from_hex("cafe").unwrap();
        let sig = s.sign_message(key.expose(), &msg, Some("addr1qyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcj04pscfgjxcvtant3cxg7588twyywwm68nglxaqul8xps7np3y0")).unwrap();

        assert_eq!(hex::encode(sig.signature), "845846a20127676164647265737358390106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303127d430c25123618becd71c191ea1ceb7108e76f479a3e6e839f3983a166686173686564f442cafe5840a16c4eb2e963ebd2555292d3dd51bb6ede526ade7e127a8815c940c51a29029931bf5f1b7ce842f12efe25a8aa28037bc9fcb834501aef79ba3df9c0b80ab009");
        assert_eq!(
            hex::encode(sig.public_key.unwrap()),
            "a401010327200621582065a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128"
        );
    }

    #[test]
    fn sign_message_with_enterprise_address() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = derive_key_material(&s, &m, 0);
        let msg = <Vec<u8>>::from_hex("cafe").unwrap();
        let sig = s
            .sign_message(
                key.expose(),
                &msg,
                Some("addr1vyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcx2tst3"),
            )
            .unwrap();

        assert_eq!(hex::encode(sig.signature), "84582aa201276761646472657373581d6106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303a166686173686564f442cafe58401bb30176a6f48c3eefd4f659afd29c98e4668e4d5676474b7e4497e960e6a8e79860fd3bdb41093e448fc62aa74291490b683adb579e6a3e17a89d0b329ea70f");
        assert_eq!(
            hex::encode(sig.public_key.unwrap()),
            "a401010327200621582065a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128"
        );
    }

    #[test]
    fn sign_message_with_reward_address() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = derive_key_material(&s, &m, 0);
        let msg = <Vec<u8>>::from_hex("cafe").unwrap();
        let sig = s
            .sign_message(
                key.expose(),
                &msg,
                Some("stake1uyf86scvy5frvx97e4cury02rn4hzz88dare50nwsw0nnqcxw9kf5"),
            )
            .unwrap();

        assert_eq!(hex::encode(sig.signature), "84582aa201276761646472657373581de1127d430c25123618becd71c191ea1ceb7108e76f479a3e6e839f3983a166686173686564f442cafe58401152563eb2dd6dd9775b1e8cd21d829edb93851aba7705156b68c6b9cde9634e9f85f434287172129d8f49c655876ac64293d5ad8370247a5b04e9bdf675d505");
        assert_eq!(
            hex::encode(sig.public_key.unwrap()),
            "a4010103272006215820097cdc1da25a445eda8db6c3f0a3c3ba86c6a9555df0b4010f4d042ed94c2206"
        );
    }

    const TX_FEE: u64 = 1_000_000u64;

    type TestAsset<'a> = (&'a str, &'a str, u64); // (policy id hex, asset name hex, quantity)

    fn build_test_tx_cbor(
        inputs: &[(&str, u32)],                        // (tx hash, index)
        outputs: &[(&str, u64, Option<&[TestAsset]>)], // (bech32 address, lovelace, optional assets)
        customize: impl FnOnce(&mut TransactionBody),
    ) -> Vec<u8> {
        let mut tx_inputs = TransactionInputs::new();
        for (tx_hash, index) in inputs {
            let input_tx_hash = TransactionHash::from_bytes(hex::decode(tx_hash).unwrap()).unwrap();
            let input = TransactionInput::new(&input_tx_hash, *index);
            tx_inputs.add(&input);
        }

        let mut tx_outputs = TransactionOutputs::new();
        for (addr, lovelace, assets) in outputs {
            let mut output_value = Value::new(&BigNum::from(*lovelace));

            if let Some(assets) = assets {
                let mut multi_asset = MultiAsset::new();
                for (policy_id_hex, asset_name_hex, quantity) in assets.iter().copied() {
                    let policy_id = ScriptHash::from_hex(policy_id_hex).unwrap();
                    let asset_name = AssetName::new(hex::decode(asset_name_hex).unwrap()).unwrap();

                    let mut policy_assets = multi_asset.get(&policy_id).unwrap_or_default();
                    policy_assets.insert(&asset_name, &BigNum::from(quantity));
                    multi_asset.insert(&policy_id, &policy_assets);
                }

                output_value.set_multiasset(&multi_asset);
            }

            let output =
                TransactionOutput::new(&Address::from_bech32(addr).unwrap(), &output_value);
            tx_outputs.add(&output);
        }

        let mut body = TransactionBody::new_tx_body(&tx_inputs, &tx_outputs, &BigNum::from(TX_FEE));

        customize(&mut body);

        FixedTransaction::new_from_body_bytes(&body.to_bytes())
            .unwrap()
            .to_bytes()
    }

    #[test]
    fn sign_transaction_with_payment_key_only() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let payment_path = CardanoSigner::payment_derivation_path(0);
        let payment_key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", &payment_path, signer.curve()).unwrap();

        let output_address = signer.derive_address(payment_key.expose()).unwrap();
        let tx_cbor = build_test_tx_cbor(
            &[(
                "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
                0,
            )],
            &[(&output_address, 2_000_000, None)],
            |_body| {},
        );

        let sign_output = signer
            .sign_transaction(payment_key.expose(), &tx_cbor)
            .unwrap();
        assert_eq!(
            hex::encode(&sign_output.signature),
            "d901028182582065a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128584081a1235ccc8c96203f379891da1041af709f532f97a73d220eb081f444622701ce5660044f8fe90ec74d3d4ad7c1c0aece569a106f08a298566c51b139285500"
        );

        let signed_tx = signer
            .encode_signed_transaction(&tx_cbor, &sign_output)
            .unwrap();
        assert_eq!(
            hex::encode(signed_tx),
            "84a300d9010281825820cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe00018182581d6106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed03031a001e8480021a000f4240a100d901028182582065a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128584081a1235ccc8c96203f379891da1041af709f532f97a73d220eb081f444622701ce5660044f8fe90ec74d3d4ad7c1c0aece569a106f08a298566c51b139285500f5f6"
        );
    }

    #[test]
    fn sign_transaction_with_payment_and_required_stake_key() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = derive_key_material(&signer, &mnemonic, 0);
        let (_, stake_key) = CardanoSigner::decode_keys(key.expose()).unwrap();
        let stake_key = stake_key.unwrap();
        let output_address = signer.derive_address(key.expose()).unwrap();
        let tx_cbor = build_test_tx_cbor(
            &[(
                "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
                1,
            )],
            &[(&output_address, 3_000_000, None)],
            |body| {
                let mut signers = Ed25519KeyHashes::new();
                signers.add(&stake_key.to_public().to_raw_key().hash());
                body.set_required_signers(&signers);
            },
        );

        let sig = signer.sign_transaction(key.expose(), &tx_cbor).unwrap();
        assert_eq!(
            hex::encode(&sig.signature),
            "d901028282582065a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a696121285840f0389089c22a690bcbcab9d5865a2b33c06f0a58ba236adaada5f24adb5a39759667876c24250f8c991d1b8c71dca80e05c789eb23a34b66fd53b81d629d1504825820097cdc1da25a445eda8db6c3f0a3c3ba86c6a9555df0b4010f4d042ed94c22065840610945a63febb28741a4d2f9870e3de903f0a8c2f1c7b86e0a61adb667b973306177827559a1e7bacd452682b90eb5b15f4e5ab5a1433b62e0b2429b76b0a604"
        );

        let signed_tx = signer.encode_signed_transaction(&tx_cbor, &sig).unwrap();
        assert_eq!(
            hex::encode(signed_tx),
            "84a400d9010281825820cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe0101818258390106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303127d430c25123618becd71c191ea1ceb7108e76f479a3e6e839f39831a002dc6c0021a000f42400ed9010281581c127d430c25123618becd71c191ea1ceb7108e76f479a3e6e839f3983a100d901028282582065a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a696121285840f0389089c22a690bcbcab9d5865a2b33c06f0a58ba236adaada5f24adb5a39759667876c24250f8c991d1b8c71dca80e05c789eb23a34b66fd53b81d629d1504825820097cdc1da25a445eda8db6c3f0a3c3ba86c6a9555df0b4010f4d042ed94c22065840610945a63febb28741a4d2f9870e3de903f0a8c2f1c7b86e0a61adb667b973306177827559a1e7bacd452682b90eb5b15f4e5ab5a1433b62e0b2429b76b0a604f5f6"
        );
    }

    #[test]
    fn sign_transaction_with_stake_delegation_cert() {
        let signer = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = derive_key_material(&signer, &m, 0);
        let (_payment_key, stake_key) = CardanoSigner::decode_keys(key.expose()).unwrap();

        let address = signer.derive_address(key.expose()).unwrap();

        let tx_cbor = build_test_tx_cbor(
            &[(
                "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
                0,
            )],
            &[(&address, 2_000_000, None)],
            |body| {
                let mut certs = Certificates::new();
                let cert = Certificate::new_stake_delegation(&StakeDelegation::new(
                    &Credential::from_keyhash(&stake_key.unwrap().to_public().to_raw_key().hash()),
                    &Ed25519KeyHash::from_bytes(vec![0xcd; 28]).unwrap(), // dummy pool keyhash
                ));
                certs.add(&cert);
                body.set_certs(&certs);
            },
        );

        let sign_output = signer.sign_transaction(key.expose(), &tx_cbor).unwrap();
        let witnesses = Vkeywitnesses::from_bytes(sign_output.signature.clone()).unwrap();

        let witnesses_keys = (0..witnesses.len())
            .map(|i| hex::encode(witnesses.get(i).vkey().public_key().as_bytes()))
            .collect::<Vec<String>>();
        assert_eq!(
            witnesses_keys,
            [
                "65a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128", // payment key
                "097cdc1da25a445eda8db6c3f0a3c3ba86c6a9555df0b4010f4d042ed94c2206"  // stake key
            ]
        );
    }

    #[test]
    fn sign_transaction_with_withdrawals() {
        let signer = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = derive_key_material(&signer, &m, 0);
        let (_payment_key, stake_key) = CardanoSigner::decode_keys(key.expose()).unwrap();
        let stake_key = stake_key.unwrap();

        let address = signer.derive_address(key.expose()).unwrap();
        let reward_address = RewardAddress::new(
            signer.network_id,
            &Credential::from_keyhash(&stake_key.to_public().to_raw_key().hash()),
        );

        let tx_cbor = build_test_tx_cbor(
            &[(
                "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
                0,
            )],
            &[(&address, 2_000_000, None)],
            |body| {
                let mut withdrawals = Withdrawals::new();
                withdrawals.insert(&reward_address, &BigNum::from(1_000_000u64));
                body.set_withdrawals(&withdrawals);
            },
        );

        let sign_output = signer.sign_transaction(key.expose(), &tx_cbor).unwrap();
        let witnesses = Vkeywitnesses::from_bytes(sign_output.signature.clone()).unwrap();

        let witnesses_keys = (0..witnesses.len())
            .map(|i| hex::encode(witnesses.get(i).vkey().public_key().as_bytes()))
            .collect::<Vec<String>>();
        assert_eq!(
            witnesses_keys,
            [
                "65a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128", // payment key
                "097cdc1da25a445eda8db6c3f0a3c3ba86c6a9555df0b4010f4d042ed94c2206"  // stake key
            ]
        );
    }

    /// Build a source transaction whose outputs can be spent as UTXOs, returning
    /// `(tx_hash, cbor_bytes)` with a real blake2b body hash.
    fn build_utxo_source_tx(outputs: &[(&str, u64, Option<&[TestAsset]>)]) -> (String, Vec<u8>) {
        let cbor = build_test_tx_cbor(
            &[(
                "0000000000000000000000000000000000000000000000000000000000000000",
                0,
            )],
            outputs,
            |_body| {},
        );
        let tx = FixedTransaction::from_bytes(cbor.clone()).unwrap();
        (tx.transaction_hash().to_hex(), cbor)
    }

    fn mock_tx_cbor_response(server: &mut Server, txs: &[(String, Vec<u8>)]) -> mockito::Mock {
        let body: Vec<serde_json::Value> = txs
            .iter()
            .map(|(hash, cbor)| {
                serde_json::json!({
                    "tx_hash": hash,
                    "cbor": hex::encode(cbor),
                })
            })
            .collect();
        server
            .mock("POST", "/tx_cbor")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    /// Wrap a mockito server URL so [`resolve_cardano_provider`] selects Koios.
    fn koios_rpc_url(server: &Server) -> String {
        format!("koios|{}", server.url())
    }

    #[test]
    fn transaction_context_self_transfer() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "author cart lend blossom pistol rocket film just distance valid room lock",
        )
        .unwrap();
        let key = derive_key_material(&signer, &mnemonic, 0);
        let address = signer.derive_address(&key.expose()).unwrap();

        let input_index = 0;
        let input_value = 10_000_000;
        let (input_tx_hash, source_cbor) = build_utxo_source_tx(&[(&address, input_value, None)]);

        let tx_cbor = build_test_tx_cbor(
            &[(&input_tx_hash, input_index)],
            &[(&address, input_value - TX_FEE, None)],
            |_body| {},
        );

        let mut server = Server::new();
        let mock = mock_tx_cbor_response(&mut server, &[(input_tx_hash, source_cbor)]);

        let rpc_url = koios_rpc_url(&server);

        let ctx = signer
            .make_transaction_context(&tx_cbor, Some(&rpc_url))
            .unwrap();

        mock.assert();
        assert_eq!(
            ctx.effects,
            vec![TransactionEffect {
                address,
                diff: vec![("lovelace".into(), -(TX_FEE as i64))],
            }]
        );
    }

    #[test]
    fn transaction_context_single_input_external_plus_change() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "author cart lend blossom pistol rocket film just distance valid room lock",
        )
        .unwrap();
        let key = derive_key_material(&signer, &mnemonic, 0);
        let my_address = signer.derive_address(&key.expose()).unwrap();
        let external_address =
            "addr1vyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcx2tst3".to_string();

        let input_index = 0;
        let input_value = 10_000_000u64;
        let external_value = 3_000_000u64;
        let change_value = input_value - external_value - TX_FEE;
        let (input_tx_hash, source_cbor) =
            build_utxo_source_tx(&[(&my_address, input_value, None)]);

        let tx_cbor = build_test_tx_cbor(
            &[(&input_tx_hash, input_index)],
            &[
                (&external_address, external_value, None),
                (&my_address, change_value, None),
            ],
            |_body| {},
        );

        let mut server = Server::new();
        let mock = mock_tx_cbor_response(&mut server, &[(input_tx_hash, source_cbor)]);

        let rpc_url = koios_rpc_url(&server);
        let ctx = signer
            .make_transaction_context(&tx_cbor, Some(&rpc_url))
            .unwrap();
        mock.assert();

        assert_eq!(
            ctx.effects,
            vec![
                TransactionEffect {
                    address: my_address,
                    diff: vec![("lovelace".into(), -4_000_000)],
                },
                TransactionEffect {
                    address: external_address,
                    diff: vec![("lovelace".into(), 3_000_000)],
                },
            ]
        );
    }

    #[test]
    fn transaction_context_single_input_external_plus_change_with_assets() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "author cart lend blossom pistol rocket film just distance valid room lock",
        )
        .unwrap();
        let key = derive_key_material(&signer, &mnemonic, 0);
        let my_address = signer.derive_address(&key.expose()).unwrap();
        let external_address =
            "addr1vyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcx2tst3".to_string();

        let input_index = 0;
        let input_value = 10_000_000u64;
        let external_value = 3_000_000u64;
        let change_value = input_value - external_value - TX_FEE;

        let policy_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let asset_name = "746f6b656e";

        let input_asset_qty = 100u64;
        let external_asset_qty = 30u64;
        let change_asset_qty = input_asset_qty - external_asset_qty;
        let asset_id = format!("{policy_id}{asset_name}");

        let input_assets: Vec<TestAsset> = vec![(policy_id, asset_name, input_asset_qty)];
        let (input_tx_hash, source_cbor) =
            build_utxo_source_tx(&[(&my_address, input_value, Some(&input_assets))]);

        let external_assets: Vec<TestAsset> = vec![(policy_id, asset_name, external_asset_qty)];
        let change_assets: Vec<TestAsset> = vec![(policy_id, asset_name, change_asset_qty)];
        let tx_cbor = build_test_tx_cbor(
            &[(&input_tx_hash, input_index)],
            &[
                (&external_address, external_value, Some(&external_assets)),
                (&my_address, change_value, Some(&change_assets)),
            ],
            |_body| {},
        );

        let mut server = Server::new();
        let mock = mock_tx_cbor_response(&mut server, &[(input_tx_hash, source_cbor)]);

        let rpc_url = koios_rpc_url(&server);
        let ctx = signer
            .make_transaction_context(&tx_cbor, Some(&rpc_url))
            .unwrap();
        mock.assert();

        assert_eq!(
            ctx.effects,
            vec![
                TransactionEffect {
                    address: my_address,
                    diff: vec![(asset_id.clone(), -30), ("lovelace".into(), -4_000_000)],
                },
                TransactionEffect {
                    address: external_address,
                    diff: vec![(asset_id, 30), ("lovelace".into(), 3_000_000)],
                },
            ]
        );
    }

    #[test]
    fn transaction_context_two_inputs_a_b_two_outputs_a_b_rebalanced() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "author cart lend blossom pistol rocket film just distance valid room lock",
        )
        .unwrap();
        let key_a = derive_key_material(&signer, &mnemonic, 0);
        let key_b = derive_key_material(&signer, &mnemonic, 1);
        let address_a = signer.derive_address(&key_a.expose()).unwrap();
        let address_b = signer.derive_address(&key_b.expose()).unwrap();

        let input_a_index = 0;
        let input_b_index = 0;
        let input_a_value = 8_000_000u64;
        let input_b_value = 7_000_000u64;
        let output_a_value = 5_000_000u64;
        let output_b_value = input_a_value + input_b_value - output_a_value - TX_FEE;

        let (input_a_hash, source_a_cbor) =
            build_utxo_source_tx(&[(&address_a, input_a_value, None)]);
        let (input_b_hash, source_b_cbor) =
            build_utxo_source_tx(&[(&address_b, input_b_value, None)]);

        let tx_cbor = build_test_tx_cbor(
            &[
                (&input_a_hash, input_a_index),
                (&input_b_hash, input_b_index),
            ],
            &[
                (&address_a, output_a_value, None),
                (&address_b, output_b_value, None),
            ],
            |_body| {},
        );

        let mut server = Server::new();
        let mock = mock_tx_cbor_response(
            &mut server,
            &[(input_a_hash, source_a_cbor), (input_b_hash, source_b_cbor)],
        );

        let rpc_url = koios_rpc_url(&server);
        let ctx = signer
            .make_transaction_context(&tx_cbor, Some(&rpc_url))
            .unwrap();
        mock.assert();

        assert_eq!(
            ctx.effects,
            vec![
                TransactionEffect {
                    address: address_a,
                    diff: vec![("lovelace".into(), -3_000_000)],
                },
                TransactionEffect {
                    address: address_b,
                    diff: vec![("lovelace".into(), 2_000_000)],
                },
            ]
        );
    }

    #[test]
    fn transaction_context_inputs_a_b_outputs_a_c() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "author cart lend blossom pistol rocket film just distance valid room lock",
        )
        .unwrap();
        let key_a = derive_key_material(&signer, &mnemonic, 0);
        let key_b = derive_key_material(&signer, &mnemonic, 1);
        let key_c = derive_key_material(&signer, &mnemonic, 2);
        let address_a = signer.derive_address(&key_a.expose()).unwrap();
        let address_b = signer.derive_address(&key_b.expose()).unwrap();
        let address_c = signer.derive_address(&key_c.expose()).unwrap();

        let input_a_index = 0;
        let input_b_index = 0;
        let input_a_value = 8_000_000u64;
        let input_b_value = 7_000_000u64;
        let output_a_value = 4_000_000u64;
        let output_c_value = input_a_value + input_b_value - output_a_value - TX_FEE;

        let (input_a_hash, source_a_cbor) =
            build_utxo_source_tx(&[(&address_a, input_a_value, None)]);
        let (input_b_hash, source_b_cbor) =
            build_utxo_source_tx(&[(&address_b, input_b_value, None)]);

        let tx_cbor = build_test_tx_cbor(
            &[
                (&input_a_hash, input_a_index),
                (&input_b_hash, input_b_index),
            ],
            &[
                (&address_a, output_a_value, None),
                (&address_c, output_c_value, None),
            ],
            |_body| {},
        );

        let mut server = Server::new();
        let mock = mock_tx_cbor_response(
            &mut server,
            &[(input_a_hash, source_a_cbor), (input_b_hash, source_b_cbor)],
        );

        let rpc_url = koios_rpc_url(&server);
        let ctx = signer
            .make_transaction_context(&tx_cbor, Some(&rpc_url))
            .unwrap();
        mock.assert();

        assert_eq!(
            ctx.effects,
            vec![
                TransactionEffect {
                    address: address_a,
                    diff: vec![("lovelace".into(), -4_000_000)],
                },
                TransactionEffect {
                    address: address_b,
                    diff: vec![("lovelace".into(), -7_000_000)],
                },
                TransactionEffect {
                    address: address_c,
                    diff: vec![("lovelace".into(), 10_000_000)],
                },
            ]
        );
    }

    #[test]
    fn transaction_context_with_withdrawal() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "author cart lend blossom pistol rocket film just distance valid room lock",
        )
        .unwrap();
        let key = derive_key_material(&signer, &mnemonic, 0);
        let (_payment_key, stake_key) = CardanoSigner::decode_keys(key.expose()).unwrap();
        let stake_key = stake_key.unwrap();
        let payment_address = signer.derive_address(key.expose()).unwrap();
        let reward_address_bech32 = signer.reward_address_bech32(&stake_key).unwrap();
        let reward_address = RewardAddress::new(
            signer.network_id,
            &Credential::from_keyhash(&stake_key.to_public().to_raw_key().hash()),
        );

        let input_value = 10_000_000u64;
        let withdrawal = 5_000_000u64;
        let output_value = input_value + withdrawal - TX_FEE;
        let (input_tx_hash, source_cbor) =
            build_utxo_source_tx(&[(&payment_address, input_value, None)]);

        let tx_cbor = build_test_tx_cbor(
            &[(&input_tx_hash, 0)],
            &[(&payment_address, output_value, None)],
            |body| {
                let mut withdrawals = Withdrawals::new();
                withdrawals.insert(&reward_address, &BigNum::from(withdrawal));
                body.set_withdrawals(&withdrawals);
            },
        );

        let mut server = Server::new();
        let mock = mock_tx_cbor_response(&mut server, &[(input_tx_hash, source_cbor)]);

        let rpc_url = koios_rpc_url(&server);
        let ctx = signer
            .make_transaction_context(&tx_cbor, Some(&rpc_url))
            .unwrap();
        mock.assert();

        assert_eq!(
            ctx.effects,
            vec![
                TransactionEffect {
                    address: payment_address,
                    diff: vec![("lovelace".into(), (withdrawal - TX_FEE) as i64)],
                },
                TransactionEffect {
                    address: reward_address_bech32,
                    diff: vec![("lovelace".into(), -(withdrawal as i64))],
                },
            ]
        );
    }

    #[test]
    fn transaction_context_with_stake_registration_deposit() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "author cart lend blossom pistol rocket film just distance valid room lock",
        )
        .unwrap();
        let key = derive_key_material(&signer, &mnemonic, 0);
        let (_payment_key, stake_key) = CardanoSigner::decode_keys(key.expose()).unwrap();
        let stake_key = stake_key.unwrap();
        let payment_address = signer.derive_address(key.expose()).unwrap();
        let reward_address_bech32 = signer.reward_address_bech32(&stake_key).unwrap();
        let stake_cred = Credential::from_keyhash(&stake_key.to_public().to_raw_key().hash());

        let deposit = 2_000_000u64;
        let input_value = 10_000_000u64;
        let output_value = input_value - deposit - TX_FEE;
        let (input_tx_hash, source_cbor) =
            build_utxo_source_tx(&[(&payment_address, input_value, None)]);

        let tx_cbor = build_test_tx_cbor(
            &[(&input_tx_hash, 0)],
            &[(&payment_address, output_value, None)],
            |body| {
                let mut certs = Certificates::new();
                let reg = StakeRegistration::new_with_explicit_deposit(
                    &stake_cred,
                    &BigNum::from(deposit),
                );
                certs.add(&Certificate::new_reg_cert(&reg).unwrap());
                body.set_certs(&certs);
            },
        );

        let mut server = Server::new();
        let mock = mock_tx_cbor_response(&mut server, &[(input_tx_hash, source_cbor)]);

        let rpc_url = koios_rpc_url(&server);
        let ctx = signer
            .make_transaction_context(&tx_cbor, Some(&rpc_url))
            .unwrap();
        mock.assert();

        assert_eq!(
            ctx.effects,
            vec![
                TransactionEffect {
                    address: payment_address,
                    diff: vec![("lovelace".into(), -((deposit + TX_FEE) as i64))],
                },
                TransactionEffect {
                    // Deposit is locked under the stake credential.
                    address: reward_address_bech32,
                    diff: vec![("lovelace".into(), deposit as i64)],
                },
            ]
        );
    }

    #[test]
    fn transaction_context_with_stake_deregistration_refund() {
        let signer = CardanoSigner::mainnet();
        let mnemonic = Mnemonic::from_phrase(
            "author cart lend blossom pistol rocket film just distance valid room lock",
        )
        .unwrap();
        let key = derive_key_material(&signer, &mnemonic, 0);
        let (_payment_key, stake_key) = CardanoSigner::decode_keys(key.expose()).unwrap();
        let stake_key = stake_key.unwrap();
        let payment_address = signer.derive_address(key.expose()).unwrap();
        let reward_address_bech32 = signer.reward_address_bech32(&stake_key).unwrap();
        let stake_cred = Credential::from_keyhash(&stake_key.to_public().to_raw_key().hash());

        let refund = 2_000_000u64;
        let input_value = 10_000_000u64;
        let output_value = input_value + refund - TX_FEE;
        let (input_tx_hash, source_cbor) =
            build_utxo_source_tx(&[(&payment_address, input_value, None)]);

        let tx_cbor = build_test_tx_cbor(
            &[(&input_tx_hash, 0)],
            &[(&payment_address, output_value, None)],
            |body| {
                let mut certs = Certificates::new();
                let unreg = StakeDeregistration::new_with_explicit_refund(
                    &stake_cred,
                    &BigNum::from(refund),
                );
                certs.add(&Certificate::new_unreg_cert(&unreg).unwrap());
                body.set_certs(&certs);
            },
        );

        let mut server = Server::new();
        let mock = mock_tx_cbor_response(&mut server, &[(input_tx_hash, source_cbor)]);

        let rpc_url = koios_rpc_url(&server);
        let ctx = signer
            .make_transaction_context(&tx_cbor, Some(&rpc_url))
            .unwrap();
        mock.assert();

        assert_eq!(
            ctx.effects,
            vec![
                TransactionEffect {
                    address: payment_address,
                    diff: vec![("lovelace".into(), (refund - TX_FEE) as i64)],
                },
                TransactionEffect {
                    // Locked deposit is released from the stake credential.
                    address: reward_address_bech32,
                    diff: vec![("lovelace".into(), -(refund as i64))],
                },
            ]
        );
    }
}
