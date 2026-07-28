pub mod bitcoin;
pub mod cardano;
pub mod cosmos;
pub mod evm;
pub mod filecoin;
pub mod nano;
pub mod near;
pub mod solana;
pub mod spark;
pub mod sui;
pub mod ton;
pub mod tron;
pub mod xrpl;

pub use self::bitcoin::BitcoinSigner;
pub use self::cardano::CardanoSigner;
pub use self::cosmos::CosmosSigner;
pub use self::evm::EvmSigner;
pub use self::filecoin::FilecoinSigner;
pub use self::nano::NanoSigner;
pub use self::near::NearSigner;
pub use self::solana::SolanaSigner;
pub use self::spark::SparkSigner;
pub use self::sui::SuiSigner;
pub use self::ton::TonSigner;
pub use self::tron::TronSigner;
pub use self::xrpl::XrplSigner;

use crate::traits::ChainSigner;
use ows_core::ChainType;

/// Get a default signer for a given chain type.
pub fn signer_for_chain(chain: ChainType) -> Box<dyn ChainSigner> {
    match chain {
        ChainType::Evm => Box::new(EvmSigner),
        ChainType::Solana => Box::new(SolanaSigner),
        ChainType::Bitcoin => Box::new(BitcoinSigner::mainnet()),
        ChainType::Cosmos => Box::new(CosmosSigner::cosmos_hub()),
        ChainType::Tron => Box::new(TronSigner),
        ChainType::Ton => Box::new(TonSigner),
        ChainType::Spark => Box::new(SparkSigner),
        ChainType::Filecoin => Box::new(FilecoinSigner),
        ChainType::Sui => Box::new(SuiSigner),
        ChainType::Xrpl => Box::new(XrplSigner),
        ChainType::Nano => Box::new(NanoSigner),
        ChainType::Near => Box::new(NearSigner),
        ChainType::Cardano => Box::new(CardanoSigner::mainnet()),
    }
}
