mod audit;
mod commands;
mod vault;

use clap::{Parser, Subcommand};
use ows_core::OwsError;
use ows_signer::hd::HdError;
use ows_signer::mnemonic::MnemonicError;
use ows_signer::{CryptoError, SignerError};

/// Open Wallet Standard CLI
#[derive(Parser)]
#[command(name = "ows", version = env!("OWS_VERSION"), about, long_version = concat!(env!("OWS_VERSION"), " (", env!("OWS_GIT_COMMIT"), ")"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage wallets
    Wallet {
        #[command(subcommand)]
        subcommand: WalletCommands,
    },
    /// Sign messages and transactions
    Sign {
        #[command(subcommand)]
        subcommand: SignCommands,
    },
    /// Generate and derive from mnemonics
    Mnemonic {
        #[command(subcommand)]
        subcommand: MnemonicCommands,
    },
    /// Fund a wallet with USDC via MoonPay
    Fund {
        #[command(subcommand)]
        subcommand: FundCommands,
    },
    /// Pay for x402-enabled API calls
    Pay {
        #[command(subcommand)]
        subcommand: PayCommands,
    },
    /// Manage policies for API key access control
    Policy {
        #[command(subcommand)]
        subcommand: PolicyCommands,
    },
    /// Manage API keys for agent access
    Key {
        #[command(subcommand)]
        subcommand: KeyCommands,
    },
    /// View configuration and RPC endpoints
    Config {
        #[command(subcommand)]
        subcommand: ConfigCommands,
    },
    /// Update ows to the latest release
    Update {
        /// Re-download even if already on the latest version
        #[arg(long)]
        force: bool,
    },
    /// Uninstall ows from the system
    Uninstall {
        /// Also remove all wallet data and config (~/.ows)
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Create a new universal wallet (generates mnemonic, derives all chain addresses)
    Create {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Number of words (12 or 24)
        #[arg(long, default_value = "12")]
        words: u32,
        /// Display the generated mnemonic (DANGEROUS — only for backup)
        #[arg(long)]
        show_mnemonic: bool,
    },
    /// Import an existing wallet from a mnemonic or private key
    Import {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Import a mnemonic phrase (from OWS_MNEMONIC env or stdin)
        #[arg(long)]
        mnemonic: bool,
        /// Import a raw private key (from OWS_PRIVATE_KEY env or stdin)
        #[arg(long)]
        private_key: bool,
        /// Source chain for private key import (determines curve: evm/bitcoin/cosmos/tron = secp256k1, solana/ton = ed25519)
        #[arg(long)]
        chain: Option<String>,
        /// Account index for HD derivation (mnemonic only)
        #[arg(long, default_value = "0")]
        index: u32,
    },
    /// Export wallet secret (mnemonic or private key) to stdout
    Export {
        /// Wallet name or ID
        #[arg(long)]
        wallet: String,
    },
    /// Delete a wallet from the vault
    Delete {
        /// Wallet name or ID
        #[arg(long)]
        wallet: String,
        /// Confirm deletion (required)
        #[arg(long)]
        confirm: bool,
    },
    /// Rename a wallet
    Rename {
        /// Current wallet name or ID
        #[arg(long)]
        wallet: String,
        /// New wallet name
        #[arg(long)]
        new_name: String,
    },
    /// List all saved wallets
    List,
    /// Show vault path and supported chains
    Info,
    /// Show the raw public key for a wallet on a given chain
    PublicKey {
        /// Wallet name or ID
        #[arg(long, env = "OWS_WALLET")]
        wallet: String,
        /// Chain name or CAIP-2 ID (e.g. "ton", "evm", "solana")
        #[arg(long)]
        chain: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SignCommands {
    /// Sign a message with chain-specific formatting (EIP-191, Bitcoin message signing, etc.)
    Message {
        /// Chain name (ethereum, base, arbitrum, solana, ...), CAIP-2 ID (eip155:8453), or EVM chain ID (8453)
        #[arg(long)]
        chain: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "OWS_WALLET")]
        wallet: String,
        /// Message to sign
        #[arg(long)]
        message: String,
        /// Message encoding: "utf8" or "hex"
        #[arg(long, default_value = "utf8")]
        encoding: String,
        /// EIP-712 typed data JSON (EVM only)
        #[arg(long)]
        typed_data: Option<String>,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON instead of raw hex
        #[arg(long)]
        json: bool,
    },
    /// Sign a transaction (accepts hex-encoded unsigned transaction bytes)
    Tx {
        /// Chain name (ethereum, base, arbitrum, solana, ...), CAIP-2 ID (eip155:8453), or EVM chain ID (8453)
        #[arg(long)]
        chain: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "OWS_WALLET")]
        wallet: String,
        /// Hex-encoded unsigned transaction bytes
        #[arg(long)]
        tx: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON instead of raw hex
        #[arg(long)]
        json: bool,
    },
    /// Sign and broadcast a transaction
    SendTx {
        /// Chain name (ethereum, base, arbitrum, solana, ...), CAIP-2 ID (eip155:8453), or EVM chain ID (8453)
        #[arg(long)]
        chain: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "OWS_WALLET")]
        wallet: String,
        /// Hex-encoded unsigned transaction bytes
        #[arg(long)]
        tx: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON instead of raw hex
        #[arg(long)]
        json: bool,
        /// Override configured RPC URL
        #[arg(long)]
        rpc_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum MnemonicCommands {
    /// Generate a new BIP-39 mnemonic phrase
    Generate {
        /// Number of words (12 or 24)
        #[arg(long, default_value = "12")]
        words: u32,
    },
    /// Derive an address from a mnemonic (reads from OWS_MNEMONIC env or stdin)
    Derive {
        /// Chain name (ethereum, base, arbitrum, solana, ...), CAIP-2 ID (eip155:8453), or EVM chain ID (8453). If omitted, derives all chains.
        #[arg(long)]
        chain: Option<String>,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },
}

#[derive(Subcommand)]
enum FundCommands {
    /// Create a MoonPay deposit — generates multi-chain deposit addresses that auto-convert to USDC
    Deposit {
        /// Wallet name or ID
        #[arg(long, env = "OWS_WALLET")]
        wallet: String,
        /// Target chain (default: base)
        #[arg(long, default_value = "base")]
        chain: String,
        /// Token to receive (default: USDC)
        #[arg(long, default_value = "USDC")]
        token: String,
    },
    /// Check token balances for a wallet
    Balance {
        /// Wallet name or ID
        #[arg(long, env = "OWS_WALLET")]
        wallet: String,
        /// Chain to check (default: base)
        #[arg(long, default_value = "base")]
        chain: String,
    },
}

#[derive(Subcommand)]
enum PayCommands {
    /// Make a paid request to an x402-enabled API endpoint
    Request {
        /// The URL to request
        url: String,
        /// Wallet name or ID
        #[arg(long, env = "OWS_WALLET")]
        wallet: String,
        /// HTTP method
        #[arg(long, default_value = "GET")]
        method: String,
        /// Request body (JSON)
        #[arg(long)]
        body: Option<String>,
        /// Skip passphrase prompt (use empty passphrase)
        #[arg(long)]
        no_passphrase: bool,
    },
    /// Discover x402-enabled services from the Bazaar directory
    Discover {
        /// Search query (filters by URL and description)
        #[arg(long)]
        query: Option<String>,
        /// Max results per page (default 100)
        #[arg(long)]
        limit: Option<u64>,
        /// Offset into results for pagination
        #[arg(long)]
        offset: Option<u64>,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Register a policy from a JSON file
    Create {
        /// Path to the policy JSON file
        #[arg(long)]
        file: String,
    },
    /// List all registered policies
    List,
    /// Show details of a policy
    Show {
        /// Policy ID
        #[arg(long)]
        id: String,
    },
    /// Delete a policy
    Delete {
        /// Policy ID
        #[arg(long)]
        id: String,
        /// Confirm deletion (required)
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Create an API key for agent access to wallets
    Create {
        /// Key name (e.g. "claude-agent")
        #[arg(long)]
        name: String,
        /// Wallet name or ID (repeatable)
        #[arg(long = "wallet")]
        wallets: Vec<String>,
        /// Policy ID to attach (repeatable)
        #[arg(long = "policy")]
        policies: Vec<String>,
        /// Optional expiry timestamp (ISO-8601)
        #[arg(long)]
        expires_at: Option<String>,
    },
    /// List all API keys (tokens are never shown)
    List,
    /// Revoke (delete) an API key
    Revoke {
        /// API key ID
        #[arg(long)]
        id: String,
        /// Confirm revocation (required)
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration and RPC endpoints
    Show,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Lws(#[from] OwsError),
    #[error("{0}")]
    Lib(#[from] ows_lib::OwsLibError),
    #[error("{0}")]
    Mnemonic(#[from] MnemonicError),
    #[error("{0}")]
    Hd(#[from] HdError),
    #[error("{0}")]
    Signer(#[from] SignerError),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Pay(#[from] ows_pay::PayError),
    #[error("{0}")]
    InvalidArgs(String),
}

pub(crate) fn parse_chain(s: &str) -> Result<ows_core::Chain, CliError> {
    ows_core::parse_chain(s).map_err(CliError::InvalidArgs)
}

fn main() {
    ows_signer::process_hardening::harden_process();

    // Eagerly initialize the global key cache and register it for zeroization
    // on termination signals (SIGTERM, SIGINT, SIGHUP).
    let cache = ows_signer::global_key_cache();
    ows_signer::process_hardening::register_cleanup(move || cache.clear());
    ows_signer::process_hardening::install_signal_handlers();

    // Migrate ~/.lws → ~/.ows if needed (one-time upgrade path).
    ows_lib::migrate::migrate_vault_if_needed();

    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    };

    // Explicitly zeroize all cached key material before exiting.
    ows_signer::global_key_cache().clear();
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::Wallet { subcommand } => match subcommand {
            WalletCommands::Create {
                name,
                words,
                show_mnemonic,
            } => commands::wallet::create(&name, words, show_mnemonic),
            WalletCommands::Import {
                name,
                mnemonic,
                private_key,
                chain,
                index,
            } => commands::wallet::import(&name, mnemonic, private_key, chain.as_deref(), index),
            WalletCommands::Export { wallet } => commands::wallet::export(&wallet),
            WalletCommands::Delete { wallet, confirm } => {
                commands::wallet::delete(&wallet, confirm)
            }
            WalletCommands::Rename { wallet, new_name } => {
                commands::wallet::rename(&wallet, &new_name)
            }
            WalletCommands::List => commands::wallet::list(),
            WalletCommands::Info => commands::info::run(),
            WalletCommands::PublicKey { wallet, chain, index, json } => {
                commands::wallet::public_key(&wallet, &chain, index, json)
            }
        },
        Commands::Sign { subcommand } => match subcommand {
            SignCommands::Message {
                chain,
                wallet,
                message,
                encoding,
                typed_data,
                index,
                json,
            } => commands::sign_message::run(
                &chain,
                &wallet,
                &message,
                &encoding,
                typed_data.as_deref(),
                index,
                json,
            ),
            SignCommands::Tx {
                chain,
                wallet,
                tx,
                index,
                json,
            } => commands::sign_transaction::run(&chain, &wallet, &tx, index, json),
            SignCommands::SendTx {
                chain,
                wallet,
                tx,
                index,
                json,
                rpc_url,
            } => commands::send_transaction::run(
                &chain,
                &wallet,
                &tx,
                index,
                json,
                rpc_url.as_deref(),
            ),
        },
        Commands::Fund { subcommand } => match subcommand {
            FundCommands::Deposit {
                wallet,
                chain,
                token,
            } => commands::fund::run(&wallet, Some(&chain), Some(&token)),
            FundCommands::Balance { wallet, chain } => {
                commands::fund::balance(&wallet, Some(&chain))
            }
        },
        Commands::Pay { subcommand } => match subcommand {
            PayCommands::Request {
                url,
                wallet,
                method,
                body,
                no_passphrase,
            } => commands::pay::run(&url, &wallet, &method, body.as_deref(), no_passphrase),
            PayCommands::Discover {
                query,
                limit,
                offset,
            } => commands::pay::discover(query.as_deref(), limit, offset),
        },
        Commands::Mnemonic { subcommand } => match subcommand {
            MnemonicCommands::Generate { words } => commands::generate::run(words),
            MnemonicCommands::Derive { chain, index } => {
                commands::derive::run(chain.as_deref(), index)
            }
        },
        Commands::Policy { subcommand } => match subcommand {
            PolicyCommands::Create { file } => commands::policy::create(&file),
            PolicyCommands::List => commands::policy::list(),
            PolicyCommands::Show { id } => commands::policy::show(&id),
            PolicyCommands::Delete { id, confirm } => commands::policy::delete(&id, confirm),
        },
        Commands::Key { subcommand } => match subcommand {
            KeyCommands::Create {
                name,
                wallets,
                policies,
                expires_at,
            } => commands::key::create(&name, &wallets, &policies, expires_at.as_deref()),
            KeyCommands::List => commands::key::list(),
            KeyCommands::Revoke { id, confirm } => commands::key::revoke(&id, confirm),
        },
        Commands::Config { subcommand } => match subcommand {
            ConfigCommands::Show => commands::config::show(),
        },
        Commands::Update { force } => commands::update::run(force),
        Commands::Uninstall { purge } => commands::uninstall::run(purge),
    }
}
