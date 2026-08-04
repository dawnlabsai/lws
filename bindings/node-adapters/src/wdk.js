const { getWallet, signMessage, signTransaction, signAndSend } = require("@open-wallet-standard/core");

/**
 * Map WDK blockchain names to OWS CAIP-2 chain identifiers.
 * WDK uses plain names ("evm", "solana", "btc"); OWS uses CAIP-2.
 */
const CHAIN_MAP = {
  evm: "eip155:1",
  solana: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
  btc: "bip122:000000000019d6689c085ae165831e93",
  bitcoin: "bip122:000000000019d6689c085ae165831e93",
  ton: "ton:mainnet",
  tron: "tron:mainnet",
  cosmos: "cosmos:cosmoshub-4",
  sui: "sui:mainnet",
  xrpl: "xrpl:mainnet",
  filecoin: "fil:mainnet",
  spark: "spark:mainnet",
};

function resolveChain(chain) {
  return CHAIN_MAP[chain] ?? chain;
}

/**
 * Wrap an OWS wallet as a WDK-compatible account object.
 *
 * Returns an object conforming to WDK's IWalletAccount interface for signing
 * operations. Signing is delegated to OWS core — keys never leave the vault.
 *
 * @param {string} walletNameOrId  OWS wallet name or UUID
 * @param {string} chain           WDK chain name ("evm", "solana", "btc", …) or CAIP-2 ID
 * @param {object} [options]
 * @param {string} [options.passphrase]  Vault passphrase (owner mode)
 * @param {number} [options.index]       Account derivation index (default: 0)
 * @param {string} [options.rpcUrl]      RPC endpoint for sendTransaction
 * @param {string} [options.vaultPath]   Custom vault directory
 */
function owsToWdkAccount(walletNameOrId, chain, options = {}) {
  const caipChain = resolveChain(chain);
  const namespace = caipChain.split(":")[0];
  const wallet = getWallet(walletNameOrId, options.vaultPath);
  const account =
    wallet.accounts.find((a) => a.chainId === caipChain) ??
    wallet.accounts.find((a) => a.chainId.startsWith(namespace + ":"));
  if (!account) {
    throw new Error(`No ${chain} account found in wallet "${walletNameOrId}".`);
  }

  const idx = options.index ?? 0;

  return {
    index: idx,
    path: account.derivationPath,

    keyPair: {
      publicKey: null,
      privateKey: null,
    },

    async getAddress() {
      return account.address;
    },

    async sign(message) {
      const msg = Buffer.isBuffer(message) || message instanceof Uint8Array
        ? Buffer.from(message).toString("hex")
        : message;
      const encoding = Buffer.isBuffer(message) || message instanceof Uint8Array ? "hex" : "utf8";
      const result = signMessage(walletNameOrId, caipChain, msg, options.passphrase, encoding, idx, undefined, options.vaultPath);
      return Uint8Array.from(Buffer.from(result.signature, "hex"));
    },

    async signTransaction(txData) {
      const txHex = Buffer.isBuffer(txData) || txData instanceof Uint8Array
        ? Buffer.from(txData).toString("hex")
        : typeof txData === "string" && txData.startsWith("0x") ? txData.slice(2)
        : txData;
      const result = signTransaction(walletNameOrId, caipChain, txHex, options.passphrase, idx, options.vaultPath);
      return Uint8Array.from(Buffer.from(result.signature, "hex"));
    },

    async sendTransaction(txData) {
      const txHex = Buffer.isBuffer(txData) || txData instanceof Uint8Array
        ? Buffer.from(txData).toString("hex")
        : typeof txData === "string" && txData.startsWith("0x") ? txData.slice(2)
        : txData;
      const result = signAndSend(walletNameOrId, caipChain, txHex, options.passphrase, idx, options.rpcUrl, options.vaultPath);
      return result.txHash;
    },

    dispose() { /* OWS manages key lifecycle internally */ },
  };
}

module.exports = { owsToWdkAccount, CHAIN_MAP };
