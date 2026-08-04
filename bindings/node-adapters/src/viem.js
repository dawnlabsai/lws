const { getWallet, signMessage, signTypedData, signTransaction } = require("@open-wallet-standard/core");
const { toAccount } = require("viem/accounts");

function owsToViemAccount(walletNameOrId, options = {}) {
  const chain = options.chain ?? "eip155:1";
  const wallet = getWallet(walletNameOrId, options.vaultPath);
  const evmAccount =
    wallet.accounts.find((a) => a.chainId === chain) ??
    wallet.accounts.find((a) => a.chainId.startsWith("eip155:"));
  if (!evmAccount) {
    throw new Error(`No EVM account found in wallet "${walletNameOrId}".`);
  }
  const address = evmAccount.address;
  return toAccount({
    address,
    async signMessage({ message }) {
      const raw = message.raw ?? message;
      const msg = typeof message === "string" ? message
        : typeof raw === "string" ? (raw.startsWith("0x") ? raw.slice(2) : Buffer.from(raw).toString("hex"))
        : Buffer.from(raw).toString("hex");
      const result = signMessage(walletNameOrId, chain, msg, options.passphrase, typeof message === "string" ? undefined : "hex", options.index, undefined, options.vaultPath);
      return result.signature.startsWith("0x") ? result.signature : `0x${result.signature}`;
    },
    async signTransaction(transaction) {
      const { serializeTransaction } = require("viem");
      const serialized = serializeTransaction(transaction);
      const txHex = serialized.startsWith("0x") ? serialized.slice(2) : serialized;
      const result = signTransaction(walletNameOrId, chain, txHex, options.passphrase, options.index, options.vaultPath);
      const sig = result.signature.startsWith("0x") ? result.signature.slice(2) : result.signature;
      const r = `0x${sig.slice(0, 64)}`;
      const s = `0x${sig.slice(64, 128)}`;
      const yParity = result.recovery_id != null ? (result.recovery_id >= 27 ? result.recovery_id - 27 : result.recovery_id) : parseInt(sig.slice(128, 130), 16);
      return serializeTransaction(transaction, { r, s, yParity });
    },
    async signTypedData(typedData) {
      const result = signTypedData(walletNameOrId, chain, JSON.stringify(typedData), options.passphrase, options.index, undefined, options.vaultPath);
      return result.signature.startsWith("0x") ? result.signature : `0x${result.signature}`;
    },
  });
}

module.exports = { owsToViemAccount };
