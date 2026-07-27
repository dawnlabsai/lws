const { getWallet, signMessage, signTypedData, signTransaction } = require("@open-wallet-standard/core");
const { toAccount } = require("viem/accounts");

// Encode a bigint as the core's EIP-712 parser expects a uint value: even-length
// hex. Decimal uints above 2^128 are rejected, and hex must have an even number
// of digits. Negative values fall back to decimal (int types).
function bigintToOwsHex(value) {
  if (value < 0n) return value.toString();
  const hex = value.toString(16);
  return `0x${hex.length % 2 === 1 ? `0${hex}` : hex}`;
}

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
      const result = signMessage(walletNameOrId, chain, msg, options.passphrase, typeof message === "string" ? undefined : "hex", options.index, options.vaultPath);
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
      const { getTypesForEIP712Domain } = require("viem");
      // viem's signTypedData action adds EIP712Domain to `types` before calling an
      // account; a direct account.signTypedData() call does not. Add it when absent
      // so the core resolves the domain type. A caller-supplied EIP712Domain wins.
      const payload = {
        ...typedData,
        types: {
          EIP712Domain: getTypesForEIP712Domain({ domain: typedData.domain }),
          ...typedData.types,
        },
      };
      // The core parses the JSON payload and expects uint values as even-length hex.
      // JSON.stringify cannot serialize bigints, so encode them here.
      const json = JSON.stringify(payload, (_key, value) =>
        typeof value === "bigint" ? bigintToOwsHex(value) : value
      );
      const result = signTypedData(walletNameOrId, chain, json, options.passphrase, options.index, options.vaultPath);
      return result.signature.startsWith("0x") ? result.signature : `0x${result.signature}`;
    },
  });
}

module.exports = { owsToViemAccount };
