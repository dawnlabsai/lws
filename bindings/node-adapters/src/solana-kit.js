const core = require("@open-wallet-standard/core");

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const pairs = clean.match(/.{2}/g) ?? [];
  return Uint8Array.from(pairs.map((pair) => parseInt(pair, 16)));
}

async function owsToSolanaKeyPairSigner(walletNameOrId, options = {}) {
  const {
    createKeyPairSignerFromBytes,
    createKeyPairSignerFromPrivateKeyBytes,
  } = await import("@solana/kit");
  const exported = core.exportWallet(walletNameOrId, options.passphrase, options.vaultPath);
  let keys;
  try { keys = JSON.parse(exported); } catch {
    throw new Error("Mnemonic wallets: use @open-wallet-standard/core signMessage/signTransaction directly, or import with a private key for Keypair access.");
  }
  const hex = keys.ed25519;
  if (!hex) {
    throw new Error(`No ed25519 key found in wallet "${walletNameOrId}". Wallet may use a different curve.`);
  }

  const privateKeyBytes = hexToBytes(hex);
  if (privateKeyBytes.length === 32) {
    return createKeyPairSignerFromPrivateKeyBytes(privateKeyBytes);
  }
  if (privateKeyBytes.length === 64) {
    return createKeyPairSignerFromBytes(privateKeyBytes);
  }
  throw new Error(`Unexpected key length: ${privateKeyBytes.length} bytes`);
}

module.exports = { owsToSolanaKeyPairSigner };
