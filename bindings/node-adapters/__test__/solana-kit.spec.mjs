import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { ed25519 } from "@noble/curves/ed25519";
import {
  createWallet,
  getWallet,
  importWalletPrivateKey,
} from "@open-wallet-standard/core";
import {
  createKeyPairSignerFromBytes,
  createKeyPairSignerFromPrivateKeyBytes,
} from "@solana/kit";
import { owsToSolanaKeyPairSigner } from "../src/solana-kit.js";

const require = createRequire(import.meta.url);
const core = require("@open-wallet-standard/core");

describe("@open-wallet-standard/adapters — solana-kit", () => {
  let vaultDir;
  const walletName = "solana-kit-test";
  const testEd25519Key = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

  before(() => {
    vaultDir = mkdtempSync(join(tmpdir(), "ows-solana-kit-test-"));
    importWalletPrivateKey(walletName, testEd25519Key, undefined, vaultDir, "solana");
  });

  after(() => {
    rmSync(vaultDir, { force: true, recursive: true });
  });

  it("creates a signer with the correct address", async () => {
    const wallet = getWallet(walletName, vaultDir);
    const solAccount = wallet.accounts.find((account) => account.chainId.startsWith("solana:"));
    const signer = await owsToSolanaKeyPairSigner(walletName, { vaultPath: vaultDir });

    assert.equal(signer.address, solAccount.address);
  });

  it("same wallet produces the same signer address", async () => {
    const signerA = await owsToSolanaKeyPairSigner(walletName, { vaultPath: vaultDir });
    const signerB = await owsToSolanaKeyPairSigner(walletName, { vaultPath: vaultDir });

    assert.equal(signerA.address, signerB.address);
  });

  it("throws for nonexistent wallets", async () => {
    await assert.rejects(
      () => owsToSolanaKeyPairSigner("nonexistent", { vaultPath: vaultDir }),
    );
  });

  it("throws for mnemonic wallets", async () => {
    createWallet("mnemonic-test", undefined, 12, vaultDir);

    await assert.rejects(
      () => owsToSolanaKeyPairSigner("mnemonic-test", { vaultPath: vaultDir }),
      /Mnemonic wallets/,
    );
  });

  it("accepts both 32-byte and 64-byte ed25519 exports", async () => {
    const originalExportWallet = core.exportWallet;
    const privateKeyBytes = Uint8Array.from(Buffer.from(testEd25519Key, "hex"));
    const fullKeyBytes = new Uint8Array(64);
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);

    fullKeyBytes.set(privateKeyBytes, 0);
    fullKeyBytes.set(publicKeyBytes, 32);

    try {
      core.exportWallet = () => JSON.stringify({ ed25519: Buffer.from(privateKeyBytes).toString("hex") });
      const signerFromPrivateKey = await owsToSolanaKeyPairSigner(walletName, { vaultPath: vaultDir });
      const expectedSignerFromPrivateKey = await createKeyPairSignerFromPrivateKeyBytes(privateKeyBytes);

      assert.equal(signerFromPrivateKey.address, expectedSignerFromPrivateKey.address);

      core.exportWallet = () => JSON.stringify({ ed25519: Buffer.from(fullKeyBytes).toString("hex") });
      const signerFromKeypair = await owsToSolanaKeyPairSigner(walletName, { vaultPath: vaultDir });
      const expectedSignerFromKeypair = await createKeyPairSignerFromBytes(fullKeyBytes);

      assert.equal(signerFromKeypair.address, expectedSignerFromKeypair.address);
    } finally {
      core.exportWallet = originalExportWallet;
    }
  });
});
