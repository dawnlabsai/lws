import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createWallet, importWalletPrivateKey, getWallet, signMessage } from '@open-wallet-standard/core';
import { owsToSolanaKeypair } from '../src/solana.js';

describe('@open-wallet-standard/adapters — solana', () => {
  let vaultDir;
  const walletName = 'solana-test';
  const testEd25519Key = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';

  before(() => {
    vaultDir = mkdtempSync(join(tmpdir(), 'ows-solana-test-'));
    importWalletPrivateKey(walletName, testEd25519Key, undefined, vaultDir, 'solana');
  });
  after(() => { rmSync(vaultDir, { recursive: true, force: true }); });

  it('creates keypair with correct public key', () => {
    const wallet = getWallet(walletName, vaultDir);
    const solAccount = wallet.accounts.find(a => a.chainId.startsWith('solana:'));
    const keypair = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    assert.equal(keypair.publicKey.toBase58(), solAccount.address);
  });
  it('keypair can sign messages', async () => {
    const keypair = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    const message = Buffer.from('hello solana');
    const { ed25519 } = await import('@noble/curves/ed25519');
    const signature = ed25519.sign(message, keypair.secretKey.slice(0, 32));
    assert.equal(signature.length, 64);
  });
  it('same wallet produces same keypair', () => {
    const kp1 = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    const kp2 = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    assert.equal(kp1.publicKey.toBase58(), kp2.publicKey.toBase58());
  });
  it('throws for nonexistent wallet', () => {
    assert.throws(() => owsToSolanaKeypair('nonexistent', { vaultPath: vaultDir }));
  });
  it('throws for mnemonic wallets', () => {
    createWallet('mnemonic-test', undefined, 12, vaultDir);
    assert.throws(() => owsToSolanaKeypair('mnemonic-test', { vaultPath: vaultDir }), /Mnemonic wallets/);
  });
  it('keypair matches OWS signMessage output', async () => {
    const keypair = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    const messageHex = Buffer.from('verify-match').toString('hex');
    const owsResult = signMessage(walletName, 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', messageHex, undefined, 'hex', undefined, undefined, vaultDir);
    const { ed25519 } = await import('@noble/curves/ed25519');
    const keypairSig = Buffer.from(ed25519.sign(Buffer.from(messageHex, 'hex'), keypair.secretKey.slice(0, 32))).toString('hex');
    assert.equal(keypairSig, owsResult.signature);
  });
});
