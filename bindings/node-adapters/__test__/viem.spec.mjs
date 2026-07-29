import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createWallet, getWallet, signMessage as owsSignMessage } from '@open-wallet-standard/core';
import { owsToViemAccount } from '../src/viem.js';

describe('@open-wallet-standard/adapters — viem', () => {
  let vaultDir;
  const walletName = 'viem-test';
  before(() => { vaultDir = mkdtempSync(join(tmpdir(), 'ows-viem-test-')); createWallet(walletName, undefined, 12, vaultDir); });
  after(() => { rmSync(vaultDir, { recursive: true, force: true }); });

  it('creates account with correct EVM address', () => {
    const wallet = getWallet(walletName, vaultDir);
    const evmAccount = wallet.accounts.find(a => a.chainId.startsWith('eip155:'));
    const account = owsToViemAccount(walletName, { vaultPath: vaultDir });
    assert.equal(account.address, evmAccount.address);
    assert.match(account.address, /^0x[0-9a-fA-F]{40}$/);
  });
  it('uses exact chain match when specified', () => {
    const account = owsToViemAccount(walletName, { chain: 'eip155:1', vaultPath: vaultDir });
    assert.match(account.address, /^0x[0-9a-fA-F]{40}$/);
  });
  it('falls back to any eip155 account', () => {
    const account = owsToViemAccount(walletName, { chain: 'eip155:8453', vaultPath: vaultDir });
    assert.match(account.address, /^0x[0-9a-fA-F]{40}$/);
  });
  it('signMessage returns hex signature', async () => {
    const account = owsToViemAccount(walletName, { vaultPath: vaultDir });
    const sig = await account.signMessage({ message: 'hello' });
    assert.match(sig, /^0x[0-9a-fA-F]+$/);
  });
  it('signMessage is deterministic', async () => {
    const account = owsToViemAccount(walletName, { vaultPath: vaultDir });
    const sig1 = await account.signMessage({ message: 'deterministic' });
    const sig2 = await account.signMessage({ message: 'deterministic' });
    assert.equal(sig1, sig2);
  });
  it('signMessage matches OWS SDK direct call', async () => {
    const account = owsToViemAccount(walletName, { vaultPath: vaultDir });
    const adapterSig = await account.signMessage({ message: 'parity-check' });
    const directResult = owsSignMessage(walletName, 'eip155:1', 'parity-check', undefined, undefined, undefined, undefined, vaultDir);
    const directSig = directResult.signature.startsWith('0x') ? directResult.signature : `0x${directResult.signature}`;
    assert.equal(adapterSig, directSig);
  });
  it('signTypedData returns hex signature', async () => {
    const account = owsToViemAccount(walletName, { vaultPath: vaultDir });
    const sig = await account.signTypedData({
      domain: { name: 'Test', version: '1', chainId: '1', verifyingContract: '0x0000000000000000000000000000000000000001' },
      types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }], Mail: [{ name: 'contents', type: 'string' }] },
      primaryType: 'Mail', message: { contents: 'Hello' },
    });
    assert.match(sig, /^0x[0-9a-fA-F]+$/);
  });
  it('signTypedData is deterministic', async () => {
    const account = owsToViemAccount(walletName, { vaultPath: vaultDir });
    const td = { domain: { name: 'T', version: '1', chainId: '1', verifyingContract: '0x0000000000000000000000000000000000000001' }, types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }], M: [{ name: 'c', type: 'string' }] }, primaryType: 'M', message: { c: 'D' } };
    assert.equal(await account.signTypedData(td), await account.signTypedData(td));
  });
  it('signTransaction returns RLP-encoded signed transaction', async () => {
    const account = owsToViemAccount(walletName, { vaultPath: vaultDir });
    const tx = { to: '0x0000000000000000000000000000000000000001', value: 0n, chainId: 1, type: 'eip1559', maxFeePerGas: 1000000000n, maxPriorityFeePerGas: 1000000000n };
    const signed = await account.signTransaction(tx);
    assert.match(signed, /^0x02/);  // EIP-1559 prefix
    assert.ok(signed.length > 130);  // longer than a raw 65-byte signature
  });
  it('throws for nonexistent wallet', () => {
    assert.throws(() => owsToViemAccount('nonexistent', { vaultPath: vaultDir }));
  });
});
