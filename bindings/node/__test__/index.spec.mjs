import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  generateMnemonic,
  deriveAddress,
  createWallet,
  listWallets,
  getWallet,
  deleteWallet,
  exportWallet,
  renameWallet,
  importWalletMnemonic,
  importWalletPrivateKey,
  signTransaction,
  signMessage,
  signHash,
  signAuthorization,
  signTypedData,
  createPolicy,
  listPolicies,
  getPolicy,
  deletePolicy,
  createApiKey,
  listApiKeys,
  revokeApiKey,
} from '../index.js';

describe('@open-wallet-standard/core', () => {
  let vaultDir;

  before(() => {
    vaultDir = mkdtempSync(join(tmpdir(), 'ows-node-test-'));
  });

  after(() => {
    rmSync(vaultDir, { recursive: true, force: true });
  });

  // ---- Mnemonic ----

  it('generates a 12-word mnemonic', () => {
    const phrase = generateMnemonic(12);
    assert.equal(phrase.split(' ').length, 12);
  });

  it('generates a 24-word mnemonic', () => {
    const phrase = generateMnemonic(24);
    assert.equal(phrase.split(' ').length, 24);
  });

  it('derives addresses for all chains', () => {
    const phrase = generateMnemonic(12);
    for (const chain of ['evm', 'solana', 'sui', 'bitcoin', 'cosmos', 'tron', 'ton', 'filecoin', 'xrpl', 'nano', 'near']) {
      const addr = deriveAddress(phrase, chain);
      assert.ok(addr.length > 0, `address should be non-empty for ${chain}`);
    }
  });

  it('routes Midnight through the binding: derive + message sign + SignResult shape', () => {
    const phrase = generateMnemonic(12);

    // Address derivation reaches the Midnight signer and re-encodes per network HRP.
    const preview = deriveAddress(phrase, 'midnight:preview');
    assert.ok(preview.startsWith('mn_addr_preview1'), `expected preview HRP, got ${preview}`);
    const mainnet = deriveAddress(phrase, 'midnight:mainnet');
    assert.ok(mainnet.startsWith('mn_addr1'), `expected mainnet HRP, got ${mainnet}`);

    // Owner-mode message signing works through the binding (BIP-340, x-only pubkey prefixed
    // to the signature → 96 bytes → 192 hex chars), and the SignResult now carries the
    // Midnight-only `transaction` field — undefined for a message (only `sign tx` seals a tx).
    // Uses an isolated vault so it doesn't perturb the shared-vault wallet-count assertions.
    const mnVault = mkdtempSync(join(tmpdir(), 'ows-node-mn-'));
    try {
      importWalletMnemonic('mn-node', phrase, undefined, undefined, mnVault);
      const result = signMessage('mn-node', 'midnight:preview', 'hello midnight', '', undefined, undefined, mnVault);
      assert.equal(result.signature.length, 192, 'midnight signature = pubkey(32)+sig(64) as hex');
      assert.equal(result.transaction, undefined, 'a message seals no transaction');
    } finally {
      rmSync(mnVault, { recursive: true, force: true });
    }
  });

  // ---- Universal wallet lifecycle ----

  it('creates a universal wallet with 12 accounts', () => {
    const wallet = createWallet('lifecycle-test', undefined, 12, vaultDir);
    assert.equal(wallet.name, 'lifecycle-test');
    assert.equal(wallet.accounts.length, 12);

    const chainIds = wallet.accounts.map((a) => a.chainId);
    assert.ok(chainIds.some((c) => c.startsWith('eip155:')));
    assert.ok(chainIds.some((c) => c.startsWith('solana:')));
    assert.ok(chainIds.some((c) => c.startsWith('sui:')));
    assert.ok(chainIds.some((c) => c.startsWith('bip122:')));
    assert.ok(chainIds.some((c) => c.startsWith('cosmos:')));
    assert.ok(chainIds.some((c) => c.startsWith('tron:')));
    assert.ok(chainIds.some((c) => c.startsWith('ton:')));
    assert.ok(chainIds.some((c) => c.startsWith('spark:')));
    assert.ok(chainIds.some((c) => c.startsWith('fil:')));
    assert.ok(chainIds.some((c) => c.startsWith('xrpl:')));
    assert.ok(chainIds.some((c) => c.startsWith('nano:')));
    assert.ok(chainIds.some((c) => c.startsWith('near:')));
    assert.ok(chainIds.some((c) => c.startsWith('midnight:')));

    // List
    const wallets = listWallets(vaultDir);
    assert.equal(wallets.length, 1);
    assert.equal(wallets[0].id, wallet.id);

    // Get by name
    const found = getWallet('lifecycle-test', vaultDir);
    assert.equal(found.id, wallet.id);

    // Rename
    renameWallet('lifecycle-test', 'renamed', vaultDir);
    const renamed = getWallet('renamed', vaultDir);
    assert.equal(renamed.id, wallet.id);

    // Export mnemonic
    const secret = exportWallet('renamed', undefined, vaultDir);
    assert.equal(secret.split(' ').length, 12);

    // Delete
    deleteWallet('renamed', vaultDir);
    assert.equal(listWallets(vaultDir).length, 0);
  });

  // ---- Mnemonic import round-trip ----

  it('imports a mnemonic and produces same addresses', () => {
    const phrase = generateMnemonic(12);
    const expectedEvm = deriveAddress(phrase, 'evm');
    const expectedSol = deriveAddress(phrase, 'solana');

    const wallet = importWalletMnemonic('mn-import', phrase, undefined, undefined, vaultDir);
    assert.equal(wallet.name, 'mn-import');
    assert.equal(wallet.accounts.length, 12);

    const evmAcct = wallet.accounts.find((a) => a.chainId.startsWith('eip155:'));
    assert.equal(evmAcct.address, expectedEvm);

    const solAcct = wallet.accounts.find((a) => a.chainId.startsWith('solana:'));
    assert.equal(solAcct.address, expectedSol);

    deleteWallet('mn-import', vaultDir);
  });

  // ---- Private key import (secp256k1) ----

  it('imports a secp256k1 private key with all 12 accounts', () => {
    const privkey = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const wallet = importWalletPrivateKey('pk-secp', privkey, undefined, vaultDir, 'evm');

    assert.equal(wallet.name, 'pk-secp');
    assert.equal(wallet.accounts.length, 12, 'should have all 12 chain accounts');

    // Sign on EVM (provided key's curve)
    const evmSig = signMessage('pk-secp', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on Solana (generated key's curve)
    const solSig = signMessage('pk-secp', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    // Export returns JSON with both keys
    const exported = JSON.parse(exportWallet('pk-secp', undefined, vaultDir));
    assert.equal(exported.secp256k1, privkey);
    assert.ok(exported.ed25519.length === 64, 'should have 32-byte ed25519 key in hex');

    deleteWallet('pk-secp', vaultDir);
  });

  // ---- Private key import (ed25519) ----

  it('imports an ed25519 private key with all 12 accounts', () => {
    const privkey = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
    const wallet = importWalletPrivateKey('pk-ed', privkey, undefined, vaultDir, 'solana');

    assert.equal(wallet.accounts.length, 12);

    // Sign on Solana (provided key)
    const solSig = signMessage('pk-ed', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    // Sign on EVM (generated key)
    const evmSig = signMessage('pk-ed', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on TON (same ed25519 key)
    const tonSig = signMessage('pk-ed', 'ton', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(tonSig.signature.length > 0);

    deleteWallet('pk-ed', vaultDir);
  });

  // ---- Private key import (both curves) ----

  it('imports both curve keys explicitly', () => {
    const secpKey = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const edKey = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';

    const wallet = importWalletPrivateKey(
      'pk-both', '', undefined, vaultDir, undefined, secpKey, edKey
    );

    assert.equal(wallet.name, 'pk-both');
    assert.equal(wallet.accounts.length, 12, 'should have all 12 chain accounts');

    // Sign on EVM (secp256k1 key)
    const evmSig = signMessage('pk-both', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on Solana (ed25519 key)
    const solSig = signMessage('pk-both', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    // Export returns both provided keys
    const exported = JSON.parse(exportWallet('pk-both', undefined, vaultDir));
    assert.equal(exported.secp256k1, secpKey);
    assert.equal(exported.ed25519, edKey);

    deleteWallet('pk-both', vaultDir);
  });

  // ---- Signing all chains ----

  it('signs messages on all chains', () => {
    createWallet('all-chain-signer', undefined, 12, vaultDir);

    // XRPL and Nano are excluded here because their signers explicitly do not
    // support generic off-chain message signing without a defined convention.
    // NEAR's V1 sign_message is raw ed25519 over the bytes (NEP-413 is a follow-up).
    for (const chain of ['evm', 'solana', 'sui', 'bitcoin', 'cosmos', 'tron', 'ton', 'filecoin', 'near']) {
      const result = signMessage('all-chain-signer', chain, 'test', undefined, undefined, undefined, vaultDir);
      assert.ok(result.signature.length > 0, `signature should be non-empty for ${chain}`);
    }

    deleteWallet('all-chain-signer', vaultDir);
  });

  it('signs transactions on all chains', () => {
    createWallet('tx-signer', undefined, 12, vaultDir);
    const txHex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    // Solana extract_signable_bytes expects a valid wire format:
    // [compact-u16 sig count][64-byte sig slots...][message...]
    // Build a minimal tx with 1 sig slot (0x01) + 64 zero bytes + a message.
    const solTxHex = '01' + '00'.repeat(64) + 'deadbeefdeadbeef';
    // Nano state block: 176-byte canonical layout (preamble + account + previous
    // + representative + balance + link).
    // https://docs.nano.org/integration-guides/the-basics/#self-signed-blocks
    const nanoTxHex =
      `${'00'.repeat(31)}06` +
      `${'01'.repeat(32)}` +
      `${'00'.repeat(32)}` +
      `${'02'.repeat(32)}` +
      '00000000033b2e3c9fd0803ce8000000' +
      `${'03'.repeat(32)}`;

    // NEAR transactions have no envelope; signer hashes via sha256 then ed25519
    // signs the digest. Any non-empty bytes verify the signing pipeline.
    const nearTxHex = '42'.repeat(80);

    // XRPL signing decodes the tx to inject SigningPubKey, so it needs a real
    // binary-encoded unsigned Payment (no SigningPubKey/TxnSignature).
    const xrplTxHex =
      '12000024000000016140000000000F424068400000000000000C8114AFF3C2E33458B30714CA16FFEE19952DD35C17C883145720939C1336A7356A70ED861D5934345C6B6360';

    const txHexByChain = {
      solana: solTxHex,
      nano: nanoTxHex,
      near: nearTxHex,
      xrpl: xrplTxHex,
    };

    for (const chain of ['evm', 'solana', 'sui', 'bitcoin', 'cosmos', 'tron', 'ton', 'filecoin', 'xrpl', 'nano', 'near']) {
      const hex = txHexByChain[chain] ?? txHex;
      const result = signTransaction('tx-signer', chain, hex, undefined, undefined, vaultDir);
      assert.ok(result.signature.length > 0, `signature should be non-empty for ${chain}`);
    }

    deleteWallet('tx-signer', vaultDir);
  });

  it('signs raw hashes and EIP-7702 authorizations in owner mode', () => {
    const privkey = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const wallet = importWalletPrivateKey('hash-owner', privkey, undefined, vaultDir, 'evm');

    const hashSig = signHash(wallet.id, 'base', '11'.repeat(32), undefined, undefined, vaultDir);
    assert.ok(hashSig.signature.length > 0);
    assert.ok(hashSig.recoveryId === 0 || hashSig.recoveryId === 1);

    const authSig = signAuthorization(
      wallet.id,
      'base',
      '0x1111111111111111111111111111111111111111',
      '7',
      undefined,
      undefined,
      vaultDir,
    );
    assert.ok(authSig.signature.length > 0);
    assert.ok(authSig.recoveryId === 0 || authSig.recoveryId === 1);

    deleteWallet(wallet.id, vaultDir);
  });

  // ---- Determinism ----

  it('produces deterministic signatures', () => {
    createWallet('det-test', undefined, 12, vaultDir);

    const sig1 = signMessage('det-test', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    const sig2 = signMessage('det-test', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.equal(sig1.signature, sig2.signature);

    deleteWallet('det-test', vaultDir);
  });

  // ---- Error handling ----

  it('rejects duplicate wallet names', () => {
    createWallet('dup-name', undefined, 12, vaultDir);
    assert.throws(() => createWallet('dup-name', undefined, 12, vaultDir));
    deleteWallet('dup-name', vaultDir);
  });

  it('rejects non-existent wallet', () => {
    assert.throws(() => getWallet('nonexistent', vaultDir));
    assert.throws(() => signMessage('nonexistent', 'evm', 'x', undefined, undefined, undefined, vaultDir));
  });

  it('rejects invalid private key hex', () => {
    assert.throws(() => importWalletPrivateKey('bad', 'not-hex', undefined, vaultDir));
  });

  // ---- Policy engine: API key signing ----

  it('creates a policy, API key by wallet name, and signs with the token', () => {
    const wallet = createWallet('policy-test', undefined, 12, vaultDir);

    // Register a policy allowing only Base
    createPolicy(JSON.stringify({
      id: 'test-base-only',
      name: 'Base Only',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453', 'eip155:84532'] },
      ],
      action: 'deny',
    }), vaultDir);

    // Create API key by wallet name
    const key = createApiKey('test-agent', [wallet.id], ['test-base-only'], '', null, vaultDir);
    assert.ok(key.token.startsWith('ows_key_'));
    assert.equal(key.name, 'test-agent');

    // Sign on allowed chain — should succeed
    const sig = signTransaction(wallet.id, 'base', 'deadbeef', key.token, null, vaultDir);
    assert.ok(sig.signature.length > 0);

    // Sign on denied chain — should fail
    assert.throws(
      () => signTransaction(wallet.id, 'ethereum', 'deadbeef', key.token, null, vaultDir),
      (err) => err.message.includes('not in allowlist'),
    );

    // Owner mode still works on any chain
    const ownerSig = signTransaction(wallet.id, 'ethereum', 'deadbeef', '', null, vaultDir);
    assert.ok(ownerSig.signature.length > 0);

    // Revoke and verify token is dead
    revokeApiKey(key.id, vaultDir);
    assert.throws(
      () => signTransaction(wallet.id, 'base', 'deadbeef', key.token, null, vaultDir),
      (err) => err.message.includes('API key not found'),
    );

    // Cleanup
    deletePolicy('test-base-only', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('signs with an API key for a wallet imported from a private key', () => {
    createPolicy(JSON.stringify({
      id: 'test-imported-wallet',
      name: 'Imported Wallet',
      version: 1,
      created_at: '2026-03-31T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453'] },
      ],
      action: 'deny',
    }), vaultDir);

    const wallet = importWalletPrivateKey(
      'policy-imported-wallet',
      'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
      '',
      vaultDir,
      'evm',
    );
    const key = createApiKey(
      'imported-wallet-agent',
      [wallet.id],
      ['test-imported-wallet'],
      '',
      null,
      vaultDir,
    );

    const msgSig = signMessage(
      wallet.id,
      'base',
      'hello',
      key.token,
      undefined,
      undefined,
      vaultDir,
    );
    assert.ok(msgSig.signature.length > 0);

    const txSig = signTransaction(wallet.id, 'base', 'deadbeef', key.token, null, vaultDir);
    assert.ok(txSig.signature.length > 0);

    revokeApiKey(key.id, vaultDir);
    deletePolicy('test-imported-wallet', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('signs EIP-712 typed data with an API key token', () => {
    const wallet = createWallet('typed-data-api', undefined, 12, vaultDir);

    // Register a policy allowing Base chains
    createPolicy(JSON.stringify({
      id: 'td-base-only',
      name: 'Base Only',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453', 'eip155:84532'] },
      ],
      action: 'deny',
    }), vaultDir);

    // Create API key bound to the wallet and policy
    const key = createApiKey('td-agent', [wallet.id], ['td-base-only'], '', null, vaultDir);
    assert.ok(key.token.startsWith('ows_key_'));

    // EIP-712 typed data (the standard "Mail" example)
    const typedDataJson = JSON.stringify({
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      },
      primaryType: 'Mail',
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 8453,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      },
      message: {
        from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
        to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
        contents: 'Hello, Bob!',
      },
    });

    // Sign on allowed chain — should succeed
    const sig = signTypedData(wallet.id, 'base', typedDataJson, key.token, null, vaultDir);
    assert.ok(sig.signature.length > 0, 'signature should be non-empty');
    assert.ok(sig.recoveryId != null, 'recoveryId should be present for EIP-712');

    // Sign on denied chain — should fail
    // Build typed data with chainId=1 matching ethereum so the domain check passes
    // and AllowedChains (base-only) correctly denies
    const ethTypedDataJson = JSON.stringify({
      ...JSON.parse(typedDataJson),
      domain: { ...JSON.parse(typedDataJson).domain, chainId: 1 },
    });
    assert.throws(
      () => signTypedData(wallet.id, 'ethereum', ethTypedDataJson, key.token, null, vaultDir),
      (err) => err.message.includes('not in allowlist'),
    );

    // Cleanup
    revokeApiKey(key.id, vaultDir);
    deletePolicy('td-base-only', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('enforces AllowedTypedDataContracts through the node binding', () => {
    const wallet = createWallet('typed-data-contract-api', undefined, 12, vaultDir);

    createPolicy(JSON.stringify({
      id: 'td-contract-only',
      name: 'Typed Data Contract Only',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453'] },
        {
          type: 'allowed_typed_data_contracts',
          contracts: ['0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'],
        },
      ],
      action: 'deny',
    }), vaultDir);

    const key = createApiKey('td-contract-agent', [wallet.id], ['td-contract-only'], '', null, vaultDir);

    const typedData = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Mail: [{ name: 'contents', type: 'string' }],
      },
      primaryType: 'Mail',
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 8453,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      },
      message: {
        contents: 'Hello, Bob!',
      },
    };

    const allowed = signTypedData(
      wallet.id,
      'base',
      JSON.stringify(typedData),
      key.token,
      null,
      vaultDir,
    );
    assert.ok(allowed.signature.length > 0);

    const deniedTypedData = {
      ...typedData,
      domain: {
        ...typedData.domain,
        verifyingContract: '0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC',
      },
    };

    assert.throws(
      () => signTypedData(wallet.id, 'base', JSON.stringify(deniedTypedData), key.token, null, vaultDir),
      (err) => err.message.includes('not in allowed list'),
    );

    revokeApiKey(key.id, vaultDir);
    deletePolicy('td-contract-only', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('executable policy gates signing', () => {
    const wallet = createWallet('exe-test', undefined, 12, vaultDir);

    // Write a deny script
    const scriptPath = join(vaultDir, 'deny.sh');
    writeFileSync(scriptPath, '#!/bin/sh\ncat > /dev/null\necho \'{"allow":false,"reason":"custom: blocked"}\'\n', { mode: 0o755 });

    createPolicy(JSON.stringify({
      id: 'test-exe-deny',
      name: 'Executable Deny',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [],
      executable: scriptPath,
      action: 'deny',
    }), vaultDir);

    const key = createApiKey('exe-agent', [wallet.id], ['test-exe-deny'], '', null, vaultDir);

    assert.throws(
      () => signTransaction(wallet.id, 'evm', 'deadbeef', key.token, null, vaultDir),
      (err) => err.message.includes('custom: blocked'),
    );

    revokeApiKey(key.id, vaultDir);
    deletePolicy('test-exe-deny', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('signs raw hashes and authorizations through the API-key path', () => {
    const wallet = createWallet('hash-policy-test', undefined, 12, vaultDir);

    createPolicy(JSON.stringify({
      id: 'test-hash-base-only',
      name: 'Base Only Hash',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453'] },
      ],
      action: 'deny',
    }), vaultDir);

    const key = createApiKey('hash-agent', [wallet.id], ['test-hash-base-only'], '', null, vaultDir);

    const hashSig = signHash(wallet.id, 'base', '22'.repeat(32), key.token, null, vaultDir);
    assert.ok(hashSig.signature.length > 0);

    const authSig = signAuthorization(
      wallet.id,
      'base',
      '0x1111111111111111111111111111111111111111',
      '7',
      key.token,
      null,
      vaultDir,
    );
    assert.ok(authSig.signature.length > 0);

    assert.throws(
      () => signAuthorization(
        wallet.id,
        'ethereum',
        '0x1111111111111111111111111111111111111111',
        '7',
        key.token,
        null,
        vaultDir,
      ),
      (err) => err.message.includes('not in allowlist'),
    );

    revokeApiKey(key.id, vaultDir);
    deletePolicy('test-hash-base-only', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });
});
