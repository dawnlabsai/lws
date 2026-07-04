# @open-wallet-standard/adapters

Framework adapters for the Open Wallet Standard — drop an OWS wallet into viem, Solana Kit, Solana web3.js, or the Tether WDK without surfacing private keys.

[![npm](https://img.shields.io/npm/v/@open-wallet-standard/adapters)](https://www.npmjs.com/package/@open-wallet-standard/adapters)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/open-wallet-standard/core/blob/main/LICENSE)

## Install

```bash
npm install @open-wallet-standard/adapters @open-wallet-standard/core
```

Then install whichever framework you use alongside it:

```bash
npm install viem                    # for the viem adapter
npm install @solana/kit             # for the Solana Kit adapter
npm install @solana/web3.js         # for the Solana adapter
npm install @tetherto/wdk-wallet    # for the WDK adapter
```

Framework SDKs are declared as optional peer dependencies — install only what you need.

## Adapters

| Adapter | Entry point | Returns |
|---------|-------------|---------|
| viem | `@open-wallet-standard/adapters/viem` | `viem` `Account` that signs via OWS |
| Solana | `@open-wallet-standard/adapters/solana` | `@solana/web3.js` `Keypair` |
| Solana Kit | `@open-wallet-standard/adapters/solana-kit` | `@solana/kit` `KeyPairSigner` |
| WDK | `@open-wallet-standard/adapters/wdk` | WDK `IWalletAccount`-compatible object |

All four delegate signing to `@open-wallet-standard/core`, so keys remain encrypted in the OWS vault.

## viem

```javascript
import { owsToViemAccount } from "@open-wallet-standard/adapters/viem";
import { createWalletClient, http } from "viem";
import { mainnet } from "viem/chains";

const account = owsToViemAccount("agent-treasury");

const client = createWalletClient({ account, chain: mainnet, transport: http() });
const hash = await client.sendTransaction({ to: "0x...", value: 0n });
```

Options: `chain` (CAIP-2, defaults to `eip155:1`), `passphrase`, `index`, `vaultPath`.

## Solana

```javascript
import { owsToSolanaKeypair } from "@open-wallet-standard/adapters/solana";
import { Connection, SystemProgram, Transaction } from "@solana/web3.js";

const keypair = owsToSolanaKeypair("agent-treasury");

const connection = new Connection("https://api.mainnet-beta.solana.com");
const tx = new Transaction().add(
  SystemProgram.transfer({ fromPubkey: keypair.publicKey, toPubkey: keypair.publicKey, lamports: 0 }),
);
tx.sign(keypair);
```

Options: `passphrase`, `vaultPath`.

The Solana adapter requires a wallet imported from a raw ed25519 private key. Mnemonic-derived wallets cannot be unwrapped into a `Keypair` — use `signMessage` / `signTransaction` from `@open-wallet-standard/core` directly.

## Solana Kit

```javascript
import { owsToSolanaKeyPairSigner } from "@open-wallet-standard/adapters/solana-kit";

const signer = await owsToSolanaKeyPairSigner("agent-treasury");

console.log(signer.address);
```

Options: `passphrase`, `vaultPath`.

The Solana Kit adapter requires a wallet imported from a raw ed25519 private key. Mnemonic-derived wallets cannot be unwrapped into a `KeyPairSigner` — use `signMessage` / `signTransaction` from `@open-wallet-standard/core` directly.

## WDK (Tether Wallet Development Kit)

```javascript
import { owsToWdkAccount } from "@open-wallet-standard/adapters/wdk";

const account = owsToWdkAccount("agent-treasury", "evm");

const address = await account.getAddress();
const signature = await account.sign("hello");
const txHash = await account.sendTransaction("deadbeef...");
```

`chain` accepts WDK short names (`"evm"`, `"solana"`, `"btc"`, `"ton"`, `"tron"`, `"cosmos"`, `"sui"`, `"xrpl"`, `"filecoin"`, `"spark"`) or CAIP-2 identifiers.

Options: `passphrase`, `index`, `rpcUrl`, `vaultPath`.

## Documentation

Full spec and docs at [openwallet.sh](https://openwallet.sh) and the [GitHub repo](https://github.com/open-wallet-standard/core).

## License

MIT
