import type { KeyPairSigner } from "@solana/kit";

export interface OwsSolanaKitOptions {
  passphrase?: string;
  vaultPath?: string;
}

export declare function owsToSolanaKeyPairSigner(
  walletNameOrId: string,
  options?: OwsSolanaKitOptions,
): Promise<KeyPairSigner>;
