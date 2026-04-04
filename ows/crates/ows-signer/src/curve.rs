/// Elliptic curve type used by a chain signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    Secp256k1,
    Ed25519,
    /// Ed25519-BIP32 extended keys (Cardano CIP-1852 / BIP32-Ed25519).
    /// Private keys are 64 bytes: 32-byte scalar || 32-byte extension.
    Ed25519Bip32,
}

impl Curve {
    /// Returns the expected private key length in bytes.
    pub fn private_key_len(&self) -> usize {
        match self {
            Curve::Secp256k1 => 32,
            Curve::Ed25519 => 32,
            Curve::Ed25519Bip32 => 64,
        }
    }

    /// Returns the expected public key length in bytes (compressed for secp256k1).
    pub fn public_key_len(&self) -> usize {
        match self {
            Curve::Secp256k1 => 33, // compressed
            Curve::Ed25519 => 32,
            Curve::Ed25519Bip32 => 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_lengths_secp256k1() {
        assert_eq!(Curve::Secp256k1.private_key_len(), 32);
        assert_eq!(Curve::Secp256k1.public_key_len(), 33);
    }

    #[test]
    fn test_key_lengths_ed25519() {
        assert_eq!(Curve::Ed25519.private_key_len(), 32);
        assert_eq!(Curve::Ed25519.public_key_len(), 32);
    }

    #[test]
    fn test_equality() {
        assert_eq!(Curve::Secp256k1, Curve::Secp256k1);
        assert_eq!(Curve::Ed25519, Curve::Ed25519);
        assert_ne!(Curve::Secp256k1, Curve::Ed25519);
    }
}
