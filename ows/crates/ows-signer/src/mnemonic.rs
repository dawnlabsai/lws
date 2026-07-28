use crate::zeroizing::SecretBytes;
use coins_bip39::{English, Mnemonic as Bip39Mnemonic, Wordlist};

/// Mnemonic strength / word count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicStrength {
    /// 12 words (128 bits of entropy)
    Words12,
    /// 24 words (256 bits of entropy)
    Words24,
}

/// A BIP-39 mnemonic phrase.
///
/// Wraps `coins_bip39::Mnemonic<English>` with zeroization-aware accessors.
pub struct Mnemonic {
    inner: Bip39Mnemonic<English>,
}

impl Mnemonic {
    /// Generate a new random mnemonic with the given strength.
    pub fn generate(strength: MnemonicStrength) -> Result<Self, MnemonicError> {
        let word_count = match strength {
            MnemonicStrength::Words12 => 12usize,
            MnemonicStrength::Words24 => 24usize,
        };
        let mnemonic =
            Bip39Mnemonic::<English>::new_with_count(&mut rand::thread_rng(), word_count)
                .map_err(|e| MnemonicError::GenerationFailed(e.to_string()))?;
        Ok(Mnemonic { inner: mnemonic })
    }

    /// Create a mnemonic from an existing phrase.
    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        let mnemonic = Bip39Mnemonic::<English>::new_from_phrase(phrase)
            .map_err(|e| MnemonicError::InvalidPhrase(e.to_string()))?;
        Ok(Mnemonic { inner: mnemonic })
    }

    /// Get the mnemonic phrase as SecretBytes.
    pub fn phrase(&self) -> SecretBytes {
        let phrase_str = self.inner.to_phrase();
        SecretBytes::new(phrase_str.into_bytes())
    }

    /// Derive a BIP-39 seed from this mnemonic with an optional passphrase.
    pub fn to_seed(&self, passphrase: &str) -> SecretBytes {
        let pass = if passphrase.is_empty() {
            None
        } else {
            Some(passphrase)
        };
        let seed = self
            .inner
            .to_seed(pass)
            .expect("seed derivation should not fail");
        SecretBytes::new(seed.to_vec())
    }

    /// Recover the raw BIP-39 entropy bytes encoded by this mnemonic.
    ///
    /// Each word encodes 11 bits; the trailing `word_count / 3` bits are the
    /// checksum and are discarded. Needed by Cardano's Icarus (CIP-3) master
    /// key generation, which is keyed on the entropy rather than the seed.
    pub fn to_entropy(&self) -> SecretBytes {
        let mut phrase = self.inner.to_phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let entropy_bits = words.len() * 11 - words.len() / 3;
        let mut entropy = vec![0u8; entropy_bits / 8];
        let mut bit = 0usize;
        for word in &words {
            let index = English::get_index(word).expect("phrase was validated on construction");
            for i in (0..11).rev() {
                if bit == entropy_bits {
                    break;
                }
                if (index >> i) & 1 == 1 {
                    entropy[bit / 8] |= 1 << (7 - (bit % 8));
                }
                bit += 1;
            }
        }
        zeroize::Zeroize::zeroize(unsafe { phrase.as_mut_vec() });
        SecretBytes::new(entropy)
    }

    /// Returns the number of words in this mnemonic.
    pub fn word_count(&self) -> usize {
        let mut phrase = self.inner.to_phrase();
        let count = phrase.split_whitespace().count();
        // Zeroize the temporary string to prevent mnemonic leaking in memory.
        zeroize::Zeroize::zeroize(unsafe { phrase.as_mut_vec() });
        count
    }
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Errors related to mnemonic operations.
#[derive(Debug, thiserror::Error)]
pub enum MnemonicError {
    #[error("mnemonic generation failed: {0}")]
    GenerationFailed(String),

    #[error("invalid mnemonic phrase: {0}")]
    InvalidPhrase(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_12_words() {
        let mnemonic = Mnemonic::generate(MnemonicStrength::Words12).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
    }

    #[test]
    fn test_generate_24_words() {
        let mnemonic = Mnemonic::generate(MnemonicStrength::Words24).unwrap();
        assert_eq!(mnemonic.word_count(), 24);
    }

    #[test]
    fn test_known_phrase_abandon() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
        let recovered = String::from_utf8(mnemonic.phrase().expose().to_vec()).unwrap();
        assert_eq!(recovered, phrase);
    }

    #[test]
    fn test_reject_invalid_words() {
        let result = Mnemonic::from_phrase(
            "invalid words that are not in the bip39 wordlist at all need twelve",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_bad_checksum() {
        // Valid words but wrong checksum (last word changed)
        let result = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_seed_vector_no_passphrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed = mnemonic.to_seed("");
        let seed_hex = hex::encode(seed.expose());
        assert_eq!(
            seed_hex,
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn test_seed_with_passphrase_trezor() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed_no_pass = mnemonic.to_seed("");
        let seed_with_pass = mnemonic.to_seed("TREZOR");
        // Seeds should differ with different passphrases
        assert_ne!(seed_no_pass.expose(), seed_with_pass.expose());
        // Known BIP-39 test vector for "TREZOR" passphrase
        let seed_hex = hex::encode(seed_with_pass.expose());
        assert_eq!(
            seed_hex,
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn test_debug_doesnt_leak() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let debug = format!("{:?}", mnemonic);
        assert!(!debug.contains("abandon"));
        assert!(debug.contains("[REDACTED]"));
    }
}
