use crate::zeroizing::SecretBytes;
use coins_bip39::wordlist::Wordlist;
use coins_bip39::{English, Mnemonic as Bip39Mnemonic};

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

    /// Raw BIP-39 entropy bytes (English wordlist; checksum bits excluded).
    /// NOTE: assumes that the phrase is valid and in the English wordlist.
    pub fn entropy(&self) -> SecretBytes {
        use zeroize::Zeroize;

        let phrase = self.inner.to_phrase();

        let total_bits = phrase.split(' ').count() * 11;
        let ent_bytes = (total_bits - total_bits / 33) / 8;

        let mut out = Vec::with_capacity(total_bits / 8);
        let mut acc: u32 = 0;
        let mut acc_bits: u32 = 0;
        for word in phrase.split(' ') {
            acc = (acc << 11) | English::get_index(word).unwrap() as u32;
            acc_bits += 11;
            while acc_bits >= 8 {
                acc_bits -= 8;
                out.push((acc >> acc_bits) as u8);
            }
        }
        out.truncate(ent_bytes);

        acc.zeroize();
        let mut phrase = phrase;
        Zeroize::zeroize(unsafe { phrase.as_mut_vec() });
        SecretBytes::new(out)
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
    fn test_entropy_abandon_all_zero() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let ent = mnemonic.entropy();
        assert_eq!(ent.expose(), &[0u8; 16]);
    }

    // BIP-39 test vectors (Trezor). The 24-word cases matter because 24 words carry
    // 264 bits, so the last emitted byte is pure checksum and must be dropped.
    #[test]
    fn test_entropy_bip39_vectors() {
        let cases: [(&str, &[u8]); 3] = [
            (
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                &[0x7f; 16],
            ),
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon art",
                &[0x00; 32],
            ),
            (
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                 zoo zoo zoo vote",
                &[0xff; 32],
            ),
        ];

        for (phrase, expected) in cases {
            let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
            let ent = mnemonic.entropy();
            assert_eq!(
                hex::encode(ent.expose()),
                hex::encode(expected),
                "entropy mismatch for '{phrase}'"
            );
        }
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
