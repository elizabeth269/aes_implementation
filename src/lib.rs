extern crate ring;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

/// Encrypts the given plaintext using AES-256-GCM encryption.
///
/// # Arguments
///
/// * `key` - A 32-byte key for AES-256-GCM encryption.
/// * `plaintext` - The data to encrypt.
///
/// # Returns
///
/// A tuple containing the encrypted ciphertext and the nonce used for encryption.
fn main() {
    pub fn encrypt_aes_256_gcm(
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Unspecified> {
        // Ensure the key length is 32 bytes for AES-256
        assert_eq!(key.len(), 32);

        // Generate a random nonce
        let mut nonce = vec![12; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce)?;

        let nonce = Nonce::assume_unique_for_key([12; NONCE_LEN]);
        let aad = Aad::empty();
        let mut in_out = plaintext.to_vec();

        // Initialize the key and encrypt the data
        let key = UnboundKey::new(&AES_256_GCM, key)?;
        let key = LessSafeKey::new(key);
        key.seal_in_place_append_tag(nonce, aad, &mut in_out)?;

        Ok((in_out, nonce.as_ref().to_vec()))
    }

    /// Decrypts the given ciphertext using AES-256-GCM encryption.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte key for AES-256-GCM decryption.
    /// * `nonce` - The nonce used for encryption.
    /// * `ciphertext` - The data to decrypt.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    pub fn decrypt_aes_256_gcm(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Unspecified> {
        // Ensure the key length is 32 bytes for AES-256
        assert_eq!(key.len(), 32);

        let nonce = Nonce::try_assume_unique_for_key(nonce)?;
        let aad = Aad::empty();
        let mut in_out = ciphertext.to_vec();

        // Initialize the key and decrypt the data
        let key = UnboundKey::new(&AES_256_GCM, key)?;
        let key = LessSafeKey::new(key);
        key.open_in_place(nonce, aad, &mut in_out)?;

        // Extract the plaintext from the decrypted data
        let plaintext = in_out.split_off(in_out.len() - AES_256_GCM.tag_len());
        Ok(plaintext)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        pub fn encrypt_aes_256_gcm(
            key: &[u8],
            plaintext: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), Unspecified> {
            // Ensure the key length is 32 bytes for AES-256
            assert_eq!(key.len(), 32);

            // Generate a random nonce
            let mut nonce = vec![12; NONCE_LEN];
            SystemRandom::new().fill(&mut nonce)?;

            let nonce = Nonce::assume_unique_for_key([12; NONCE_LEN]);
            let aad = Aad::empty();
            let mut in_out = plaintext.to_vec();

            // Initialize the key and encrypt the data
            let key = UnboundKey::new(&AES_256_GCM, key)?;
            let key = LessSafeKey::new(key);
            key.seal_in_place_append_tag(nonce, aad, &mut in_out)?;

            Ok((in_out, nonce.as_ref().to_vec()))
        }

        /// Decrypts the given ciphertext using AES-256-GCM encryption.
        ///
        /// # Arguments
        ///
        /// * `key` - A 32-byte key for AES-256-GCM decryption.
        /// * `nonce` - The nonce used for encryption.
        /// * `ciphertext` - The data to decrypt.
        ///
        /// # Returns
        ///
        /// The decrypted plaintext.
        pub fn decrypt_aes_256_gcm(
            key: &[u8],
            nonce: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, Unspecified> {
            // Ensure the key length is 32 bytes for AES-256
            assert_eq!(key.len(), 32);

            let nonce = Nonce::try_assume_unique_for_key(nonce)?;
            let aad = Aad::empty();
            let mut in_out = ciphertext.to_vec();

            // Initialize the key and decrypt the data
            let key = UnboundKey::new(&AES_256_GCM, key)?;
            let key = LessSafeKey::new(key);
            key.open_in_place(nonce, aad, &mut in_out)?;

            // Extract the plaintext from the decrypted data
            let plaintext = in_out.split_off(in_out.len() - AES_256_GCM.tag_len());
            Ok(plaintext)
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn test_aes_256_gcm_encryption_decryption() {
                let key = b"an example very very secret key."; // 32 bytes
                let plaintext = b"hello world";

                let (ciphertext, nonce) =
                    encrypt_aes_256_gcm(key, plaintext).expect("encryption failed");
                let decrypted_plaintext =
                    decrypt_aes_256_gcm(key, &nonce, &ciphertext).expect("decryption failed");

                assert_eq!(plaintext.to_vec(), decrypted_plaintext);
            }
        }

        #[test]
        fn test_aes_256_gcm_encryption_decryption() {
            let key = b"an example very very secret key."; // 32 bytes
            let plaintext = b"hello world";

            let (ciphertext, nonce) =
                encrypt_aes_256_gcm(key, plaintext).expect("encryption failed");
            let decrypted_plaintext =
                decrypt_aes_256_gcm(key, &nonce, &ciphertext).expect("decryption failed");

            assert_eq!(plaintext.to_vec(), decrypted_plaintext);
        }
    }
}
