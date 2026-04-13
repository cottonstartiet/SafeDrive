/// Block cipher engines and encryption algorithm cascade table.
/// Supports AES-256, Serpent-256, and Twofish-256 with 128-bit blocks.

use aes::Aes256;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use cipher::generic_array::GenericArray;
use serpent::Serpent;
use twofish::Twofish;

/// A single block cipher engine (encrypt + decrypt) with a 256-bit key.
pub struct CipherEngine {
    name: &'static str,
    engine: CipherImpl,
}

enum CipherImpl {
    Aes(Aes256),
    Serpent(Serpent),
    Twofish(Twofish),
}

impl CipherEngine {
    pub fn new(name: &'static str, key: &[u8; 32]) -> Self {
        let engine = match name {
            "AES" => CipherImpl::Aes(Aes256::new_from_slice(key).unwrap()),
            "Serpent" => CipherImpl::Serpent(Serpent::new_from_slice(key).unwrap()),
            "Twofish" => CipherImpl::Twofish(Twofish::new_from_slice(key).unwrap()),
            _ => panic!("Unknown cipher: {}", name),
        };
        CipherEngine { name, engine }
    }

    #[inline]
    pub fn encrypt_block(&self, data: &mut [u8]) {
        let block = GenericArray::from_mut_slice(&mut data[..16]);
        match &self.engine {
            CipherImpl::Aes(c) => c.encrypt_block(block),
            CipherImpl::Serpent(c) => c.encrypt_block(block),
            CipherImpl::Twofish(c) => c.encrypt_block(block),
        }
    }

    #[inline]
    pub fn decrypt_block(&self, data: &mut [u8]) {
        let block = GenericArray::from_mut_slice(&mut data[..16]);
        match &self.engine {
            CipherImpl::Aes(c) => c.decrypt_block(block),
            CipherImpl::Serpent(c) => c.decrypt_block(block),
            CipherImpl::Twofish(c) => c.decrypt_block(block),
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
}

/// A TrueCrypt Encryption Algorithm — one or more ciphers in a cascade.
#[derive(Debug, Clone)]
pub struct EncryptionAlgorithm {
    pub name: &'static str,
    pub cipher_names: &'static [&'static str],
}

impl EncryptionAlgorithm {
    /// Total key size in bytes (each cipher uses 32 bytes).
    pub fn key_size(&self) -> usize {
        self.cipher_names.len() * 32
    }

    /// All encryption algorithms from TrueCrypt's EncryptionAlgorithms[] table.
    pub const ALL: &[EncryptionAlgorithm] = &[
        EncryptionAlgorithm { name: "AES", cipher_names: &["AES"] },
        EncryptionAlgorithm { name: "Serpent", cipher_names: &["Serpent"] },
        EncryptionAlgorithm { name: "Twofish", cipher_names: &["Twofish"] },
        EncryptionAlgorithm { name: "Twofish-AES", cipher_names: &["Twofish", "AES"] },
        EncryptionAlgorithm { name: "Serpent-Twofish-AES", cipher_names: &["Serpent", "Twofish", "AES"] },
        EncryptionAlgorithm { name: "AES-Serpent", cipher_names: &["AES", "Serpent"] },
        EncryptionAlgorithm { name: "AES-Twofish-Serpent", cipher_names: &["AES", "Twofish", "Serpent"] },
        EncryptionAlgorithm { name: "Serpent-Twofish", cipher_names: &["Serpent", "Twofish"] },
    ];

    /// Creates cipher engines from key material.
    /// Returns (primary_engines, secondary_engines) for XTS mode.
    pub fn create_engines(&self, derived_key: &[u8]) -> (Vec<CipherEngine>, Vec<CipherEngine>) {
        let key_size = self.key_size();
        let mut primary = Vec::with_capacity(self.cipher_names.len());
        let mut secondary = Vec::with_capacity(self.cipher_names.len());

        for (i, &cipher_name) in self.cipher_names.iter().enumerate() {
            let mut pk = [0u8; 32];
            let mut sk = [0u8; 32];
            pk.copy_from_slice(&derived_key[i * 32..(i + 1) * 32]);
            sk.copy_from_slice(&derived_key[key_size + i * 32..key_size + (i + 1) * 32]);
            primary.push(CipherEngine::new(cipher_name, &pk));
            secondary.push(CipherEngine::new(cipher_name, &sk));
        }

        (primary, secondary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let engine = CipherEngine::new("AES", &key);
        let original = [0xABu8; 16];
        let mut data = original;
        engine.encrypt_block(&mut data);
        assert_ne!(data, original);
        engine.decrypt_block(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_all_algorithms_key_sizes() {
        assert_eq!(EncryptionAlgorithm::ALL[0].key_size(), 32);  // AES
        assert_eq!(EncryptionAlgorithm::ALL[3].key_size(), 64);  // Twofish-AES
        assert_eq!(EncryptionAlgorithm::ALL[4].key_size(), 96);  // Serpent-Twofish-AES
    }

    #[test]
    fn test_create_engines() {
        let key_material = [0x55u8; 256];
        let ea = &EncryptionAlgorithm::ALL[3]; // Twofish-AES (2 ciphers)
        let (primary, secondary) = ea.create_engines(&key_material);
        assert_eq!(primary.len(), 2);
        assert_eq!(secondary.len(), 2);
        assert_eq!(primary[0].name(), "Twofish");
        assert_eq!(primary[1].name(), "AES");
    }

    #[test]
    fn test_serpent_encrypt_decrypt_roundtrip() {
        let key = [0x13u8; 32];
        let engine = CipherEngine::new("Serpent", &key);
        let original = [0xCDu8; 16];
        let mut data = original;
        engine.encrypt_block(&mut data);
        assert_ne!(data, original);
        engine.decrypt_block(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_twofish_encrypt_decrypt_roundtrip() {
        let key = [0x77u8; 32];
        let engine = CipherEngine::new("Twofish", &key);
        let original = [0xEFu8; 16];
        let mut data = original;
        engine.encrypt_block(&mut data);
        assert_ne!(data, original);
        engine.decrypt_block(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_cipher_engine_names() {
        let key = [0u8; 32];
        assert_eq!(CipherEngine::new("AES", &key).name(), "AES");
        assert_eq!(CipherEngine::new("Serpent", &key).name(), "Serpent");
        assert_eq!(CipherEngine::new("Twofish", &key).name(), "Twofish");
    }

    #[test]
    #[should_panic(expected = "Unknown cipher")]
    fn test_unknown_cipher_panics() {
        let key = [0u8; 32];
        CipherEngine::new("Blowfish", &key);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let engine1 = CipherEngine::new("AES", &key1);
        let engine2 = CipherEngine::new("AES", &key2);

        let mut data1 = [0xAAu8; 16];
        let mut data2 = [0xAAu8; 16];
        engine1.encrypt_block(&mut data1);
        engine2.encrypt_block(&mut data2);
        assert_ne!(data1, data2);
    }

    #[test]
    fn test_all_encryption_algorithm_names() {
        let names: Vec<&str> = EncryptionAlgorithm::ALL.iter().map(|ea| ea.name).collect();
        assert!(names.contains(&"AES"));
        assert!(names.contains(&"Serpent"));
        assert!(names.contains(&"Twofish"));
        assert!(names.contains(&"Twofish-AES"));
        assert!(names.contains(&"Serpent-Twofish-AES"));
        assert!(names.contains(&"AES-Serpent"));
        assert!(names.contains(&"AES-Twofish-Serpent"));
        assert!(names.contains(&"Serpent-Twofish"));
    }

    #[test]
    fn test_all_algorithm_count() {
        assert_eq!(EncryptionAlgorithm::ALL.len(), 8);
    }

    #[test]
    fn test_single_cipher_key_sizes() {
        for ea in EncryptionAlgorithm::ALL {
            if ea.cipher_names.len() == 1 {
                assert_eq!(ea.key_size(), 32, "Single cipher {} should have 32-byte key", ea.name);
            }
        }
    }

    #[test]
    fn test_cascade_key_sizes() {
        for ea in EncryptionAlgorithm::ALL {
            assert_eq!(
                ea.key_size(),
                ea.cipher_names.len() * 32,
                "Algorithm {} key size mismatch",
                ea.name
            );
        }
    }

    #[test]
    fn test_create_engines_all_algorithms() {
        let key_material = [0xAA_u8; 256];
        for ea in EncryptionAlgorithm::ALL {
            let (primary, secondary) = ea.create_engines(&key_material);
            assert_eq!(primary.len(), ea.cipher_names.len(), "Primary engine count mismatch for {}", ea.name);
            assert_eq!(secondary.len(), ea.cipher_names.len(), "Secondary engine count mismatch for {}", ea.name);

            // Verify engine names match cipher_names
            for (i, &cipher_name) in ea.cipher_names.iter().enumerate() {
                assert_eq!(primary[i].name(), cipher_name);
                assert_eq!(secondary[i].name(), cipher_name);
            }
        }
    }

    #[test]
    fn test_create_engines_roundtrip_all_algorithms() {
        let key_material = [0xBB_u8; 256];
        let original = [0x99_u8; 16];

        for ea in EncryptionAlgorithm::ALL {
            let (primary, _secondary) = ea.create_engines(&key_material);

            // Each primary engine should roundtrip correctly
            for engine in &primary {
                let mut data = original;
                engine.encrypt_block(&mut data);
                assert_ne!(data, original, "Encryption should change data for {}", ea.name);
                engine.decrypt_block(&mut data);
                assert_eq!(data, original, "Roundtrip failed for engine in {}", ea.name);
            }
        }
    }

    #[test]
    fn test_encrypt_is_not_identity() {
        // Ensure encrypting all-zero data does not produce all-zero output
        let key = [0x42u8; 32];
        for cipher_name in &["AES", "Serpent", "Twofish"] {
            let engine = CipherEngine::new(cipher_name, &key);
            let mut data = [0u8; 16];
            engine.encrypt_block(&mut data);
            assert_ne!(data, [0u8; 16], "{} encrypted zeros should not be zeros", cipher_name);
        }
    }
}
