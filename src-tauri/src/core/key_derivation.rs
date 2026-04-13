/// PBKDF2 key derivation supporting all TrueCrypt PRFs.

use crate::core::constants::MASTER_KEY_DATA_SIZE;
use hmac::Hmac;
use pbkdf2::pbkdf2_hmac;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prf {
    RipeMd160,
    Sha512,
    Whirlpool,
    Sha1,
}

impl Prf {
    pub const ALL: &[Prf] = &[Prf::RipeMd160, Prf::Sha512, Prf::Whirlpool, Prf::Sha1];

    pub fn name(&self) -> &'static str {
        match self {
            Prf::RipeMd160 => "HMAC-RIPEMD-160",
            Prf::Sha512 => "HMAC-SHA-512",
            Prf::Whirlpool => "HMAC-Whirlpool",
            Prf::Sha1 => "HMAC-SHA-1",
        }
    }
}

/// Returns the PBKDF2 iteration count for a given PRF.
pub fn get_iterations(prf: Prf, boot: bool) -> u32 {
    match prf {
        Prf::RipeMd160 => if boot { 1000 } else { 2000 },
        Prf::Sha512 => 1000,
        Prf::Whirlpool => 1000,
        Prf::Sha1 => 2000,
    }
}

/// Derives a key using PBKDF2-HMAC with the specified PRF.
/// Output is MASTER_KEY_DATA_SIZE (256) bytes.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    prf: Prf,
    boot: bool,
) -> [u8; MASTER_KEY_DATA_SIZE] {
    let iterations = get_iterations(prf, boot);
    let mut output = [0u8; MASTER_KEY_DATA_SIZE];

    match prf {
        Prf::RipeMd160 => {
            pbkdf2_hmac::<ripemd::Ripemd160>(password, salt, iterations, &mut output);
        }
        Prf::Sha512 => {
            pbkdf2_hmac::<sha2::Sha512>(password, salt, iterations, &mut output);
        }
        Prf::Whirlpool => {
            // whirlpool crate implements the Digest trait; use hmac manually
            pbkdf2::pbkdf2::<Hmac<whirlpool::Whirlpool>>(password, salt, iterations, &mut output)
                .expect("HMAC can be initialized with any key length");
        }
        Prf::Sha1 => {
            pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, &mut output);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_sha512_produces_output() {
        let password = b"test_password";
        let salt = [0u8; 64];
        let key = derive_key(password, &salt, Prf::Sha512, false);
        // Just verify it's not all zeros (actual correctness verified against C# app)
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_all_prfs_produce_output() {
        let password = b"hello";
        let salt = [0x42u8; 64];
        for &prf in Prf::ALL {
            let key = derive_key(password, &salt, prf, false);
            assert!(key.iter().any(|&b| b != 0), "PRF {:?} produced all zeros", prf);
        }
    }

    #[test]
    fn test_prf_names() {
        assert_eq!(Prf::RipeMd160.name(), "HMAC-RIPEMD-160");
        assert_eq!(Prf::Sha512.name(), "HMAC-SHA-512");
        assert_eq!(Prf::Whirlpool.name(), "HMAC-Whirlpool");
        assert_eq!(Prf::Sha1.name(), "HMAC-SHA-1");
    }

    #[test]
    fn test_prf_all_count() {
        assert_eq!(Prf::ALL.len(), 4);
    }

    #[test]
    fn test_iterations_non_boot() {
        assert_eq!(get_iterations(Prf::RipeMd160, false), 2000);
        assert_eq!(get_iterations(Prf::Sha512, false), 1000);
        assert_eq!(get_iterations(Prf::Whirlpool, false), 1000);
        assert_eq!(get_iterations(Prf::Sha1, false), 2000);
    }

    #[test]
    fn test_iterations_boot() {
        assert_eq!(get_iterations(Prf::RipeMd160, true), 1000);
        // SHA-512, Whirlpool, SHA-1 don't change with boot flag
        assert_eq!(get_iterations(Prf::Sha512, true), 1000);
        assert_eq!(get_iterations(Prf::Whirlpool, true), 1000);
        assert_eq!(get_iterations(Prf::Sha1, true), 2000);
    }

    #[test]
    fn test_boot_flag_affects_ripemd160() {
        let boot_iters = get_iterations(Prf::RipeMd160, true);
        let normal_iters = get_iterations(Prf::RipeMd160, false);
        assert_ne!(boot_iters, normal_iters);
        assert!(boot_iters < normal_iters);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"deterministic_test";
        let salt = [0xCC_u8; 64];
        let key1 = derive_key(password, &salt, Prf::Sha512, false);
        let key2 = derive_key(password, &salt, Prf::Sha512, false);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_passwords_produce_different_keys() {
        let salt = [0x11u8; 64];
        let key1 = derive_key(b"password1", &salt, Prf::Sha512, false);
        let key2 = derive_key(b"password2", &salt, Prf::Sha512, false);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        let password = b"same_password";
        let salt1 = [0x11u8; 64];
        let salt2 = [0x22u8; 64];
        let key1 = derive_key(password, &salt1, Prf::Sha512, false);
        let key2 = derive_key(password, &salt2, Prf::Sha512, false);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_prfs_produce_different_keys() {
        let password = b"same_password";
        let salt = [0x55u8; 64];
        let keys: Vec<[u8; MASTER_KEY_DATA_SIZE]> = Prf::ALL
            .iter()
            .map(|&prf| derive_key(password, &salt, prf, false))
            .collect();

        // All PRFs should produce different outputs
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "PRF {:?} and {:?} produced same key", Prf::ALL[i], Prf::ALL[j]);
            }
        }
    }

    #[test]
    fn test_derive_key_output_length() {
        let key = derive_key(b"test", &[0u8; 64], Prf::Sha512, false);
        assert_eq!(key.len(), MASTER_KEY_DATA_SIZE);
        assert_eq!(key.len(), 256);
    }

    #[test]
    fn test_empty_password() {
        let salt = [0x42u8; 64];
        // Empty password should still produce output
        let key = derive_key(b"", &salt, Prf::Sha512, false);
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_boot_vs_non_boot_different_output_ripemd() {
        let password = b"boot_test";
        let salt = [0x99u8; 64];
        let key_boot = derive_key(password, &salt, Prf::RipeMd160, true);
        let key_normal = derive_key(password, &salt, Prf::RipeMd160, false);
        // Different iteration counts should produce different keys
        assert_ne!(key_boot, key_normal);
    }

    #[test]
    fn test_prf_equality() {
        assert_eq!(Prf::Sha512, Prf::Sha512);
        assert_ne!(Prf::Sha512, Prf::Sha1);
    }
}
