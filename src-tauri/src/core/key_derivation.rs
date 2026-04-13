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
}
