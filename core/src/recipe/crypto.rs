//! F-79 — AES (CBC/CTR/ECB) and RC4, via the RustCrypto ciphers (D8: crypto
//! reuses RustCrypto rather than being hand-rolled — the same precedent as the
//! hashes). Everything else in this module is byte-shuffling; this is the one
//! place a vetted implementation is non-negotiable.
//!
//! CBC and ECB use PKCS#7 padding; CTR is a keystream mode with no padding.
//! The key length selects AES-128/192/256; the IV must be 16 bytes for CBC/CTR.

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit, StreamCipher,
};

use crate::error::{Error, ErrorKind, Result};

fn bad(detail: impl Into<String>) -> Error {
    Error::new(ErrorKind::Io, detail)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesMode {
    Cbc,
    Ctr,
    Ecb,
}

impl AesMode {
    pub fn name(self) -> &'static str {
        match self {
            AesMode::Cbc => "cbc",
            AesMode::Ctr => "ctr",
            AesMode::Ecb => "ecb",
        }
    }

    pub fn from_name(s: &str) -> Option<AesMode> {
        Some(match s.to_ascii_lowercase().as_str() {
            "cbc" => AesMode::Cbc,
            "ctr" => AesMode::Ctr,
            "ecb" => AesMode::Ecb,
            _ => return None,
        })
    }
}

/// Runs one AES operation. `$c` is the concrete AES cipher chosen by key length.
macro_rules! aes_run {
    ($c:ty, $mode:expr, $enc:expr, $key:expr, $iv:expr, $data:expr) => {{
        let bad_iv = || bad("AES CBC/CTR need a 16-byte IV");
        match ($mode, $enc) {
            (AesMode::Cbc, true) => Ok(cbc::Encryptor::<$c>::new_from_slices($key, $iv)
                .map_err(|_| bad_iv())?
                .encrypt_padded_vec::<Pkcs7>($data)),
            (AesMode::Cbc, false) => cbc::Decryptor::<$c>::new_from_slices($key, $iv)
                .map_err(|_| bad_iv())?
                .decrypt_padded_vec::<Pkcs7>($data)
                .map_err(|_| bad("AES-CBC: invalid padding or wrong key")),
            (AesMode::Ecb, true) => Ok(ecb::Encryptor::<$c>::new_from_slice($key)
                .expect("key length checked")
                .encrypt_padded_vec::<Pkcs7>($data)),
            (AesMode::Ecb, false) => ecb::Decryptor::<$c>::new_from_slice($key)
                .expect("key length checked")
                .decrypt_padded_vec::<Pkcs7>($data)
                .map_err(|_| bad("AES-ECB: invalid padding or wrong key")),
            (AesMode::Ctr, _) => {
                let mut buf = $data.to_vec();
                ctr::Ctr128BE::<$c>::new_from_slices($key, $iv)
                    .map_err(|_| bad_iv())?
                    .apply_keystream(&mut buf);
                Ok(buf)
            }
        }
    }};
}

pub fn aes(mode: AesMode, encrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match key.len() {
        16 => aes_run!(Aes128, mode, encrypt, key, iv, data),
        24 => aes_run!(Aes192, mode, encrypt, key, iv, data),
        32 => aes_run!(Aes256, mode, encrypt, key, iv, data),
        n => Err(bad(format!("AES key must be 16, 24 or 32 bytes, got {n}"))),
    }
}

pub fn rc4(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use rc4::{KeyInit as _, Rc4, StreamCipher as _};
    let mut cipher = Rc4::new_from_slice(key).map_err(|_| bad("RC4 key must be 1..=256 bytes"))?;
    let mut buf = data.to_vec();
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}
