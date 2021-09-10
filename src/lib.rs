#![doc = include_str!("../README.md")]

use rand::rngs::OsRng;
use rand::RngCore;

#[macro_use]
mod macros;

#[cfg(feature = "cipher")]
pub mod cipher;

#[cfg(feature = "signature")]
pub mod signature;

#[cfg(feature = "hash")]
pub mod hash;

// from https://docs.rs/crate/chacha20/0.3.4/source/src/cipher.rs
/// Xors two buffers. Both buffers need to have the same length.
/// 
/// ## Panics
/// When the buffers don't have the same length.
pub fn xor(buf: &mut [u8], key: &[u8]) {
	assert_eq!(buf.len(), key.len());

	for (a, b) in buf.iter_mut().zip(key) {
		*a ^= *b;
	}
}

/// Fills a slice with random bytes.
pub fn fill_random(buf: &mut [u8]) {
	OsRng.fill_bytes(buf)
}

#[cfg(feature = "b64")]
#[derive(Debug, Clone)]
pub enum FromBase64Error {
	LengthNot32Bytes,
	LengthNot64Bytes,
	Base64(base64::DecodeError)
}

#[cfg(feature = "b64")]
impl From<base64::DecodeError> for FromBase64Error {
	fn from(e: base64::DecodeError) -> Self {
		Self::Base64(e)
	}
}
