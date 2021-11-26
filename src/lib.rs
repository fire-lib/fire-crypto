#![doc = include_str!("../README.md")]

use rand::rngs::OsRng;
use rand::RngCore;

/// used internally when b64
#[cfg(feature = "b64")]
use std::str::FromStr;

#[cfg(feature = "cipher")]
pub mod cipher;

#[cfg(feature = "signature")]
pub mod signature;

#[cfg(feature = "hash")]
pub mod hash;

pub mod token;

pub mod error;

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

/// todo replace when rust #88582 get's stabilized
/// 
/// Since this function multiplies s with 4
/// s needs to be 1/4 of usize::MAX in practice this should not be a problem
/// since the tokens won't be that long.
#[inline(always)]
const fn calculate_b64_len(s: usize) -> usize {
	let s = 4 * s;

	// following block is a div ceil
	let mut d = s / 3;
	let r = s % 3;
	if r > 0 {
		d += 1;
	}

	d
}

