//! Contains structs used for hashing.
//!
//! ## Note
//! **Do not** use this hasher for hashing password
//! or other sensitive data since this hash does not
//! use any salt, it is vulnerable to a rainbow table
//! attack.


#[cfg(feature = "b64")]
use crate::FromBase64Error;
#[cfg(feature = "b64")]
use std::fmt;

use std::ptr;
use std::convert::TryInto;
use std::mem::ManuallyDrop;

use blake2::{Blake2b, Digest};
use generic_array::{GenericArray, typenum::U64};

pub struct Hasher {
	inner: Blake2b
}

impl Hasher {
	pub fn new() -> Self {
		Self {
			inner: Blake2b::new()
		}
	}

	pub fn update(&mut self, data: impl AsRef<[u8]>) {
		self.inner.update(data);
	}

	pub fn finalize(self) -> Hash {
		let arr = self.inner.finalize();
		Hash {
			bytes: convert_generic_array(arr)
		}
	}

	pub fn hash(data: impl AsRef<[u8]>) -> Hash {
		let mut hasher = Hasher::new();
		hasher.update(data);
		hasher.finalize()
	}
}

fn convert_generic_array<T>(arr: GenericArray<T, U64>) -> [T; 64] {
	// safe because both have the same memory layout
	// and generic array does it
	unsafe {
		// see https://docs.rs/generic-array/0.14.4/src/generic_array/lib.rs.html#636
		let a = ManuallyDrop::new(arr);
		ptr::read(&*a as *const GenericArray<T, U64> as *const [T; 64])
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash {
	bytes: [u8; 64]
}

impl Hash {
	pub const LEN: usize = 64;

	pub fn from_bytes(bytes: [u8; 64]) -> Self {
		Self { bytes }
	}

	/// ## Panics
	/// if the slice is not 64 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		Self::from_bytes(slice.try_into().unwrap())
	}

	pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
		slice.try_into().ok()
			.map(Self::from_bytes)
	}

	pub fn to_bytes(&self) -> [u8; 64] {
		self.bytes
	}

	pub fn as_slice(&self) -> &[u8] {
		&self.bytes
	}

	#[cfg(feature = "b64")]
	pub fn from_b64<T: AsRef<[u8]>>(input: T) -> Result<Self, FromBase64Error> {
		let b = base64::decode_config(input, base64::URL_SAFE_NO_PAD)?;
		Self::try_from_slice(&b)
			.ok_or(FromBase64Error::LengthNot64Bytes)
	}

	#[cfg(feature = "b64")]
	pub fn to_b64(&self) -> String {
		// returns 86 str
		base64::encode_config(self.as_slice(), base64::URL_SAFE_NO_PAD)
	}
}

impl From<[u8; 64]> for Hash {
	fn from(bytes: [u8; 64]) -> Self {
		Self::from_bytes(bytes)
	}
}

// DISPLAY
#[cfg(feature = "b64")]
impl fmt::Display for Hash {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(&self.to_b64())
	}
}

#[cfg(all(feature = "serde", feature = "b64"))]
impl_serde!(Hash, 86);

#[cfg(test)]
mod tests {

	use super::*;

	#[test]
	fn hash_something() {

		let bytes: Vec<u8> = (0..=255).collect();

		let hash = Hasher::hash(bytes);

		let hash_bytes = [
			30, 204, 137, 111, 52, 211, 249, 202,
			196, 132, 199, 63, 117, 246, 165, 251,
			88, 238, 103, 132, 190, 65, 179, 95,
			70, 6, 123, 156, 101, 198, 58, 103,
			148, 211, 215, 68, 17, 44, 101, 63,
			115, 221, 125, 235, 102, 102, 32, 76,
			90, 155, 250, 91, 70, 8, 31, 193,
			15, 219, 231, 136, 79, 165, 203, 248
		];
		assert_eq!(hash.to_bytes(), hash_bytes);

	}

	#[test]
	#[cfg(feature = "b64")]
	fn hash_b64() {

		let bytes: Vec<u8> = (0..=255).collect();

		let hash = Hasher::hash(bytes);

		assert_eq!(hash.to_b64(), "HsyJbzTT-crEhMc_dfal-1juZ4S-QbNfRgZ7nGXGOme\
			U09dEESxlP3PdfetmZiBMWpv6W0YIH8EP2-eIT6XL-A");

	}

}