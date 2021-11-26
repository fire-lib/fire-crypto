use crate::fill_random;
use crate::error::TryFromError;

use std::convert::{TryFrom, TryInto};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
	bytes: [u8; 24]
}

impl Nonce {
	pub const LEN: usize = 24;

	/// Creates a new random Nonce.
	pub fn new() -> Self {
		let mut this = Self { bytes: [0u8; 24] };
		this.fill_random();
		this
	}

	/// Fills the nonce with new random bytes.
	pub fn fill_random(&mut self) {
		fill_random(&mut self.bytes);
	}

	#[cfg(test)]
	pub fn ones() -> Self {
		Self { bytes: [1u8; 24] }
	}

	/// ## Panics
	/// if the slice is not 24 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; 24] {
		self.bytes
	}

	/// Returns the nonce representation.
	pub fn into_bytes(self) -> [u8; 24] {
		self.bytes
	}

	/// Takes the current nonce, replacing it
	/// with a new random one.
	pub fn take(&mut self) -> Self {
		let n = Nonce::new();
		std::mem::replace(self, n)
	}

}

impl From<[u8; 24]> for Nonce {
	/// Creates a nonce from bytes.
	fn from(bytes: [u8; 24]) -> Self {
		Self { bytes }
	}
}

impl TryFrom<&[u8]> for Nonce {
	type Error = TryFromError;

	fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
		<[u8; 24]>::try_from(s)
			.map_err(TryFromError::from_any)
			.map(Nonce::from)
	}
}

impl AsRef<[u8]> for Nonce {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}