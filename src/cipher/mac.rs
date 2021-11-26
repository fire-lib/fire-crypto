use crate::error::TryFromError;

use std::fmt;
use std::convert::{TryFrom, TryInto};

use generic_array::{GenericArray, typenum};
use typenum::{U16};

use poly1305::Tag;

// Tag is an universal_hash::Output which provides a `Eq` implementation with
// constant time
/// A message authentication code.
/// 
/// This is used to authenticate a message and it should always be transferred
/// with the ciphertext. Without it data integrity and authenticity is not guaranteed.
#[derive(Clone, PartialEq, Eq)]
pub struct Mac {
	tag: Tag
}

impl Mac {
	pub const LEN: usize = 16;

	pub(crate) fn new(tag: Tag) -> Self {
		Self { tag }
	}

	/// ## Panics
	/// if the slice is not 16 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn into_bytes(self) -> [u8; 16] {
		self.tag.into_bytes().into()
	}
}

impl fmt::Debug for Mac {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("Mac")
	}
}

impl From<[u8; 16]> for Mac {
	/// This function should only be used with bytes that
	/// were received with a message.
	fn from(bytes: [u8; 16]) -> Self {
		let gen: GenericArray<u8, U16> = bytes.into();

		Self { tag: Tag::new(gen) }
	}
}

impl TryFrom<&[u8]> for Mac {
	type Error = TryFromError;

	fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
		<[u8; 16]>::try_from(s)
			.map_err(TryFromError::from_any)
			.map(Mac::from)
	}
}