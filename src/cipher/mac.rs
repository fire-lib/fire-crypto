use std::fmt;

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

	/// This function should only be used with bytes that
	/// were received with a message.
	pub fn from_bytes(bytes: [u8; 16]) -> Self {
		let gen: GenericArray<u8, U16> = bytes.into();

		Self { tag: Tag::new(gen) }
	}

	/// Expects the slice to be of len `Mac::LEN`.
	pub fn from_slice_unchecked(slice: &[u8]) -> Self {
		let mut bytes = [0u8; 16];
		bytes.copy_from_slice(slice);

		Self::from_bytes(bytes)
	}

	pub fn into_bytes(self) -> [u8; 16] {
		self.tag.into_bytes().into()
	}
}

impl fmt::Debug for Mac {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Mac")
	}
}

impl From<Tag> for Mac {
	fn from(tag: Tag) -> Self {
		Self { tag }
	}
}

impl From<[u8; 16]> for Mac {
	fn from(bytes: [u8; 16]) -> Self {
		Self::from_bytes(bytes)
	}
}
