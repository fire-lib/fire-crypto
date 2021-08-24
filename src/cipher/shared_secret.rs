use super::{Key, Nonce};

use std::fmt;
use std::cmp;

use x25519_dalek as x;

// should be hashed with
pub struct SharedSecret {
	inner: x::SharedSecret
}

impl SharedSecret {
	// nonce size U24
	/// ## Warning
	/// Don't call this function with the same nonce again.
	/// This probably leads to an insecure key.
	pub fn to_key(&self, initial_nonce: Nonce) -> Key {
		Key::new(self.to_bytes(), initial_nonce.into_inner())
	}

	fn to_bytes(&self) -> [u8; 32] {
		self.inner.to_bytes()
	}

	pub fn as_bytes(&self) -> &[u8; 32] {
		self.inner.as_bytes()
	}

	pub fn as_slice(&self) -> &[u8] {
		self.inner.as_bytes()
	}
}

impl fmt::Debug for SharedSecret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "SharedSecret")
	}
}

impl From<x::SharedSecret> for SharedSecret {
	fn from(inner: x::SharedSecret) -> Self {
		Self { inner }
	}
}

impl cmp::PartialEq for SharedSecret {
	fn eq(&self, other: &SharedSecret) -> bool {
		self.as_slice() == other.as_slice()
	}
}

impl cmp::Eq for SharedSecret {}
