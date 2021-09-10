#[cfg(feature = "b64")]
use crate::FromBase64Error;

use std::{fmt, cmp};
use std::convert::TryInto;

use x25519_dalek as x;

#[derive(Clone)]
pub struct PublicKey {
	pub inner: x::PublicKey
}

impl PublicKey {
	pub const LEN: usize = 32;

	pub(crate) fn from_ephemeral_secret(secret: &x::EphemeralSecret) -> Self {
		Self {
			inner: secret.into()
		}
	}

	pub(crate) fn from_static_secret(secret: &x::StaticSecret) -> Self {
		Self {
			inner: secret.into()
		}
	}

	// pub(crate) fn empty_bytes() -> [u8; 32] {
	// 	[0u8; 32]
	// }

	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self {
			inner: bytes.into()
		}
	}

	/// ## Panics
	/// if the slice is not 32 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		Self::from_bytes(slice.try_into().unwrap())
	}

	pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
		slice.try_into().ok()
			.map(Self::from_bytes)
	}

	pub fn to_bytes(&self) -> [u8; 32] {
		self.as_slice().try_into().unwrap()
	}

	pub fn as_slice(&self) -> &[u8] {
		self.inner.as_bytes()
	}

	#[cfg(feature = "b64")]
	pub fn from_b64<T: AsRef<[u8]>>(input: T) -> Result<Self, FromBase64Error> {
		let b = base64::decode_config(input, base64::URL_SAFE_NO_PAD)?;
		Self::try_from_slice(&b)
			.ok_or(FromBase64Error::LengthNot32Bytes)
	}

	#[cfg(feature = "b64")]
	pub fn to_b64(&self) -> String {
		// returns 43 str
		base64::encode_config(self.as_slice(), base64::URL_SAFE_NO_PAD)
	}

	pub fn inner(&self) -> &x::PublicKey {
		&self.inner
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PublicKey")
			.field(&self.to_b64())
			.finish()
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PublicKey")
			.field(&self.as_slice())
			.finish()
	}
}

impl From<[u8; 32]> for PublicKey {
	fn from(bytes: [u8; 32]) -> Self {
		Self::from_bytes(bytes)
	}
}

impl cmp::PartialEq for PublicKey {
	fn eq(&self, other: &PublicKey) -> bool {
		self.as_slice() == other.as_slice()
	}
}

impl cmp::Eq for PublicKey {}

// Display
#[cfg(feature = "b64")]
impl fmt::Display for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.to_b64())
	}
}

#[cfg(all(feature = "serde", feature = "b64"))]
impl_serde!(PublicKey, 43);
