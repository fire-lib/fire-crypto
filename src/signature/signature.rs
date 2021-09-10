#[cfg(feature = "b64")]
use crate::FromBase64Error;

use std::convert::TryInto;

use ed25519_dalek as ed;

#[cfg(feature = "b64")]
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
	inner: ed::Signature
}

impl Signature {
	pub const LEN: usize = 64;

	pub(crate) fn from_sign(inner: ed::Signature) -> Self {
		Self { inner }
	}

	pub fn from_bytes(bytes: [u8; 64]) -> Self {
		Self::from_sign(ed::Signature::new(bytes))
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
		self.inner.to_bytes()
	}

	pub fn as_slice(&self) -> &[u8] {
		self.inner.as_ref()
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
		base64::encode_config(self.to_bytes().as_ref(), base64::URL_SAFE_NO_PAD)
	}

	pub(crate) fn inner(&self) -> &ed::Signature {
		&self.inner
	}
}

impl From<[u8; 64]> for Signature {
	fn from(bytes: [u8; 64]) -> Self {
		Self::from_bytes(bytes)
	}
}

// DISPLAY
#[cfg(feature = "b64")]
impl fmt::Display for Signature {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.to_b64())
	}
}

#[cfg(all(feature = "serde", feature = "b64"))]
impl_serde!(Signature, 86);