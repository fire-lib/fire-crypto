#[cfg(feature = "b64")]
use crate::FromBase64Error;
use super::Signature;

use ed25519_dalek as ed;

#[cfg(feature = "b64")]
use std::fmt;
use std::convert::TryInto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
	inner: ed::PublicKey
}

impl PublicKey {
	pub const LEN: usize = 32;

	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		ed::PublicKey::from_bytes(&bytes)
		.unwrap()
		.into()
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
		self.inner.to_bytes()
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

	pub(crate) fn inner(&self) -> &ed::PublicKey {
		&self.inner
	}

	pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
		self.inner.verify_strict(msg, signature.inner()).is_ok()
	}
}

impl From<ed::PublicKey> for PublicKey {
	fn from(inner: ed::PublicKey) -> Self {
		Self { inner }
	}
}

impl From<[u8; 32]> for PublicKey {
	fn from(bytes: [u8; 32]) -> Self {
		Self::from_bytes(bytes)
	}
}

// DISPLAY
#[cfg(feature = "b64")]
impl fmt::Display for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.to_b64())
	}
}

#[cfg(all(feature = "serde", feature = "b64"))]
impl_serde!(PublicKey, 43);