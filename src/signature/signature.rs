use crate::error::TryFromError;
#[cfg(feature = "b64")]
use crate::error::DecodeError;

use std::fmt;
use std::convert::{TryFrom, TryInto};

use ed25519_dalek as ed;

#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
	inner: ed::Signature
}

impl Signature {
	pub const LEN: usize = 64;

	pub(crate) fn from_sign(inner: ed::Signature) -> Self {
		Self { inner }
	}

	/// ## Panics
	/// if the slice is not 64 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; 64] {
		self.inner.to_bytes()
	}

	pub(crate) fn inner(&self) -> &ed::Signature {
		&self.inner
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for Signature {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Signature")
			.field(&self.as_ref())
			.finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for Signature {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Signature")
			.field(&self.to_string())
			.finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Display for Signature {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::with_config(
			self.as_ref(),
			base64::URL_SAFE_NO_PAD
		).fmt(f)
	}
}

impl TryFrom<&[u8]> for Signature {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		ed::Signature::from_bytes(v)
			.map_err(TryFromError::from_any)
			.map(Self::from_sign)
	}
}

#[cfg(feature = "b64")]
impl crate::FromStr for Signature {
	type Err = DecodeError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != crate::calculate_b64_len(Self::LEN) {
			return Err(DecodeError::InvalidLength)
		}

		let mut bytes = [0u8; Self::LEN];
		base64::decode_config_slice(s, base64::URL_SAFE_NO_PAD, &mut bytes)
			.map_err(DecodeError::inv_bytes)
			.and_then(|_| {
				Self::try_from(bytes.as_ref())
					.map_err(DecodeError::inv_bytes)
			})
	}
}

impl AsRef<[u8]> for Signature {
	fn as_ref(&self) -> &[u8] {
		self.inner.as_ref()
	}
}

#[cfg(all(feature = "b64", feature = "serde"))]
mod impl_serde {

	use super::*;

	use std::borrow::Cow;
	use std::str::FromStr;

	use _serde::{Serialize, Serializer, Deserialize, Deserializer};
	use _serde::de::Error;

	impl Serialize for Signature {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where S: Serializer {
			serializer.collect_str(&self)
		}
	}

	impl<'de> Deserialize<'de> for Signature {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where D: Deserializer<'de> {
			let s: Cow<'_, str> = Deserialize::deserialize(deserializer)?;
			Self::from_str(s.as_ref())
				.map_err(D::Error::custom)
		}
	}

}