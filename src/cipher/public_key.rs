use crate::error::TryFromError;
#[cfg(feature = "b64")]
use crate::error::DecodeError;

use std::{fmt, cmp};
use std::convert::{TryFrom, TryInto};
use std::hash::{Hash, Hasher};

use x25519_dalek as x;

#[cfg(feature = "b64")]
use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};


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

	/// ## Panics
	/// if the slice is not 32 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; 32] {
		self.as_ref().try_into().unwrap()
	}

	pub fn inner(&self) -> &x::PublicKey {
		&self.inner
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PublicKey")
			.field(&self.as_ref())
			.finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PublicKey")
			.field(&self.to_string())
			.finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Display for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::new(
			self.as_ref(),
			&URL_SAFE_NO_PAD
		).fmt(f)
	}
}

impl cmp::PartialEq for PublicKey {
	fn eq(&self, other: &PublicKey) -> bool {
		self.as_ref() == other.as_ref()
	}
}

impl cmp::Eq for PublicKey {}

impl Hash for PublicKey {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.as_ref().hash(state)
	}
}

impl From<[u8; 32]> for PublicKey {
	fn from(bytes: [u8; 32]) -> Self {
		Self {
			inner: bytes.into()
		}
	}
}

impl TryFrom<&[u8]> for PublicKey {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		<[u8; 32]>::try_from(v)
			.map_err(TryFromError::from_any)
			.map(Self::from)
	}
}

#[cfg(feature = "b64")]
impl crate::FromStr for PublicKey {
	type Err = DecodeError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != crate::calculate_b64_len(Self::LEN) {
			return Err(DecodeError::InvalidLength)
		}

		let mut bytes = [0u8; Self::LEN];
		URL_SAFE_NO_PAD.decode_slice_unchecked(s, &mut bytes)
			.map_err(DecodeError::inv_bytes)
			.and_then(|_| {
				Self::try_from(bytes.as_ref())
					.map_err(DecodeError::inv_bytes)
			})
	}
}

impl AsRef<[u8]> for PublicKey {
	fn as_ref(&self) -> &[u8] {
		self.inner.as_bytes()
	}
}

#[cfg(all(feature = "b64", feature = "serde"))]
mod impl_serde {

	use super::*;

	use std::borrow::Cow;
	use std::str::FromStr;

	use _serde::{Serialize, Serializer, Deserialize, Deserializer};
	use _serde::de::Error;

	impl Serialize for PublicKey {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where S: Serializer {
			serializer.collect_str(&self)
		}
	}

	impl<'de> Deserialize<'de> for PublicKey {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where D: Deserializer<'de> {
			let s: Cow<'_, str> = Deserialize::deserialize(deserializer)?;
			Self::from_str(s.as_ref())
				.map_err(D::Error::custom)
		}
	}

}