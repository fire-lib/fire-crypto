use crate::error::TryFromError;
#[cfg(feature = "b64")]
use crate::error::DecodeError;

use std::fmt;
use std::convert::{TryFrom, TryInto};

use rand::rngs::OsRng;
use rand::RngCore;


/// A random Token
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Token<const S: usize> {
	bytes: [u8; S]
}

impl<const S: usize> Token<S> {

	pub const LEN: usize = S;

	pub const STR_LEN: usize = crate::calculate_b64_len(S);

	/// Creates a new random Token
	pub fn new() -> Self {
		let mut bytes = [0u8; S];

		OsRng.fill_bytes(&mut bytes);

		Self { bytes }
	}

	/// ## Panics
	/// if the slice is not `S` bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; S] {
		self.bytes
	}

}

#[cfg(not(feature = "b64"))]
impl<const S: usize> fmt::Debug for Token<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Token")
			.field(&self.as_ref())
			.finish()
	}
}

#[cfg(feature = "b64")]
impl<const S: usize> fmt::Debug for Token<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Token")
			.field(&self.to_string())
			.finish()
	}
}

#[cfg(feature = "b64")]
impl<const S: usize> fmt::Display for Token<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::with_config(
			self.as_ref(),
			base64::URL_SAFE_NO_PAD
		).fmt(f)
	}
}

impl<const S: usize> From<[u8; S]> for Token<S> {
	fn from(bytes: [u8; S]) -> Self {
		Self { bytes }
	}
}

impl<const S: usize> TryFrom<&[u8]> for Token<S> {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		<[u8; S]>::try_from(v)
			.map_err(TryFromError::from_any)
			.map(Self::from)
	}
}

#[cfg(feature = "b64")]
impl<const S: usize> crate::FromStr for Token<S> {
	type Err = DecodeError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != crate::calculate_b64_len(S) {
			return Err(DecodeError::InvalidLength)
		}

		let mut bytes = [0u8; S];
		base64::decode_config_slice(s, base64::URL_SAFE_NO_PAD, &mut bytes)
			.map_err(DecodeError::inv_bytes)
			.map(|_| Self::from(bytes))
	}
}

impl<const S: usize> AsRef<[u8]> for Token<S> {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

#[cfg(all(feature = "b64", feature = "serde"))]
mod impl_serde {

	use super::*;

	use std::borrow::Cow;
	use std::str::FromStr;

	use _serde::{Serialize, Serializer, Deserialize, Deserializer};
	use _serde::de::Error;

	impl<const SI: usize> Serialize for Token<SI> {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where S: Serializer {
			serializer.collect_str(&self)
		}
	}

	impl<'de, const S: usize> Deserialize<'de> for Token<S> {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where D: Deserializer<'de> {
			let s: Cow<'_, str> = Deserialize::deserialize(deserializer)?;
			Self::from_str(s.as_ref())
				.map_err(D::Error::custom)
		}
	}

}

#[cfg(test)]
mod tests {

	use super::*;

	#[cfg(feature = "b64")]
	use std::str::FromStr;

	#[cfg(feature = "b64")]
	pub fn b64<const S: usize>() {
		let tok = Token::<S>::new();

		let b64 = tok.to_string();
		let tok_2 = Token::<S>::from_str(&b64).unwrap();

		assert_eq!(b64, tok_2.to_string());
	}

	#[cfg(feature = "b64")]
	#[test]
	pub fn test_b64() {
		b64::<1>();
		b64::<2>();
		b64::<3>();
		b64::<13>();
		b64::<24>();
		b64::<200>();
		b64::<213>();
	}

}