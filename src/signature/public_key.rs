#[cfg(feature = "b64")]
use crate::FromBase64Error;
use super::Signature;

use ed25519_dalek as ed;

#[cfg(feature = "b64")]
use std::fmt;

#[cfg(all(feature = "serde", feature = "b64"))]
use _serde::{
	de::{self, Deserialize, Deserializer, Visitor},
	ser::{Serialize, Serializer}
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
	inner: ed::PublicKey
}

impl PublicKey {
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		ed::PublicKey::from_bytes(&bytes)
		.unwrap()
		.into()
	}

	pub fn from_slice_unchecked(slice: &[u8]) -> Self {
		ed::PublicKey::from_bytes(slice)
			.expect("could not get publickey from slice")
			.into()
	}

	#[cfg(feature = "b64")]
	pub fn try_from_slice(slice: &[u8]) -> Result<Self, FromBase64Error> {
		if slice.len() != 32 {
			return Err(FromBase64Error::LengthNot32Bytes);
		}
		Ok(Self::from_slice_unchecked(slice))
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
			.map_err(Into::into)
	}

	#[cfg(feature = "b64")]
	pub fn to_b64(&self) -> String {
		// returns 43 str
		base64::encode_config(self.as_slice(), base64::URL_SAFE_NO_PAD)
	}

	pub fn inner(&self) -> &ed::PublicKey {
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

// SERIALIZE
#[cfg(all(feature = "serde", feature = "b64"))]
impl Serialize for PublicKey {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where S: Serializer {
		serializer.serialize_str(&self.to_b64())
	}
}

#[cfg(all(feature = "serde", feature = "b64"))]
struct PublicKeyVisitor;

#[cfg(all(feature = "serde", feature = "b64"))]
impl<'de> Visitor<'de> for PublicKeyVisitor {
	type Value = PublicKey;

	fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str("an string with 43 characters")
	}

	fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
	where E: de::Error {
		if v.len() == 43 {
			PublicKey::from_b64(v)
				.map_err(|e| E::custom(format!("DecodeError {:?}", e)))
		} else {
			Err(E::custom("string isn't 43 characters long"))
		}
	}
}

#[cfg(all(feature = "serde", feature = "b64"))]
impl<'de> Deserialize<'de> for PublicKey {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where D: Deserializer<'de> {
		deserializer.deserialize_str(PublicKeyVisitor)
	}
}
