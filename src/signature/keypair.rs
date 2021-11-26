use super::{PublicKey, Signature};
use crate::error::TryFromError;
#[cfg(feature = "b64")]
use crate::error::DecodeError;

use std::fmt;
use std::convert::{TryFrom, TryInto};

use rand::rngs::OsRng;

use ed25519_dalek as ed;

pub struct Keypair {
	secret: ed::SecretKey,
	public: PublicKey
}

impl Keypair {
	pub const LEN: usize = 32;

	pub fn new() -> Self {
		Self::from_keypair(ed::Keypair::generate(&mut OsRng))
	}

	pub(crate) fn from_keypair(keypair: ed::Keypair) -> Self {
		Self {
			secret: keypair.secret,
			public: PublicKey::from_raw(keypair.public)
		}
	}

	pub(crate) fn from_secret(secret: ed::SecretKey) -> Self {
		let public = PublicKey::from_raw(ed::PublicKey::from(&secret));
		Self { secret, public }
	}

	/// ## Panics
	/// if the slice is not valid.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; 32] {
		self.secret.to_bytes()
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}

	pub fn sign(&self, msg: impl AsRef<[u8]>) -> Signature {
		let expanded: ed::ExpandedSecretKey = (&self.secret).into();
		let sign = expanded.sign(msg.as_ref(), self.public().inner());
		Signature::from_sign(sign)
	}

	pub fn verify(&self, msg: impl AsRef<[u8]>, signature: &Signature) -> bool {
		self.public.verify(msg, signature)
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair")
			.field("secret", &self.as_ref())
			.field("public", &self.public)
			.finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair")
			.field("secret", &self.to_string())
			.field("public", &self.public)
			.finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Display for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::with_config(
			self.as_ref(),
			base64::URL_SAFE_NO_PAD
		).fmt(f)
	}
}

impl TryFrom<&[u8]> for Keypair {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		ed::SecretKey::from_bytes(v)
			.map_err(TryFromError::from_any)
			.map(Self::from_secret)
	}
}

#[cfg(feature = "b64")]
impl crate::FromStr for Keypair {
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

impl AsRef<[u8]> for Keypair {
	fn as_ref(&self) -> &[u8] {
		self.secret.as_bytes()
	}
}

impl Clone for Keypair {
	fn clone(&self) -> Self {
		self.as_ref().try_into().unwrap()
	}
}

#[cfg(all(feature = "b64", feature = "serde"))]
mod impl_serde {

	use super::*;

	use std::borrow::Cow;
	use std::str::FromStr;

	use _serde::{Serialize, Serializer, Deserialize, Deserializer};
	use _serde::de::Error;

	impl Serialize for Keypair {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where S: Serializer {
			serializer.collect_str(&self)
		}
	}

	impl<'de> Deserialize<'de> for Keypair {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where D: Deserializer<'de> {
			let s: Cow<'_, str> = Deserialize::deserialize(deserializer)?;
			Self::from_str(s.as_ref())
				.map_err(D::Error::custom)
		}
	}

}