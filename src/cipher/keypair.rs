use super::{PublicKey, SharedSecret};
#[cfg(feature = "b64")]
use crate::FromBase64Error;

use std::fmt;

use rand::rngs::OsRng;

use x25519_dalek as x;

// EphemeralKeypair

/// A Keypair that can only be used once.
pub struct EphemeralKeypair {
	secret: x::EphemeralSecret,
	public: PublicKey
}

impl EphemeralKeypair {
	pub fn generate() -> Self {
		let secret = x::EphemeralSecret::new(&mut OsRng);
		let public = PublicKey::from_ephemeral_secret(&secret);

		Self { secret, public }
	}

	// maybe return a Key??
	pub fn diffie_hellman(self, public_key: &PublicKey) -> SharedSecret {
		self.secret.diffie_hellman(public_key.inner()).into()
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}
}

impl fmt::Debug for EphemeralKeypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "EphemeralKeypair {{ {:?} }}", self.public)
	}
}

// Keypair

/// A Keypair that can be used multiple times.
#[derive(Clone)]
pub struct Keypair {
	pub secret: x::StaticSecret,
	pub public: PublicKey
}

impl Keypair {
	pub fn generate() -> Self {
		x::StaticSecret::new(&mut OsRng).into()
	}

	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		x::StaticSecret::from(bytes).into()
	}

	pub fn from_slice_unchecked(slice: &[u8]) -> Self {
		let mut bytes = [0u8; 32];
		bytes.copy_from_slice(slice);
		bytes.into()
	}

	#[cfg(feature = "b64")]
	pub fn try_from_slice(slice: &[u8]) -> Result<Self, FromBase64Error> {
		if slice.len() != 32 {
			return Err(FromBase64Error::LengthNot32Bytes);
		}
		Ok(Self::from_slice_unchecked(slice))
	}

	pub fn to_bytes(&self) -> [u8; 32] {
		self.secret.to_bytes()
	}

	#[cfg(feature = "b64")]
	pub fn from_b64<T: AsRef<[u8]>>(input: T) -> Result<Self, FromBase64Error> {
		let b = base64::decode_config(input, base64::URL_SAFE_NO_PAD)?;
		Ok(Self::try_from_slice(&b)?)
	}

	#[cfg(feature = "b64")]
	pub fn to_b64(&self) -> String {
		base64::encode_config(self.to_bytes().as_ref(), base64::URL_SAFE_NO_PAD)
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}

	pub fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
		self.secret.diffie_hellman(public_key.inner()).into()
	}
}

impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "StaticKeypair {{ {:?} }}", self.public)
	}
}

impl From<x::StaticSecret> for Keypair {
	fn from(secret: x::StaticSecret) -> Self {
		let public = PublicKey::from_static_secret(&secret);

		Self { secret, public }
	}
}

impl From<[u8; 32]> for Keypair {
	fn from(bytes: [u8; 32]) -> Self {
		Self::from_bytes(bytes)
	}
}
