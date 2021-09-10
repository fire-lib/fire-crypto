use super::{PublicKey, SharedSecret};
#[cfg(feature = "b64")]
use crate::FromBase64Error;

use std::fmt;
use std::convert::TryInto;

use rand::rngs::OsRng;

use x25519_dalek as x;

// EphemeralKeypair

/// A Keypair that can only be used once.
pub struct EphemeralKeypair {
	secret: x::EphemeralSecret,
	public: PublicKey
}

impl EphemeralKeypair {
	pub fn new() -> Self {
		let secret = x::EphemeralSecret::new(&mut OsRng);
		let public = PublicKey::from_ephemeral_secret(&secret);

		Self { secret, public }
	}

	// maybe return a Key??
	pub fn diffie_hellman(self, public_key: &PublicKey) -> SharedSecret {
		let secret = self.secret.diffie_hellman(public_key.inner());
		SharedSecret::from_shared_secret(secret)
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}
}

impl fmt::Debug for EphemeralKeypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("EphemeralKeypair")
			.field("public", &self.public)
			.finish()
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
	pub const LEN: usize = 32;

	fn from_static_secret(secret: x::StaticSecret) -> Self {
		let public = PublicKey::from_static_secret(&secret);

		Self { secret, public }
	}

	pub fn new() -> Self {
		Self::from_static_secret(
			x::StaticSecret::new(&mut OsRng)
		)
	}

	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self::from_static_secret(
			x::StaticSecret::from(bytes)
		)
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
		self.secret.to_bytes()
	}

	// pub fn as_slice(&self) -> &[u8] {
	// 	self.secret.as_ref()
	// }

	#[cfg(feature = "b64")]
	pub fn from_b64<T: AsRef<[u8]>>(input: T) -> Result<Self, FromBase64Error> {
		let b = base64::decode_config(input, base64::URL_SAFE_NO_PAD)?;
		Self::try_from_slice(&b)
			.ok_or(FromBase64Error::LengthNot32Bytes)
	}

	#[cfg(feature = "b64")]
	pub fn to_b64(&self) -> String {
		base64::encode_config(self.to_bytes().as_ref(), base64::URL_SAFE_NO_PAD)
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}

	pub fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
		let secret = self.secret.diffie_hellman(public_key.inner());
		SharedSecret::from_shared_secret(secret)
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair")
			.field("secret", &self.to_b64())
			.field("public", &self.public)
			.finish()
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair")
			.field("secret", &self.to_bytes())
			.field("public", &self.public)
			.finish()
	}
}

// Display
#[cfg(feature = "b64")]
impl fmt::Display for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.to_b64())
	}
}

impl From<[u8; 32]> for Keypair {
	fn from(bytes: [u8; 32]) -> Self {
		Self::from_bytes(bytes)
	}
}

#[cfg(all(feature = "serde", feature = "b64"))]
impl_serde!(Keypair, 43);