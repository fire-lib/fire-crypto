use super::{PublicKey, Signature};
#[cfg(feature = "b64")]
use crate::FromBase64Error;

use std::convert::TryInto;

use rand::rngs::OsRng;

use ed25519_dalek as ed;

#[derive(Debug)]
pub struct Keypair {
	secret: ed::SecretKey,
	public: PublicKey
}

impl Keypair {
	pub const LEN: usize = 32;

	pub fn generate() -> Self {
		Self::from_keypair(ed::Keypair::generate(&mut OsRng))
	}

	pub(crate) fn from_keypair(keypair: ed::Keypair) -> Self {
		Self {
			secret: keypair.secret,
			public: keypair.public.into()
		}
	}

	pub(crate) fn from_secret(secret: ed::SecretKey) -> Self {
		let public = ed::PublicKey::from(&secret).into();
		Self { secret, public }
	}

	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self::from_secret(ed::SecretKey::from_bytes(&bytes).unwrap())
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

	pub fn as_slice(&self) -> &[u8] {
		self.secret.as_ref()
	}

	#[cfg(feature = "b64")]
	pub fn from_b64<T: AsRef<[u8]>>(input: T) -> Result<Self, FromBase64Error> {
		let b = base64::decode_config(input, base64::URL_SAFE_NO_PAD)?;
		Self::try_from_slice(&b)
			.ok_or(FromBase64Error::LengthNot32Bytes)
	}

	#[cfg(feature = "b64")]
	pub fn to_b64(&self) -> String {
		base64::encode_config(self.as_slice(), base64::URL_SAFE_NO_PAD)
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}

	pub fn sign(&self, msg: &[u8]) -> Signature {
		let expanded: ed::ExpandedSecretKey = (&self.secret).into();
		let sign = expanded.sign(msg, self.public().inner());
		Signature::from_sign(sign)
	}

	pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
		self.public.verify(msg, signature)
	}
}

impl From<[u8; 32]> for Keypair {
	fn from(bytes: [u8; 32]) -> Self {
		Self::from_bytes(bytes)
	}
}

impl Clone for Keypair {
	fn clone(&self) -> Self {
		Self::from_bytes(self.to_bytes())
	}
}

#[cfg(all(feature = "serde", feature = "b64"))]
impl_serde!(Keypair, 43);