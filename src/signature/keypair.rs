#[cfg(feature = "b64")]
use crate::FromBase64Error;
use super::{PublicKey, Signature};

use rand::rngs::OsRng;

use ed25519_dalek as ed;

#[derive(Debug)]
pub struct Keypair {
	secret: ed::SecretKey,
	public: PublicKey
}

impl Keypair {
	pub fn generate() -> Self {
		ed::Keypair::generate(&mut OsRng).into()
	}

	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		ed::SecretKey::from_bytes(&bytes).unwrap().into()
	}

	pub fn from_slice_unchecked(slice: &[u8]) -> Self {
		ed::SecretKey::from_bytes(slice)
			.expect("could not get secretkey from slice")
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
		self.secret.to_bytes()
	}

	#[cfg(feature = "b64")]
	pub fn from_b64<T: AsRef<[u8]>>(input: T) -> Result<Self, FromBase64Error> {
		let b = base64::decode_config(input, base64::URL_SAFE_NO_PAD)?;
		Self::try_from_slice(&b)
			.map_err(Into::into)
	}

	#[cfg(feature = "b64")]
	pub fn to_b64(&self) -> String {
		base64::encode_config(self.to_bytes().as_ref(), base64::URL_SAFE_NO_PAD)
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}

	pub fn sign(&self, msg: &[u8]) -> Signature {
		let expanded: ed::ExpandedSecretKey = (&self.secret).into();
		expanded.sign(msg, self.public().inner()).into()
	}

	pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
		self.public.verify(msg, signature)
	}
}

impl From<ed::Keypair> for Keypair {
	fn from(keypair: ed::Keypair) -> Self {
		Self {
			secret: keypair.secret,
			public: keypair.public.into()
		}
	}
}

impl From<ed::SecretKey> for Keypair {
	fn from(secret: ed::SecretKey) -> Self {
		let public = ed::PublicKey::from(&secret).into();
		Self { secret, public }
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
