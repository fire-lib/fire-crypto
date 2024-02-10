//! Contains structs used for signing and verifying.

mod keypair;
pub use keypair::Keypair;

mod public_key;
pub use public_key::PublicKey;

mod signature;
pub use signature::Signature;

// TESTS

#[cfg(test)]
mod tests {

	use super::*;

	#[cfg(feature = "b64")]
	use std::str::FromStr;

	#[cfg(feature = "b64")]
	#[test]
	pub fn b64() {
		// keypair
		let alice = Keypair::new();

		let b64 = alice.to_string();
		let alice_2 = Keypair::from_str(&b64).unwrap();

		assert_eq!(b64, alice_2.to_string());
	}

	#[test]
	pub fn signature_test() {
		let alice = Keypair::new();

		let msg = b"Hey thats my message";

		let signature = alice.sign(msg);

		assert!(alice.public().verify(msg, &signature));
	}

	#[cfg(feature = "b64")]
	#[test]
	pub fn b64_signature() {
		let alice = Keypair::new();
		let msg = b"Hey thats my message";
		let signature = alice.sign(msg);

		// check b64 signature
		let b64 = signature.to_string();

		let signature_2 = Signature::from_str(&b64).unwrap();

		assert_eq!(signature, signature_2);
	}

	#[cfg(feature = "b64")]
	#[test]
	pub fn static_keypair_and_signature_test() {
		let alice =
			Keypair::from_str("ZMIO9cdDRvhD6QXo9mR94REWV0810FRTXCkoG3mIO8k")
				.unwrap();

		let msg = b"Hey thats my message";

		let signature = alice.sign(msg);
		assert_eq!(signature.to_string(), "f5Yg6kEyXCsJTssIlZY8msoGnIuf3tdGvpJclwArp75pA-5W0FQTj9E6Lz2345P0IekLsuK-mmDkfViPcqf_DA");

		assert!(alice.public().verify(msg, &signature));
	}

	// todo: add test to make sure From<[u8; S]> can not panic
}
