use crate::fill_random;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
	inner: [u8; 24]
}

impl Nonce {
	pub const LEN: usize = 24;

	/// Creates a new random Nonce.
	pub fn new() -> Self {
		let mut this = Self { inner: [0u8; 24] };
		this.fill_random();
		this
	}

	/// Fills the nonce with new random bytes.
	pub fn fill_random(&mut self) {
		fill_random(&mut self.inner);
	}

	#[cfg(test)]
	pub fn ones() -> Self {
		Self { inner: [1u8; 24] }
	}

	/// Returns the nonce as a reference.
	pub fn as_ref(&self) -> &[u8; 24] {
		&self.inner
	}

	/// Returns the nonce representation.
	pub(crate) fn into_inner(self) -> [u8; 24] {
		self.inner
	}

	/// Takes the current nonce, replacing it
	/// with a new random one.
	pub fn take(&mut self) -> Self {
		let n = Nonce::new();
		std::mem::replace(self, n)
	}

	/// Creates a nonce from bytes.
	pub fn from_bytes(bytes: [u8; 24]) -> Self {
		Self { inner: bytes }
	}

	/// Creates a nonce from a slice, the slice needs to be
	/// 24 bytes long.
	pub fn from_slice_unchecked(slice: &[u8]) -> Self {
		debug_assert_eq!(slice.len(), 24);
		let mut buf = [0u8; 24];
		buf.copy_from_slice(slice);
		Self { inner: buf }
	}
}
