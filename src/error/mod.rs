
use std::fmt;
use std::error::Error;

/// Either the length or the format of a slice is incorrect
#[derive(Debug, Copy, Clone)]
pub struct TryFromError(());

impl TryFromError {
	pub(crate) fn from_any<T>(_: T) -> Self {
		Self(())
	}
}

impl fmt::Display for TryFromError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(
			"TryFrom<&[u8]> failed: \
			either the length is incorrect or the format"
		)
	}
}

impl Error for TryFromError {}

/// Either the length or the format of a slice is incorrect
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum DecodeError {
	InvalidLength,
	InvalidBytes
}

impl DecodeError {
	#[cfg(feature = "b64")]
	pub(crate) fn inv_bytes<T>(_: T) -> Self {
		Self::InvalidBytes
	}
}

impl fmt::Display for DecodeError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

impl Error for DecodeError {}