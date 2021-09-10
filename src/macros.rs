#[cfg(all(feature = "serde", feature = "b64"))]
macro_rules! impl_serde {
	($struct:ident, $len:literal) => (
		impl _serde::Serialize for $struct {
			fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
			where S: _serde::ser::Serializer {
				serializer.serialize_str(&self.to_b64())
			}
		}

		impl<'de> _serde::Deserialize<'de> for $struct {
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
			where D: _serde::de::Deserializer<'de> {


				struct CustomVisitor;

				impl<'de> _serde::de::Visitor<'de> for CustomVisitor {
					type Value = $struct;

					fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
						f.write_str(concat!("a string with ", $len, " characters"))
					}

					fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
					where E: _serde::de::Error {
						if v.len() == $len {
							$struct::from_b64(v)
								.map_err(|e| E::custom(format!("DecodeError {:?}", e)))
						} else {
							Err(E::custom(concat!("string isn't ", $len, " characters long")))
						}
					}
				}

				deserializer.deserialize_str(CustomVisitor)
			}
		}

	)
}
