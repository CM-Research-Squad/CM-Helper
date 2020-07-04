use hex::{FromHex, ToHex};
use serde::{Serializer, Deserialize, Deserializer};

/// Serializes `buffer` to a lowercase hex string.
///
/// Usage: `#[serde(serialize_with = "ser_hex")]`
pub fn ser_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
  where T: AsRef<[u8]>,
        S: Serializer
{
  serializer.serialize_str(&buffer.encode_hex::<String>())
}

/// Deserializes a lowercase hex string to a `Vec<u8>`.
///
/// Usage: `#[serde(deserialize_with = "deser_hex")]`
pub fn deser_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
  where D: Deserializer<'de>
{
  use serde::de::Error;
  String::deserialize(deserializer)
    .and_then(|string| Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string())))
}

/// Deserializes a base64 string to a `Vec<u8>`.
///
/// Usage: `#[serde(deserialize_with = "deser_base64")]`
pub fn deser_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de>
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(|err| Error::custom(err.to_string())))
}
