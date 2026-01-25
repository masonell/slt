use serde::{Deserialize, Deserializer, Serializer, de};

pub fn serialize<const N: usize, S>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

pub fn deserialize<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let decoded = hex::decode(s).map_err(de::Error::custom)?;
    if decoded.len() != N {
        return Err(de::Error::custom(format!(
            "expected {N} bytes, got {}",
            decoded.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}
