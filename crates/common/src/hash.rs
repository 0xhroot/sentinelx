use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashValue(String);

impl HashValue {
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Self(hex::encode(result))
    }

    pub fn from_hex(hex_str: &str) -> crate::Result<Self> {
        if hex_str.len() != 64 {
            return Err(crate::Error::Serialization(
                "Invalid SHA256 hex length".to_string(),
            ));
        }
        Ok(Self(hex_str.to_lowercase()))
    }

    pub fn as_hex(&self) -> &str {
        &self.0
    }

    pub fn matches(&self, other: &HashValue) -> bool {
        self.0 == other.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
