pub mod builder;
pub mod structs;

#[cfg(test)]
mod tests;

pub use builder::ProfanityError;
pub use structs::{CharSubEntry, ConvertItem, DictionaryItem, ProfanityDictionary, RevCharSubEntry};

use std::fs;
use std::path::Path;

impl ProfanityDictionary {
    /// Parse a `ProfanityDictionary` from encrypted binary bytes using the default key.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfanityError> {
        builder::parse_profanity_binary(data, None)
    }

    /// Parse a `ProfanityDictionary` from encrypted binary bytes using a custom 128-bit key.
    pub fn from_bytes_with_key(data: &[u8], key: [u32; 4]) -> Result<Self, ProfanityError> {
        builder::parse_profanity_binary(data, Some(key))
    }

    /// Read and parse a `ProfanityDictionary` from a `.bin` file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ProfanityError> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Serialize this dictionary to encrypted binary bytes using the default key.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProfanityError> {
        builder::build_profanity_binary(self, None)
    }

    /// Serialize this dictionary to encrypted binary bytes using a custom 128-bit key.
    pub fn to_bytes_with_key(&self, key: [u32; 4]) -> Result<Vec<u8>, ProfanityError> {
        builder::build_profanity_binary(self, Some(key))
    }

    /// Serialize and write this dictionary to a `.bin` file on disk.
    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<(), ProfanityError> {
        let bytes = self.to_bytes()?;
        fs::write(path, bytes)?;
        Ok(())
    }

    /// Export the dictionary to a pretty-printed JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Import a dictionary from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}
