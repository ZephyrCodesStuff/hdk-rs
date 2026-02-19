use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AfsHash(pub i32);

impl AfsHash {
    /// Returns `true` if the given string could be a valid uppercase hex AfsHash.
    ///
    /// This does not verify that the string is an actual AfsHash: only that it matches the expected format.
    pub fn is_valid_hash_str(s: &str) -> bool {
        s.len() == 8
            && s.chars()
                .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_uppercase() || c.is_ascii_digit()))
    }

    pub fn new_from_str(s: &str) -> Self {
        Self(afs_hash(s.chars()))
    }

    /// Create an AfsHash from a file path.
    pub fn new_from_path(path: &Path) -> Self {
        let s = path.to_str().unwrap_or_default();

        Self(afs_hash(s.chars()))
    }
}

impl core::fmt::Display for AfsHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.0.to_be_bytes();
        write!(
            f,
            "{:02X}{:02X}{:02X}{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

pub fn afs_hash(data: std::str::Chars) -> i32 {
    let mut hash: i32 = 0;

    for mut c in data {
        if c == '\\' {
            c = '/';
        }
        c = c.to_lowercase().next().unwrap();

        hash = hash.overflowing_mul(0x25).0; // 37
        hash += c as i32;
    }

    hash
}
