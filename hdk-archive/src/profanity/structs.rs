use serde::{Deserialize, Serialize};

fn default_version() -> u32 {
    4
}

fn default_flags() -> u32 {
    3
}

/// Blacklisted word entry in the profanity dictionary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DictionaryItem {
    /// The blacklisted word string (UTF-8)
    pub word: String,
    /// Bitflags (bit 0x02 = has whitelist entries)
    pub flags: u8,
    /// Whitelist exception words (words containing this profanity that are allowed)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub whitelist: Vec<String>,
}

/// Character conversion rule (e.g. accented uppercase to lowercase ASCII).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvertItem {
    pub from: u32,
    pub to: u32,
}

/// Forward character substitution rule for leetspeak / homoglyph normalization.
///
/// Maps a plain character to a list of possible obfuscated strings (e.g. 'a' -> ["4", "@", "ª", "Æ", "æ"], 'u' -> ["(_)", "|_|"]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharSubEntry {
    /// Target plain character (e.g. 0x0061 for 'a')
    pub target: u16,
    /// Obfuscated substitution variants
    pub substitutions: Vec<String>,
}

/// Reverse character substitution rule.
///
/// Maps an obfuscated character to a list of candidate plain characters (e.g. '!' -> ['i', 'l'], '$' -> ['s'], '1' -> ['b', 'i', 'l']).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevCharSubEntry {
    /// Obfuscated symbol (e.g. 0x0021 for '!')
    pub symbol: u16,
    /// Plain character candidates
    pub candidates: Vec<u16>,
}

/// Complete PlayStation Home Profanity Dictionary representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfanityDictionary {
    /// Format version (default: 4)
    #[serde(default = "default_version")]
    pub version: u32,
    /// Format flags (bit 0: CharSub, bit 1: RevCharSub)
    #[serde(default = "default_flags")]
    pub flags: u32,
    /// List of blacklisted dictionary items with optional whitelists
    pub dictionary_items: Vec<DictionaryItem>,
    /// Character conversion table
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub convert_items: Vec<ConvertItem>,
    /// Custom punctuation codepoints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_punctuation: Vec<u32>,
    /// Forward character substitution rules (e.g. 'a' -> '@', '4')
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub char_substitutions: Vec<CharSubEntry>,
    /// Reverse character substitution rules (e.g. '!' -> 'i', 'l')
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rev_char_substitutions: Vec<RevCharSubEntry>,
}

impl Default for ProfanityDictionary {
    fn default() -> Self {
        Self {
            version: 4,
            flags: 3,
            dictionary_items: Vec::new(),
            convert_items: Vec::new(),
            custom_punctuation: Vec::new(),
            char_substitutions: Vec::new(),
            rev_char_substitutions: Vec::new(),
        }
    }
}
