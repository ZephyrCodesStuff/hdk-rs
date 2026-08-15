use super::*;
use std::fs;
use std::path::Path;

#[test]
fn test_profanity_dict_roundtrip_synthetic() {
    let dict = ProfanityDictionary {
        version: 4,
        flags: 3,
        dictionary_items: vec![
            DictionaryItem {
                word: "badword".to_string(),
                flags: 0x1F,
                whitelist: vec!["notbadword".to_string(), "badwordexception".to_string()],
            },
            DictionaryItem {
                word: "simple".to_string(),
                flags: 0x01,
                whitelist: vec![],
            },
        ],
        convert_items: vec![
            ConvertItem { from: 0xC0, to: 0x61 },
            ConvertItem { from: 0xC1, to: 0x61 },
        ],
        custom_punctuation: vec![0xA7, 0xA8, 0xB0],
        char_substitutions: vec![
            CharSubEntry {
                target: 'a' as u16,
                substitutions: vec!["4".to_string(), "@".to_string()],
            },
            CharSubEntry {
                target: 'u' as u16,
                substitutions: vec!["(_)".to_string(), "|_|".to_string()],
            },
        ],
        rev_char_substitutions: vec![
            RevCharSubEntry {
                symbol: '!' as u16,
                candidates: vec!['i' as u16, 'l' as u16],
            },
            RevCharSubEntry {
                symbol: '$' as u16,
                candidates: vec!['s' as u16],
            },
        ],
    };

    // 1. Test binary serialization & parsing roundtrip
    let bin_bytes = dict.to_bytes().expect("Failed to serialize dictionary");
    assert!(!bin_bytes.is_empty());
    assert_eq!(bin_bytes.len() % 4, 0);

    let parsed_dict = ProfanityDictionary::from_bytes(&bin_bytes)
        .expect("Failed to parse serialized dictionary");
    assert_eq!(parsed_dict, dict);

    // 2. Test JSON roundtrip
    let json_str = dict.to_json().expect("Failed to serialize to JSON");
    let from_json: ProfanityDictionary =
        ProfanityDictionary::from_json(&json_str).expect("Failed to deserialize from JSON");
    assert_eq!(from_json, dict);
}

#[test]
fn test_real_profanity_dictionary_en_us() {
    let test_path = Path::new(r"..\ProfanityDictionary_en-US.bin");
    let path = if test_path.exists() {
        test_path
    } else {
        Path::new(r"C:\Users\zeph\Downloads\porting\ProfanityDictionary_en-US.bin")
    };

    if !path.exists() {
        eprintln!("Warning: Skipping test_real_profanity_dictionary_en_us as file not found");
        return;
    }

    let raw_bytes = fs::read(path).expect("Failed to read ProfanityDictionary_en-US.bin");
    let dict = ProfanityDictionary::from_bytes(&raw_bytes)
        .expect("Failed to parse ProfanityDictionary_en-US.bin");

    // Validate header and counts
    assert_eq!(dict.version, 4);
    assert_eq!(dict.flags, 3);
    assert_eq!(dict.dictionary_items.len(), 525);
    assert_eq!(dict.convert_items.len(), 138);
    assert_eq!(dict.custom_punctuation.len(), 106);
    assert_eq!(dict.char_substitutions.len(), 17);
    assert_eq!(dict.rev_char_substitutions.len(), 37);

    // Validate specific entries
    let anal_item = dict.dictionary_items.iter().find(|i| i.word == "anal").unwrap();
    assert!(anal_item.whitelist.contains(&"canal".to_string()));
    assert!(anal_item.whitelist.contains(&"analog".to_string()));

    let ass_item = dict.dictionary_items.iter().find(|i| i.word == "ass").unwrap();
    assert!(ass_item.whitelist.contains(&"assume".to_string()));
    assert!(ass_item.whitelist.contains(&"assert".to_string()));

    // Test JSON export & import
    let json_str = dict.to_json().expect("Failed to export to JSON");
    let from_json = ProfanityDictionary::from_json(&json_str)
        .expect("Failed to import from JSON");
    assert_eq!(from_json, dict);

    // Test Repacking to binary
    let repacked_bytes = dict.to_bytes().expect("Failed to repack dictionary to binary");
    assert_eq!(repacked_bytes.len(), raw_bytes.len());

    let repacked_dict = ProfanityDictionary::from_bytes(&repacked_bytes)
        .expect("Failed to parse repacked binary dictionary");
    assert_eq!(repacked_dict, dict);
}
