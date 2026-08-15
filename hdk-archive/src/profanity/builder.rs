use byteorder::{BigEndian, ByteOrder};
use hdk_secure::xxtea::{Xxtea, PROFANITY_DICT_KEY};
use std::io::Write;

use super::structs::{CharSubEntry, ConvertItem, DictionaryItem, ProfanityDictionary, RevCharSubEntry};

/// Error type for Profanity dictionary operations.
#[derive(Debug, thiserror::Error)]
pub enum ProfanityError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Buffer too small ({0} bytes)")]
    BufferTooSmall(usize),
    #[error("Invalid dictionary version: {0} (expected 4)")]
    InvalidVersion(u32),
    #[error("Offset out of bounds: 0x{0:X} > buffer size 0x{1:X}")]
    OutOfBounds(usize, usize),
    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Crypto error: {0}")]
    Crypto(&'static str),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serialize forward `CharSubEntry` list into its index table and string pool.
fn serialize_char_subs(entries: &[CharSubEntry]) -> (Vec<u8>, Vec<u8>) {
    let mut table = Vec::with_capacity(entries.len() * 4);
    let mut pool = Vec::new();

    for entry in entries {
        let pool_offset = pool.len() as u16;
        let mut entry_table_bytes = [0u8; 4];
        BigEndian::write_u16(&mut entry_table_bytes[0..2], entry.target);
        BigEndian::write_u16(&mut entry_table_bytes[2..4], pool_offset);
        table.extend_from_slice(&entry_table_bytes);

        // Pool format:
        // u8 num_variants
        // for each variant:
        //   u8 char_count
        //   u16 utf16_chars[char_count]
        pool.push(entry.substitutions.len() as u8);
        for sub in &entry.substitutions {
            let utf16_units: Vec<u16> = sub.encode_utf16().collect();
            pool.push(utf16_units.len() as u8);
            for unit in utf16_units {
                let mut buf = [0u8; 2];
                BigEndian::write_u16(&mut buf, unit);
                pool.extend_from_slice(&buf);
            }
        }
    }

    (table, pool)
}

/// Parse forward `CharSubEntry` list from its index table and string pool.
fn parse_char_subs(
    buffer: &[u8],
    count: usize,
    table_offset: usize,
    pool_offset: usize,
) -> Result<Vec<CharSubEntry>, ProfanityError> {
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let entry_pos = table_offset + i * 4;
        if entry_pos + 4 > buffer.len() {
            return Err(ProfanityError::OutOfBounds(entry_pos + 4, buffer.len()));
        }
        let target = BigEndian::read_u16(&buffer[entry_pos..entry_pos + 2]);
        let p_offset = BigEndian::read_u16(&buffer[entry_pos + 2..entry_pos + 4]) as usize;

        let mut current_pool_pos = pool_offset + p_offset;
        if current_pool_pos >= buffer.len() {
            return Err(ProfanityError::OutOfBounds(current_pool_pos, buffer.len()));
        }

        let num_variants = buffer[current_pool_pos] as usize;
        current_pool_pos += 1;

        let mut substitutions = Vec::with_capacity(num_variants);
        for _ in 0..num_variants {
            if current_pool_pos >= buffer.len() {
                return Err(ProfanityError::OutOfBounds(current_pool_pos, buffer.len()));
            }
            let char_count = buffer[current_pool_pos] as usize;
            current_pool_pos += 1;

            if current_pool_pos + char_count * 2 > buffer.len() {
                return Err(ProfanityError::OutOfBounds(
                    current_pool_pos + char_count * 2,
                    buffer.len(),
                ));
            }

            let mut units = Vec::with_capacity(char_count);
            for _ in 0..char_count {
                units.push(BigEndian::read_u16(&buffer[current_pool_pos..current_pool_pos + 2]));
                current_pool_pos += 2;
            }
            let sub_str = String::from_utf16_lossy(&units);
            substitutions.push(sub_str);
        }

        entries.push(CharSubEntry {
            target,
            substitutions,
        });
    }

    Ok(entries)
}

/// Serialize reverse `RevCharSubEntry` list into its index table and candidate pool.
fn serialize_rev_char_subs(entries: &[RevCharSubEntry]) -> (Vec<u8>, Vec<u8>) {
    let mut table = Vec::with_capacity(entries.len() * 4);
    let mut pool = Vec::new();

    for entry in entries {
        let pool_offset = pool.len() as u16;
        let mut entry_table_bytes = [0u8; 4];
        BigEndian::write_u16(&mut entry_table_bytes[0..2], entry.symbol);
        BigEndian::write_u16(&mut entry_table_bytes[2..4], pool_offset);
        table.extend_from_slice(&entry_table_bytes);

        // Pool format:
        // u8 candidate_count
        // u16 candidates[candidate_count]
        pool.push(entry.candidates.len() as u8);
        for &cand in &entry.candidates {
            let mut buf = [0u8; 2];
            BigEndian::write_u16(&mut buf, cand);
            pool.extend_from_slice(&buf);
        }
    }

    (table, pool)
}

/// Parse reverse `RevCharSubEntry` list from its index table and candidate pool.
fn parse_rev_char_subs(
    buffer: &[u8],
    count: usize,
    table_offset: usize,
    pool_offset: usize,
) -> Result<Vec<RevCharSubEntry>, ProfanityError> {
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let entry_pos = table_offset + i * 4;
        if entry_pos + 4 > buffer.len() {
            return Err(ProfanityError::OutOfBounds(entry_pos + 4, buffer.len()));
        }
        let symbol = BigEndian::read_u16(&buffer[entry_pos..entry_pos + 2]);
        let p_offset = BigEndian::read_u16(&buffer[entry_pos + 2..entry_pos + 4]) as usize;

        let mut current_pool_pos = pool_offset + p_offset;
        if current_pool_pos >= buffer.len() {
            return Err(ProfanityError::OutOfBounds(current_pool_pos, buffer.len()));
        }

        let candidate_count = buffer[current_pool_pos] as usize;
        current_pool_pos += 1;

        if current_pool_pos + candidate_count * 2 > buffer.len() {
            return Err(ProfanityError::OutOfBounds(
                current_pool_pos + candidate_count * 2,
                buffer.len(),
            ));
        }

        let mut candidates = Vec::with_capacity(candidate_count);
        for _ in 0..candidate_count {
            let cand = BigEndian::read_u16(&buffer[current_pool_pos..current_pool_pos + 2]);
            current_pool_pos += 2;
            candidates.push(cand);
        }

        entries.push(RevCharSubEntry { symbol, candidates });
    }

    Ok(entries)
}

/// Builds and serializes a `ProfanityDictionary` into binary bytes (swapped & XXTEA encrypted).
pub fn build_profanity_binary(
    dict: &ProfanityDictionary,
    key: Option<[u32; 4]>,
) -> Result<Vec<u8>, ProfanityError> {
    let key = key.unwrap_or(PROFANITY_DICT_KEY);

    // 1. Build Dictionary Items data block and record relative offsets
    let mut dict_items_data = Vec::new();
    let mut dict_item_offsets = Vec::with_capacity(dict.dictionary_items.len());

    for item in &dict.dictionary_items {
        // Offset is relative to the start of the whole file buffer (header = 56 bytes)
        let item_offset = 56 + dict_items_data.len();
        dict_item_offsets.push(item_offset as u32);

        let has_whitelist = !item.whitelist.is_empty();
        let flags = if has_whitelist {
            item.flags | 0x02
        } else {
            item.flags & !0x02
        };

        dict_items_data.push(flags);
        if has_whitelist {
            dict_items_data.push(item.whitelist.len() as u8);
            dict_items_data.push(item.word.len() as u8);
            dict_items_data.extend_from_slice(item.word.as_bytes());
            for wl in &item.whitelist {
                dict_items_data.push(wl.len() as u8);
                dict_items_data.extend_from_slice(wl.as_bytes());
            }
        } else {
            dict_items_data.push(item.word.len() as u8);
            dict_items_data.extend_from_slice(item.word.as_bytes());
        }
    }

    // 2. Dictionary item offsets table
    let dictionary_item_list_offset = 56 + dict_items_data.len();
    let mut dict_offsets_table = Vec::with_capacity(dict_item_offsets.len() * 4);
    for off in dict_item_offsets {
        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf, off);
        dict_offsets_table.extend_from_slice(&buf);
    }

    // 3. Convert Items
    let convert_item_list_offset = dictionary_item_list_offset + dict_offsets_table.len();
    let mut convert_table = Vec::with_capacity(dict.convert_items.len() * 8);
    for item in &dict.convert_items {
        let mut buf = [0u8; 8];
        BigEndian::write_u32(&mut buf[0..4], item.from);
        BigEndian::write_u32(&mut buf[4..8], item.to);
        convert_table.extend_from_slice(&buf);
    }

    // 4. Custom Punctuation
    let custom_punct_chars_offset = convert_item_list_offset + convert_table.len();
    let mut punct_table = Vec::with_capacity(dict.custom_punctuation.len() * 4);
    for &punct in &dict.custom_punctuation {
        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf, punct);
        punct_table.extend_from_slice(&buf);
    }

    // 5. Char Substitutions
    let (char_sub_table, char_sub_pool) = serialize_char_subs(&dict.char_substitutions);
    let char_sub_item_list_offset = custom_punct_chars_offset + punct_table.len();
    let char_sub_list_offset = char_sub_item_list_offset + char_sub_table.len();

    // 6. Rev Char Substitutions
    let (rev_char_sub_table, rev_char_sub_pool) = serialize_rev_char_subs(&dict.rev_char_substitutions);
    let rev_char_sub_item_list_offset = char_sub_list_offset + char_sub_pool.len();
    let rev_char_sub_list_offset = rev_char_sub_item_list_offset + rev_char_sub_table.len();

    // Assemble Header (56 bytes)
    let mut header = [0u8; 56];
    BigEndian::write_u32(&mut header[0x00..0x04], dict.version);
    BigEndian::write_u32(&mut header[0x04..0x08], dict.flags);
    BigEndian::write_u32(&mut header[0x08..0x0C], dict.dictionary_items.len() as u32);
    BigEndian::write_u32(&mut header[0x0C..0x10], dictionary_item_list_offset as u32);
    BigEndian::write_u32(&mut header[0x10..0x14], dict.convert_items.len() as u32);
    BigEndian::write_u32(&mut header[0x14..0x18], convert_item_list_offset as u32);
    BigEndian::write_u32(&mut header[0x18..0x1C], dict.custom_punctuation.len() as u32);
    BigEndian::write_u32(&mut header[0x1C..0x20], custom_punct_chars_offset as u32);
    BigEndian::write_u32(&mut header[0x20..0x24], dict.char_substitutions.len() as u32);
    BigEndian::write_u32(&mut header[0x24..0x28], char_sub_item_list_offset as u32);
    BigEndian::write_u32(&mut header[0x28..0x2C], char_sub_list_offset as u32);
    BigEndian::write_u32(&mut header[0x2C..0x30], dict.rev_char_substitutions.len() as u32);
    BigEndian::write_u32(&mut header[0x30..0x34], rev_char_sub_item_list_offset as u32);
    BigEndian::write_u32(&mut header[0x34..0x38], rev_char_sub_list_offset as u32);

    // Concatenate full buffer
    let mut buffer = Vec::new();
    buffer.write_all(&header)?;
    buffer.write_all(&dict_items_data)?;
    buffer.write_all(&dict_offsets_table)?;
    buffer.write_all(&convert_table)?;
    buffer.write_all(&punct_table)?;
    buffer.write_all(&char_sub_table)?;
    buffer.write_all(&char_sub_pool)?;
    buffer.write_all(&rev_char_sub_table)?;
    buffer.write_all(&rev_char_sub_pool)?;

    // Pad to 4-byte boundary if needed
    while buffer.len() % 4 != 0 {
        buffer.push(0);
    }

    // Convert buffer to 32-bit big-endian words
    let num_words = buffer.len() / 4;
    let mut words = vec![0u32; num_words];
    for (i, chunk) in buffer.as_chunks::<4>().0.iter().enumerate() {
        words[i] = BigEndian::read_u32(chunk);
    }

    // Encrypt in-place using PS3 pipeline (endian swap then XXTEA encrypt)
    let cipher = Xxtea::new_from_words(key);
    cipher.encrypt_ps3_words(&mut words);

    // Write encrypted words back to big-endian byte stream
    let mut encrypted_bytes = vec![0u8; words.len() * 4];
    for (i, &w) in words.iter().enumerate() {
        BigEndian::write_u32(&mut encrypted_bytes[i * 4..(i + 1) * 4], w);
    }

    Ok(encrypted_bytes)
}

/// Parses a binary buffer (XXTEA encrypted & swapped) into a `ProfanityDictionary`.
pub fn parse_profanity_binary(
    raw_data: &[u8],
    key: Option<[u32; 4]>,
) -> Result<ProfanityDictionary, ProfanityError> {
    if raw_data.len() < 56 || !raw_data.len().is_multiple_of(4) {
        return Err(ProfanityError::BufferTooSmall(raw_data.len()));
    }

    let key = key.unwrap_or(PROFANITY_DICT_KEY);

    // Read words as Big-Endian
    let num_words = raw_data.len() / 4;
    let mut words = vec![0u32; num_words];
    for (i, chunk) in raw_data.as_chunks::<4>().0.iter().enumerate() {
        words[i] = BigEndian::read_u32(chunk);
    }

    // Decrypt in-place using PS3 pipeline (XXTEA decrypt then endian swap)
    let cipher = Xxtea::new_from_words(key);
    cipher.decrypt_ps3_words(&mut words);

    // Convert decrypted words back to Big-Endian bytes for structure parsing
    let mut buffer = vec![0u8; words.len() * 4];
    for (i, &w) in words.iter().enumerate() {
        BigEndian::write_u32(&mut buffer[i * 4..(i + 1) * 4], w);
    }

    // Parse Header
    let version = BigEndian::read_u32(&buffer[0x00..0x04]);
    if version != 4 {
        return Err(ProfanityError::InvalidVersion(version));
    }
    let flags = BigEndian::read_u32(&buffer[0x04..0x08]);
    let num_dictionary_items = BigEndian::read_u32(&buffer[0x08..0x0C]) as usize;
    let dictionary_item_list_offset = BigEndian::read_u32(&buffer[0x0C..0x10]) as usize;
    let num_convert_items = BigEndian::read_u32(&buffer[0x10..0x14]) as usize;
    let convert_item_list_offset = BigEndian::read_u32(&buffer[0x14..0x18]) as usize;
    let num_custom_punct_chars = BigEndian::read_u32(&buffer[0x18..0x1C]) as usize;
    let custom_punct_chars_offset = BigEndian::read_u32(&buffer[0x1C..0x20]) as usize;
    let num_char_sub_items = BigEndian::read_u32(&buffer[0x20..0x24]) as usize;
    let char_sub_item_list_offset = BigEndian::read_u32(&buffer[0x24..0x28]) as usize;
    let char_sub_list_offset = BigEndian::read_u32(&buffer[0x28..0x2C]) as usize;
    let num_rev_char_sub_items = BigEndian::read_u32(&buffer[0x2C..0x30]) as usize;
    let rev_char_sub_item_list_offset = BigEndian::read_u32(&buffer[0x30..0x34]) as usize;
    let rev_char_sub_list_offset = BigEndian::read_u32(&buffer[0x34..0x38]) as usize;

    // 1. Parse Dictionary Items
    let mut dictionary_items = Vec::with_capacity(num_dictionary_items);
    for i in 0..num_dictionary_items {
        let off_pos = dictionary_item_list_offset + i * 4;
        if off_pos + 4 > buffer.len() {
            return Err(ProfanityError::OutOfBounds(off_pos + 4, buffer.len()));
        }
        let item_offset = BigEndian::read_u32(&buffer[off_pos..off_pos + 4]) as usize;
        if item_offset >= buffer.len() {
            return Err(ProfanityError::OutOfBounds(item_offset, buffer.len()));
        }

        let item_flags = buffer[item_offset];
        let has_whitelist = (item_flags & 0x02) != 0;

        let (word, whitelist) = if has_whitelist {
            let num_wl = buffer[item_offset + 1] as usize;
            let word_len = buffer[item_offset + 2] as usize;
            let word_start = item_offset + 3;
            let word_end = word_start + word_len;
            if word_end > buffer.len() {
                return Err(ProfanityError::OutOfBounds(word_end, buffer.len()));
            }
            let word = String::from_utf8(buffer[word_start..word_end].to_vec())?;

            let mut wl_list = Vec::with_capacity(num_wl);
            let mut cur = word_end;
            for _ in 0..num_wl {
                if cur >= buffer.len() {
                    return Err(ProfanityError::OutOfBounds(cur, buffer.len()));
                }
                let wl_len = buffer[cur] as usize;
                cur += 1;
                if cur + wl_len > buffer.len() {
                    return Err(ProfanityError::OutOfBounds(cur + wl_len, buffer.len()));
                }
                let wl_str = String::from_utf8(buffer[cur..cur + wl_len].to_vec())?;
                cur += wl_len;
                wl_list.push(wl_str);
            }
            (word, wl_list)
        } else {
            let word_len = buffer[item_offset + 1] as usize;
            let word_start = item_offset + 2;
            let word_end = word_start + word_len;
            if word_end > buffer.len() {
                return Err(ProfanityError::OutOfBounds(word_end, buffer.len()));
            }
            let word = String::from_utf8(buffer[word_start..word_end].to_vec())?;
            (word, Vec::new())
        };

        dictionary_items.push(DictionaryItem {
            word,
            flags: item_flags,
            whitelist,
        });
    }

    // 2. Parse Convert Items
    let mut convert_items = Vec::with_capacity(num_convert_items);
    for i in 0..num_convert_items {
        let pos = convert_item_list_offset + i * 8;
        if pos + 8 > buffer.len() {
            return Err(ProfanityError::OutOfBounds(pos + 8, buffer.len()));
        }
        let from = BigEndian::read_u32(&buffer[pos..pos + 4]);
        let to = BigEndian::read_u32(&buffer[pos + 4..pos + 8]);
        convert_items.push(ConvertItem { from, to });
    }

    // 3. Parse Custom Punctuation
    let mut custom_punctuation = Vec::with_capacity(num_custom_punct_chars);
    for i in 0..num_custom_punct_chars {
        let pos = custom_punct_chars_offset + i * 4;
        if pos + 4 > buffer.len() {
            return Err(ProfanityError::OutOfBounds(pos + 4, buffer.len()));
        }
        let punct = BigEndian::read_u32(&buffer[pos..pos + 4]);
        custom_punctuation.push(punct);
    }

    // 4. Parse Char Substitutions
    let char_substitutions = if num_char_sub_items > 0 {
        parse_char_subs(
            &buffer,
            num_char_sub_items,
            char_sub_item_list_offset,
            char_sub_list_offset,
        )?
    } else {
        Vec::new()
    };

    // 5. Parse Rev Char Substitutions
    let rev_char_substitutions = if num_rev_char_sub_items > 0 {
        parse_rev_char_subs(
            &buffer,
            num_rev_char_sub_items,
            rev_char_sub_item_list_offset,
            rev_char_sub_list_offset,
        )?
    } else {
        Vec::new()
    };

    Ok(ProfanityDictionary {
        version,
        flags,
        dictionary_items,
        convert_items,
        custom_punctuation,
        char_substitutions,
        rev_char_substitutions,
    })
}
