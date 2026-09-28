use crate::types::{EncodingType, StringCandidate};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionConfig {
    pub min_len: usize,
    pub max_len: usize,
    pub start: usize,
    pub end: usize,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            min_len: 4,
            max_len: usize::MAX,
            start: 0,
            end: usize::MAX,
        }
    }
}

/// High-performance extractor optimized for the common case
pub fn extract_strings(data: &[u8], config: &ExtractionConfig) -> Vec<StringCandidate> {
    let mut results = Vec::new();

    // 1. ASCII & UTF-8
    results.extend(extract_utf8_text(data, config));

    // 2-5. UTF-16
    results.extend(extract_utf16(data, config, true, 0)); // LE, alignment 0
    results.extend(extract_utf16(data, config, true, 1)); // LE, alignment 1
    results.extend(extract_utf16(data, config, false, 0)); // BE, alignment 0
    results.extend(extract_utf16(data, config, false, 1)); // BE, alignment 1

    // Sort by offset and deduplicate
    results.sort_by_key(|a| a.offset);
    results.dedup_by(|a, b| a.offset == b.offset && a.raw_bytes == b.raw_bytes);

    results
}
fn extract_utf8_text(data: &[u8], config: &ExtractionConfig) -> Vec<StringCandidate> {
    let mut results = Vec::new();

    let start = config.start.min(data.len());
    let end = config.end.min(data.len());
    if start >= end {
        return results;
    }

    let mut current_idx = start;

    let mut in_string = false;
    let mut str_start = 0;
    let mut str_byte_len = 0;
    let mut str_char_len = 0;
    let mut has_non_ascii = false;

    let emit = |in_string: &mut bool,
                start_offset: usize,
                byte_len: usize,
                char_len: usize,
                has_non_ascii: &mut bool,
                results: &mut Vec<StringCandidate>| {
        if *in_string && char_len >= config.min_len && char_len <= config.max_len {
            let encoding = if *has_non_ascii {
                EncodingType::Utf8
            } else {
                EncodingType::Ascii
            };
            let raw_bytes = data[start_offset..start_offset + byte_len].to_vec();
            results.push(StringCandidate::new(
                start_offset,
                byte_len,
                char_len,
                raw_bytes,
                encoding,
            ));
        }
        *in_string = false;
        *has_non_ascii = false;
    };

    while current_idx < end {
        let remaining = &data[current_idx..end];
        match std::str::from_utf8(remaining) {
            Ok(valid_str) => {
                for c in valid_str.chars() {
                    let c_len = c.len_utf8();
                    if c.is_control() {
                        emit(
                            &mut in_string,
                            str_start,
                            str_byte_len,
                            str_char_len,
                            &mut has_non_ascii,
                            &mut results,
                        );
                    } else {
                        if !in_string {
                            in_string = true;
                            str_start = current_idx;
                            str_byte_len = 0;
                            str_char_len = 0;
                        }
                        if !c.is_ascii() {
                            has_non_ascii = true;
                        }
                        str_byte_len += c_len;
                        str_char_len += 1;
                    }
                    current_idx += c_len;
                }
                break;
            }
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                if valid_up_to > 0 {
                    let valid_str =
                        unsafe { std::str::from_utf8_unchecked(&remaining[..valid_up_to]) };
                    for c in valid_str.chars() {
                        let c_len = c.len_utf8();
                        if c.is_control() {
                            emit(
                                &mut in_string,
                                str_start,
                                str_byte_len,
                                str_char_len,
                                &mut has_non_ascii,
                                &mut results,
                            );
                        } else {
                            if !in_string {
                                in_string = true;
                                str_start = current_idx;
                                str_byte_len = 0;
                                str_char_len = 0;
                            }
                            if !c.is_ascii() {
                                has_non_ascii = true;
                            }
                            str_byte_len += c_len;
                            str_char_len += 1;
                        }
                        current_idx += c_len;
                    }
                }

                emit(
                    &mut in_string,
                    str_start,
                    str_byte_len,
                    str_char_len,
                    &mut has_non_ascii,
                    &mut results,
                );

                // Skip the invalid bytes
                let error_len = e.error_len().unwrap_or(remaining.len() - valid_up_to);
                current_idx += error_len;
            }
        }
    }

    emit(
        &mut in_string,
        str_start,
        str_byte_len,
        str_char_len,
        &mut has_non_ascii,
        &mut results,
    );

    results
}
#[inline]
fn is_unicode_printable(cp: u32) -> bool {
    // Control characters
    if cp < 0x20 {
        return false;
    }
    if (0x7F..=0x9F).contains(&cp) {
        return false;
    }
    true
}

fn extract_utf16(
    data: &[u8],
    config: &ExtractionConfig,
    is_le: bool,
    alignment: usize,
) -> Vec<StringCandidate> {
    let mut results = Vec::new();

    let end = config.end.min(data.len());
    let mut i = alignment;
    while i < config.start {
        i += 2;
    }

    let mut in_string = false;
    let mut start_idx = 0;
    let mut current_bytes = Vec::new();
    let mut char_len = 0;

    let emit = |in_string: &mut bool,
                start: usize,
                bytes: &mut Vec<u8>,
                chars: &mut usize,
                results: &mut Vec<StringCandidate>| {
        if *in_string && *chars >= config.min_len && *chars <= config.max_len {
            let encoding = if is_le {
                EncodingType::Utf16Le
            } else {
                EncodingType::Utf16Be
            };
            results.push(StringCandidate::new(
                start,
                bytes.len(),
                *chars,
                bytes.clone(),
                encoding,
            ));
        }
        *in_string = false;
        bytes.clear();
        *chars = 0;
    };

    while i + 1 < end {
        let cp = if is_le {
            u16::from_le_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], data[i + 1]])
        };

        if (0xD800..=0xDBFF).contains(&cp) {
            // High surrogate
            if i + 3 < end {
                let next_cp = if is_le {
                    u16::from_le_bytes([data[i + 2], data[i + 3]])
                } else {
                    u16::from_be_bytes([data[i + 2], data[i + 3]])
                };
                if (0xDC00..=0xDFFF).contains(&next_cp) {
                    // Valid surrogate pair
                    let scalar =
                        (((cp - 0xD800) as u32) << 10) | (((next_cp - 0xDC00) as u32) + 0x10000);
                    if is_unicode_printable(scalar) {
                        if !in_string {
                            in_string = true;
                            start_idx = i;
                        }
                        current_bytes.extend_from_slice(&data[i..i + 4]);
                        char_len += 1;
                        i += 4;
                        continue;
                    }
                }
            }
            // Invalid surrogate pair or EOF
            emit(
                &mut in_string,
                start_idx,
                &mut current_bytes,
                &mut char_len,
                &mut results,
            );
            i += 2;
        } else if (0xDC00..=0xDFFF).contains(&cp) {
            // Isolated low surrogate
            emit(
                &mut in_string,
                start_idx,
                &mut current_bytes,
                &mut char_len,
                &mut results,
            );
            i += 2;
        } else {
            // BMP character
            if is_unicode_printable(cp as u32) {
                if !in_string {
                    in_string = true;
                    start_idx = i;
                }
                current_bytes.extend_from_slice(&data[i..i + 2]);
                char_len += 1;
            } else {
                emit(
                    &mut in_string,
                    start_idx,
                    &mut current_bytes,
                    &mut char_len,
                    &mut results,
                );
            }
            i += 2;
        }
    }

    emit(
        &mut in_string,
        start_idx,
        &mut current_bytes,
        &mut char_len,
        &mut results,
    );
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate_str(c: &StringCandidate) -> String {
        match c.encoding {
            EncodingType::Ascii | EncodingType::Utf8 => {
                String::from_utf8_lossy(&c.raw_bytes).to_string()
            }
            _ => String::new(),
        }
    }

    #[test]
    fn test_phase3_utf16_correctness() {
        let config = ExtractionConfig {
            min_len: 2,
            max_len: 100,
            start: 0,
            end: usize::MAX,
        };

        // 1. UTF-16LE ASCII subset (align 0)
        let res = extract_utf16(b"a\x00b\x00c\x00d\x00", &config, true, 0);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].encoding, EncodingType::Utf16Le);
        assert_eq!(res[0].char_len, 4);
        assert_eq!(res[0].byte_len, 8);

        // 2. UTF-16BE ASCII subset (align 0)
        let res = extract_utf16(b"\x00a\x00b\x00c\x00d", &config, false, 0);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].encoding, EncodingType::Utf16Be);
        assert_eq!(res[0].char_len, 4);

        // 3. odd byte alignment LE
        let res = extract_utf16(b"\xFFa\x00b\x00c\x00d\x00", &config, true, 1);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].offset, 1);
        assert_eq!(res[0].encoding, EncodingType::Utf16Le);

        // 4. odd byte alignment BE
        let res = extract_utf16(b"\xFF\x00a\x00b\x00c\x00d", &config, false, 1);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].offset, 1);
        assert_eq!(res[0].encoding, EncodingType::Utf16Be);

        // 5. non-ASCII UTF-16 (e.g. U+00E4 'ä' -> LE: E4 00)
        let res = extract_utf16(b"\xE4\x00\xE4\x00", &config, true, 0);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].char_len, 2);

        // 6. valid surrogate pair (U+1F600 😀 -> D83D DE00)
        let res = extract_utf16(b"a\x00\x3D\xD8\x00\xDEb\x00", &config, true, 0);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].char_len, 3); // 'a', 😀, 'b'
        assert_eq!(res[0].byte_len, 8);

        // 7. isolated high surrogate
        let res = extract_utf16(b"a\x00b\x00\x3D\xD8c\x00d\x00", &config, true, 0);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].char_len, 2); // "ab"
        assert_eq!(res[1].char_len, 2); // "cd"

        // 8. isolated low surrogate
        let res = extract_utf16(b"a\x00b\x00\x00\xDEc\x00d\x00", &config, true, 0);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].char_len, 2); // "ab"

        // 9. candidate at EOF
        let res = extract_utf16(b"a\x00b\x00", &config, true, 0);
        assert_eq!(res.len(), 1);

        // 10. candidate exactly at --end
        let config2 = ExtractionConfig {
            min_len: 2,
            max_len: 100,
            start: 0,
            end: 4,
        };
        let res = extract_utf16(b"a\x00b\x00c\x00", &config2, true, 0);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].char_len, 2); // "ab"
    }
    #[test]
    fn test_extract_ascii_strings() {
        let data = b"Hello, World!\x00Some\x00Text";
        let config = ExtractionConfig {
            min_len: 4,
            max_len: usize::MAX,
            start: 0,
            end: usize::MAX,
        };

        let all_strings = extract_strings(data, &config);
        let strings: Vec<_> = all_strings
            .into_iter()
            .filter(|s| s.encoding == EncodingType::Ascii)
            .collect();
        assert_eq!(strings.len(), 3);
        assert_eq!(candidate_str(&strings[0]), "Hello, World!");
        assert_eq!(candidate_str(&strings[1]), "Some");
        assert_eq!(candidate_str(&strings[2]), "Text");
    }

    #[test]
    fn test_extract_utf8_strings() {
        let data = "Hällö, Wörld! Test".as_bytes();
        let config = ExtractionConfig::default();

        let strings = extract_strings(data, &config);
        assert!(!strings.is_empty());
        assert!(candidate_str(&strings[0]).contains("Hällö"));
    }

    #[test]
    fn test_length_filtering() {
        // String 1: "abcd" (char_len 4) -> discarded (min_len=5)
        // String 2: "abcdefgh" (char_len 8) -> emitted
        // String 3: "abc" (char_len 3) -> discarded
        // String 4: "12345678901" (char_len 11) -> discarded (max_len=10), no splitting!
        let data = b"abcd\x00abcdefgh\x00abc\x0012345678901";
        let config = ExtractionConfig {
            min_len: 5,
            max_len: 10,
            start: 0,
            end: usize::MAX,
        };

        let all_strings = extract_strings(data, &config);
        let strings: Vec<_> = all_strings
            .into_iter()
            .filter(|s| s.encoding == EncodingType::Ascii)
            .collect();

        // We should ONLY get "abcdefgh". The "12345678901" string must be dropped, not split.
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].char_len, 8); // "abcdefgh"
        assert_eq!(strings[0].byte_len, 8);
    }

    #[test]
    fn test_range_filtering() {
        let data = b"Start\x00Target\x00End";
        let config = ExtractionConfig {
            min_len: 4,
            max_len: usize::MAX,
            start: 6, // After "Start "
            end: 13,  // Before " End"
        };

        let all_strings = extract_strings(data, &config);
        let strings: Vec<_> = all_strings
            .into_iter()
            .filter(|s| s.encoding == EncodingType::Ascii)
            .collect();
        assert!(!strings.is_empty());
        let contents: Vec<String> = strings.iter().map(candidate_str).collect();
        assert!(contents.iter().any(|c| c.contains("Target")));
    }

    #[test]
    fn test_utf16_le_extraction() {
        // "Hello" in UTF-16 LE
        let hello_utf16le = b"H e l l o ";
        let data = hello_utf16le;

        let config = ExtractionConfig {
            min_len: 2, // 2 bytes = 1 char in UTF-16
            max_len: usize::MAX,
            start: 0,
            end: usize::MAX,
        };

        let strings = extract_strings(data, &config);
        assert!(!strings.is_empty());
        assert!(strings.iter().any(|s| s.encoding == EncodingType::Utf16Le));
    }
}
