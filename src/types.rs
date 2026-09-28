//! Core data types for strx

use serde::{Serialize, Deserialize};
use std::fmt;

/// Supported string encodings for detection and extraction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncodingType {
    /// ASCII encoding (7-bit printable characters)
    Ascii,
    /// UTF-8 encoding (variable-length, 1-4 bytes per codepoint)
    Utf8,
    /// UTF-16 Little Endian
    Utf16Le,
    /// UTF-16 Big Endian
    Utf16Be,
}

impl fmt::Display for EncodingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodingType::Ascii => write!(f, "ASCII"),
            EncodingType::Utf8 => write!(f, "UTF-8"),
            EncodingType::Utf16Le => write!(f, "UTF-16LE"),
            EncodingType::Utf16Be => write!(f, "UTF-16BE"),
        }
    }
}

/// Tags for classifying extracted strings
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tag {
    /// IPv4 address pattern
    IpV4,
    /// IPv6 address pattern
    IpV6,
    /// URL pattern
    Url,
    /// Email address pattern
    Email,
    /// Base64 decoded content
    Base64Decoded,
    /// Hex encoded content
    HexDecoded,
    /// Cryptographic key (various formats)
    CryptoKey,
    /// MD5 hash
    Md5Hash,
    /// SHA1 hash
    Sha1Hash,
    /// SHA256 hash
    Sha256Hash,
    /// Dictionary word match (from --dict)
    DictionaryMatch,
    /// Code snippet (contains braces, keywords, etc.)
    CodeSnippet,
    /// AI/ML model token or prompt
    AiToken,
    /// High entropy string (potential encryption/encoding)
    HighEntropy,
    /// Low entropy string (likely plaintext)
    LowEntropy,
    /// Fuzzy matched dictionary word
    FuzzyMatch,
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tag::IpV4 => write!(f, "IPv4"),
            Tag::IpV6 => write!(f, "IPv6"),
            Tag::Url => write!(f, "URL"),
            Tag::Email => write!(f, "Email"),
            Tag::Base64Decoded => write!(f, "Base64"),
            Tag::HexDecoded => write!(f, "Hex"),
            Tag::CryptoKey => write!(f, "CryptoKey"),
            Tag::Md5Hash => write!(f, "MD5"),
            Tag::Sha1Hash => write!(f, "SHA1"),
            Tag::Sha256Hash => write!(f, "SHA256"),
            Tag::DictionaryMatch => write!(f, "Dict"),
            Tag::CodeSnippet => write!(f, "Code"),
            Tag::AiToken => write!(f, "AI"),
            Tag::HighEntropy => write!(f, "HighEntropy"),
            Tag::LowEntropy => write!(f, "LowEntropy"),
            Tag::FuzzyMatch => write!(f, "Fuzzy"),
        }
    }
}

/// A candidate string extracted from binary data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringCandidate {
    /// Byte offset from the start of the input
    pub offset: usize,
    /// Length of the string in bytes
    pub length: usize,
    /// Reference to the raw bytes (owned for flexibility)
    pub raw_bytes: Vec<u8>,
    /// Detected encoding type
    pub encoding: EncodingType,
}

impl StringCandidate {
    /// Create a new StringCandidate
    pub fn new(offset: usize, length: usize, raw_bytes: Vec<u8>, encoding: EncodingType) -> Self {
        Self {
            offset,
            length,
            raw_bytes,
            encoding,
        }
    }

    /// Get the content as a string slice (lossy UTF-8 conversion)
    pub fn as_str(&self) -> &str {
        // For ASCII and UTF-8, we can use from_utf8_lossy
        // For UTF-16, we need proper decoding
        match self.encoding {
            EncodingType::Ascii | EncodingType::Utf8 => {
                std::str::from_utf8(&self.raw_bytes).unwrap_or("")
            }
            EncodingType::Utf16Le | EncodingType::Utf16Be => {
                // Attempt UTF-16 decoding - return empty as we can't return owned String
                ""
            }
        }
    }

    /// Check if the candidate meets length constraints
    pub fn is_within_length_bounds(&self, min_len: usize, max_len: usize) -> bool {
        self.length >= min_len && self.length <= max_len
    }

    /// Check if the candidate is within the byte range
    pub fn is_within_range(&self, start: usize, end: usize) -> bool {
        self.offset >= start && (self.offset + self.length) <= end
    }
}

/// An annotated string with metadata, tags, and scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedString {
    /// The underlying string candidate
    pub candidate: StringCandidate,
    /// Heuristic score (higher = more interesting)
    pub score: f32,
    /// Classification tags
    pub tags: Vec<Tag>,
    /// Decoded content (UTF-8 string)
    pub content: String,
    /// Optional context bytes for hex dump
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_bytes: Option<Vec<u8>>,
}

impl AnnotatedString {
    /// Create a new AnnotatedString from a candidate
    pub fn from_candidate(candidate: StringCandidate) -> Self {
        let content = match candidate.encoding {
            EncodingType::Ascii | EncodingType::Utf8 => {
                String::from_utf8_lossy(&candidate.raw_bytes).to_string()
            }
            EncodingType::Utf16Le => {
                encoding_rs::UTF_16LE
                    .decode(&candidate.raw_bytes)
                    .0
                    .to_string()
            }
            EncodingType::Utf16Be => {
                encoding_rs::UTF_16BE
                    .decode(&candidate.raw_bytes)
                    .0
                    .to_string()
            }
        };

        Self {
            candidate,
            score: 0.0,
            tags: Vec::new(),
            content,
            context_bytes: None,
        }
    }

    /// Add a tag if not already present
    pub fn add_tag(&mut self, tag: Tag) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Check if the string has any of the specified tags
    pub fn has_any_tag(&self, tags: &[Tag]) -> bool {
        tags.iter().any(|t| self.tags.contains(t))
    }

    /// Check if the string has all of the specified tags
    pub fn has_all_tags(&self, tags: &[Tag]) -> bool {
        tags.iter().all(|t| self.tags.contains(t))
    }

    /// Get display-ready content with escaping for terminal
    pub fn display_content(&self) -> String {
        // Escape non-printable characters
        self.content
            .chars()
            .map(|c| match c {
                '\n' => "\\n".to_string(),
                '\r' => "\\r".to_string(),
                '\t' => "\\t".to_string(),
                c if c.is_control() => format!("\\x{:02x}", c as u8),
                c => c.to_string(),
            })
            .collect()
    }
}

impl PartialEq for AnnotatedString {
    fn eq(&self, other: &Self) -> bool {
        self.candidate.offset == other.candidate.offset
            && self.candidate.length == other.candidate.length
            && self.candidate.raw_bytes == other.candidate.raw_bytes
    }
}

impl Eq for AnnotatedString {}

/// Sort order for output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    /// Sort by byte offset (ascending)
    Offset,
    /// Sort by string length (ascending)
    LengthAsc,
    /// Sort by string length (descending)
    LengthDesc,
    /// Sort by heuristic score (descending)
    Score,
    /// Sort alphabetically by content
    Alphabetical,
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::Offset
    }
}

impl fmt::Display for SortOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SortOrder::Offset => write!(f, "offset"),
            SortOrder::LengthAsc => write!(f, "length-asc"),
            SortOrder::LengthDesc => write!(f, "length-desc"),
            SortOrder::Score => write!(f, "score"),
            SortOrder::Alphabetical => write!(f, "alphabetical"),
        }
    }
}

/// Configuration for the extraction and analysis pipeline
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub min_len: usize,
    pub max_len: usize,
    pub start: usize,
    pub end: usize,
    pub raw_mode: bool,
    pub fuzzy_matching: bool,
    pub sort_order: SortOrder,
    pub context_bytes: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            min_len: 4,
            max_len: usize::MAX,
            start: 0,
            end: usize::MAX,
            raw_mode: false,
            fuzzy_matching: false,
            sort_order: SortOrder::Offset,
            context_bytes: 0,
        }
    }
}
