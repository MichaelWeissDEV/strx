//! CLI argument parsing and configuration

use clap::{ArgAction, Parser, ValueEnum};
use std::path::PathBuf;
use std::str::FromStr;

use crate::types::{PipelineConfig, SortOrder};

/// Custom parser for hexadecimal usize values
fn parse_hex_or_decimal(s: &str) -> Result<usize, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        usize::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex number '{}': {}", s, e))
    } else {
        usize::from_str(s).map_err(|e| format!("Invalid decimal number '{}': {}", s, e))
    }
}

/// Sort order enum for clap ValueEnum
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliSortOrder {
    /// Sort by offset
    Offset,
    /// Sort by length (ascending)
    #[value(alias = "length-asc")]
    LengthAsc,
    /// Sort by length (descending)
    #[value(alias = "length-desc")]
    LengthDesc,
    /// Sort by score
    Score,
    /// Sort alphabetically
    Alphabetical,
}

impl From<CliSortOrder> for SortOrder {
    fn from(order: CliSortOrder) -> Self {
        match order {
            CliSortOrder::Offset => SortOrder::Offset,
            CliSortOrder::LengthAsc => SortOrder::LengthAsc,
            CliSortOrder::LengthDesc => SortOrder::LengthDesc,
            CliSortOrder::Score => SortOrder::Score,
            CliSortOrder::Alphabetical => SortOrder::Alphabetical,
        }
    }
}

/// Main CLI arguments
#[derive(Parser, Debug)]
#[command(
    name = "strx",
    author,
    version,
    about = "Strings Extended - A high-performance heuristic drop-in replacement for the Unix 'strings' tool",
    long_about = None,
    after_help = "Examples:\n  strx file.bin                    # Extract strings from file\n  strx --min 8 --max 64 file.bin    # Filter by length\n  strx --dict words.txt file.bin   # Use dictionary matching\n  strx --fuzzy --dict words.txt    # Enable fuzzy matching\n  strx --json file.bin             # Output as JSON\n  strx -C 16 file.bin             # Show 16 bytes of context\n  strx --start 0x1000 --end 0x2000 # Extract from specific range"
)]
pub struct Args {
    /// Input file to process. If not provided, reads from stdin.
    #[arg(value_name = "INPUT", default_value = "-")]
    pub input: String,

    /// Enable raw mode: skip all heuristics, behave like GNU strings
    #[arg(long, short = 'r')]
    pub raw: bool,

    /// Minimum length in characters to extract (default: 4)
    #[arg(long, short = 'n', default_value = "4", value_parser = clap::value_parser!(usize))]
    pub min: usize,

    /// Maximum length in characters to extract (default: unlimited)
    #[arg(long, short = 'x', value_parser = clap::value_parser!(usize))]
    pub max: Option<usize>,

    /// Start offset in bytes (supports hex with 0x prefix)
    #[arg(long, short = 'S', default_value = "0", value_parser = parse_hex_or_decimal)]
    pub start: usize,

    /// End offset in bytes (supports hex with 0x prefix)
    #[arg(long, short = 'E', value_parser = parse_hex_or_decimal)]
    pub end: Option<usize>,

    /// Paths to dictionary files for word matching (e.g., SecLists)
    #[arg(long, short = 'd', value_name = "DICT_FILE", action = ArgAction::Append)]
    pub dict: Vec<PathBuf>,

    /// Custom regex patterns to match
    #[arg(long, short = 'e', value_name = "PATTERN", action = ArgAction::Append)]
    pub regex: Vec<String>,

    /// Enable fuzzy matching with Levenshtein distance (tolerance: 1 or 2 edits)
    #[arg(long, short = 'f')]
    pub fuzzy: bool,

    /// Sort order for output
    #[arg(long, short = 's', value_enum, default_value = "offset")]
    pub sort: CliSortOrder,

    /// Show X bytes of context before and after each string as hex dump
    #[arg(long, short = 'C', value_name = "BYTES", default_value = "0", value_parser = clap::value_parser!(usize))]
    pub context: usize,

    /// Output as JSON array
    #[arg(long)]
    pub json: bool,

    /// Show encoding type for each string
    #[arg(long)]
    pub show_encoding: bool,

    /// Only show strings with specific tags (can be specified multiple times)
    #[arg(long, value_name = "TAG", action = ArgAction::Append)]
    pub tag: Vec<String>,

    /// Exclude strings with specific tags
    #[arg(long, value_name = "TAG", action = ArgAction::Append)]
    pub exclude_tag: Vec<String>,

    /// Silent mode: suppress all output except errors
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Verbose mode: show additional debugging information
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

impl Args {
    /// Convert CLI args to pipeline configuration
    pub fn to_config(&self) -> PipelineConfig {
        PipelineConfig {
            min_len: self.min,
            max_len: self.max.unwrap_or(usize::MAX),
            start: self.start,
            end: self.end.unwrap_or(usize::MAX),
            raw_mode: self.raw,
            fuzzy_matching: self.fuzzy,
            sort_order: self.sort.into(),
            context_bytes: self.context,
        }
    }

    /// Get the input source path
    pub fn input_path(&self) -> Option<&str> {
        if self.input == "-" {
            None
        } else {
            Some(&self.input)
        }
    }

    /// Check if we should read from stdin
    pub fn use_stdin(&self) -> bool {
        self.input == "-"
    }
}

/// Parse tag name from string
pub fn parse_tag(s: &str) -> Option<crate::types::Tag> {
    match s.to_lowercase().as_str() {
        "ipv4" | "ip4" => Some(crate::types::Tag::IpV4),
        "ipv6" | "ip6" => Some(crate::types::Tag::IpV6),
        "url" => Some(crate::types::Tag::Url),
        "email" => Some(crate::types::Tag::Email),
        "base64" | "b64" => Some(crate::types::Tag::Base64Decoded),
        "hex" => Some(crate::types::Tag::HexDecoded),
        "crypto" | "cryptokey" => Some(crate::types::Tag::CryptoKey),
        "md5" => Some(crate::types::Tag::Md5Hash),
        "sha1" => Some(crate::types::Tag::Sha1Hash),
        "sha256" => Some(crate::types::Tag::Sha256Hash),
        "dict" | "dictionary" => Some(crate::types::Tag::DictionaryMatch),
        "code" => Some(crate::types::Tag::CodeSnippet),
        "ai" | "aitoken" => Some(crate::types::Tag::AiToken),
        "highentropy" | "high-entropy" => Some(crate::types::Tag::HighEntropy),
        "lowentropy" | "low-entropy" => Some(crate::types::Tag::LowEntropy),
        "fuzzy" => Some(crate::types::Tag::FuzzyMatch),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_or_decimal() {
        assert_eq!(parse_hex_or_decimal("100").unwrap(), 100);
        assert_eq!(parse_hex_or_decimal("0x100").unwrap(), 256);
        assert_eq!(parse_hex_or_decimal("0X100").unwrap(), 256);
        assert_eq!(parse_hex_or_decimal("0xff").unwrap(), 255);
        assert!(parse_hex_or_decimal("invalid").is_err());
    }

    #[test]
    fn test_parse_tag() {
        assert_eq!(parse_tag("ipv4"), Some(crate::types::Tag::IpV4));
        assert_eq!(parse_tag("IPv4"), Some(crate::types::Tag::IpV4));
        assert_eq!(parse_tag("base64"), Some(crate::types::Tag::Base64Decoded));
        assert_eq!(parse_tag("nonexistent"), None);
    }

    #[test]
    fn test_args_to_config() {
        let args = Args {
            input: "test.bin".to_string(),
            raw: false,
            min: 8,
            max: Some(64),
            start: 0,
            end: Some(1024),
            dict: vec![],
            regex: vec![],
            fuzzy: true,
            sort: CliSortOrder::Score,
            context: 16,
            json: false,
            show_encoding: false,
            tag: vec![],
            exclude_tag: vec![],
            quiet: false,
            verbose: false,
        };

        let config = args.to_config();
        assert_eq!(config.min_len, 8);
        assert_eq!(config.max_len, 64);
        assert_eq!(config.start, 0);
        assert_eq!(config.end, 1024);
        assert!(config.fuzzy_matching);
        assert!(matches!(config.sort_order, SortOrder::Score));
        assert_eq!(config.context_bytes, 16);
    }
}
