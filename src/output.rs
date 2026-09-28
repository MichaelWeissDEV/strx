//! Output formatting module for strx

use crate::types::{AnnotatedString, EncodingType};
use anyhow::Result;
use colored::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, Write};

/// Output formatter
pub struct OutputFormatter {
    json_mode: bool,
    show_encoding: bool,
    context_bytes: usize,
    show_colors: bool,
}

impl OutputFormatter {
    /// Create a new output formatter
    pub fn new() -> Self {
        Self {
            json_mode: false,
            show_encoding: false,
            context_bytes: 0,
            show_colors: true,
        }
    }

    /// Set JSON output mode
    pub fn with_json(mut self, json: bool) -> Self {
        self.json_mode = json;
        self
    }

    /// Show encoding type
    pub fn with_encoding(mut self, show: bool) -> Self {
        self.show_encoding = show;
        self
    }

    /// Set context bytes
    pub fn with_context(mut self, bytes: usize) -> Self {
        self.context_bytes = bytes;
        self
    }

    /// Enable/disable colors
    pub fn with_colors(mut self, show: bool) -> Self {
        self.show_colors = show;
        self
    }

    /// Format a single string
    pub fn format_string(&self, s: &AnnotatedString, source_data: Option<&[u8]>) -> String {
        if self.json_mode {
            self.format_json(s, source_data)
        } else {
            self.format_text(s, source_data)
        }
    }

    /// Format as JSON
    fn format_json(&self, s: &AnnotatedString, source_data: Option<&[u8]>) -> String {
        let mut obj = json!({
            "offset": s.candidate.offset,
            "byte_length": s.candidate.byte_len,
            "char_length": s.candidate.char_len,
            "content": s.content,
            "encoding": format!("{}", s.candidate.encoding),
            "score": s.score,
            "tags": s.tags.iter().map(|t| format!("{}", t)).collect::<Vec<_>>(),
        });

        // Add context if requested
        if self.context_bytes > 0 && source_data.is_some() {
            if let Some(data) = source_data {
                if let Some(context) = crate::io::get_hex_dump_context(
                    data,
                    s.candidate.offset,
                    s.candidate.byte_len,
                    self.context_bytes,
                ) {
                    obj["context"] = json!(context);
                }
            }
        }

        obj.to_string()
    }

    /// Format as plain text with colors
    fn format_text(&self, s: &AnnotatedString, source_data: Option<&[u8]>) -> String {
        let mut output = String::new();

        // Offset
        if self.show_colors {
            output.push_str(&format!("{} ", s.candidate.offset.to_string().dimmed()));
        } else {
            output.push_str(&format!("{:8} ", s.candidate.offset));
        }

        // Encoding (if enabled)
        if self.show_encoding {
            let encoding_str = match s.candidate.encoding {
                EncodingType::Ascii => "ASCII",
                EncodingType::Utf8 => "UTF-8",
                EncodingType::Utf16Le => "UTF-16LE",
                EncodingType::Utf16Be => "UTF-16BE",
            };
            if self.show_colors {
                output.push_str(&format!("[{}] ", encoding_str.dimmed()));
            } else {
                output.push_str(&format!("[{:8}] ", encoding_str));
            }
        }

        // Tags
        if !s.tags.is_empty() {
            let tag_strings: Vec<String> = s.tags.iter().map(|t| self.format_tag(t)).collect();
            output.push_str(&tag_strings.join(" "));
            output.push(' ');
        }

        // Content
        if self.show_colors {
            let content = self.colorize_content(&s.content, &s.tags);
            output.push_str(&content);
        } else {
            output.push_str(&s.display_content());
        }

        // Context (hex dump)
        if self.context_bytes > 0 && source_data.is_some() {
            if let Some(data) = source_data {
                if let Some(context) = crate::io::get_hex_dump_context(
                    data,
                    s.candidate.offset,
                    s.candidate.byte_len,
                    self.context_bytes,
                ) {
                    output.push('\n');
                    // Calculate the base offset for hex dump
                    let base_offset = s.candidate.offset.saturating_sub(self.context_bytes);
                    output.push_str(&format_hex_dump(&context, base_offset));
                }
            }
        }

        output
    }

    /// Format a tag with appropriate color
    fn format_tag(&self, tag: &crate::types::Tag) -> String {
        if !self.show_colors {
            return format!("[{}]", tag);
        }

        match tag {
            crate::types::Tag::IpV4 | crate::types::Tag::IpV6 => {
                format!("[{}]", tag.to_string().green())
            }
            crate::types::Tag::Url | crate::types::Tag::Email => {
                format!("[{}]", tag.to_string().blue())
            }
            crate::types::Tag::Base64Decoded | crate::types::Tag::HexDecoded => {
                format!("[{}]", tag.to_string().yellow())
            }
            crate::types::Tag::CryptoKey => {
                format!("[{}]", tag.to_string().purple())
            }
            crate::types::Tag::Md5Hash
            | crate::types::Tag::Sha1Hash
            | crate::types::Tag::Sha256Hash => {
                format!("[{}]", tag.to_string().cyan())
            }
            crate::types::Tag::DictionaryMatch | crate::types::Tag::RegexMatch => {
                format!("[{}]", tag.to_string().bright_green())
            }
            crate::types::Tag::CodeSnippet => {
                format!("[{}]", tag.to_string().bright_blue())
            }
            crate::types::Tag::AiToken => {
                format!("[{}]", tag.to_string().bright_purple())
            }
            crate::types::Tag::HighEntropy => {
                format!("[{}]", tag.to_string().red())
            }
            crate::types::Tag::LowEntropy => {
                format!("[{}]", tag.to_string().bright_black())
            }
            crate::types::Tag::FuzzyMatch => {
                format!("[{}]", tag.to_string().bright_yellow())
            }
        }
    }

    /// Colorize content based on tags
    fn colorize_content(&self, content: &str, tags: &[crate::types::Tag]) -> String {
        if !self.show_colors {
            return content.to_string();
        }

        // Check if any special tags apply
        for tag in tags {
            match tag {
                crate::types::Tag::Url => {
                    return content.blue().to_string();
                }
                crate::types::Tag::Email => {
                    return content.blue().to_string();
                }
                crate::types::Tag::IpV4 | crate::types::Tag::IpV6 => {
                    return content.green().to_string();
                }
                crate::types::Tag::Base64Decoded | crate::types::Tag::HexDecoded => {
                    return content.yellow().to_string();
                }
                crate::types::Tag::CryptoKey => {
                    return content.purple().to_string();
                }
                _ => {}
            }
        }

        content.white().to_string()
    }

    /// Format multiple strings
    pub fn format_strings(
        &self,
        strings: &[AnnotatedString],
        source_data: Option<&[u8]>,
    ) -> Vec<String> {
        strings
            .iter()
            .map(|s| self.format_string(s, source_data))
            .collect()
    }

    /// Format as JSON array
    pub fn format_json_array(
        &self,
        strings: &[AnnotatedString],
        source_data: Option<&[u8]>,
    ) -> String {
        let items: Vec<Value> = strings
            .iter()
            .map(|s| {
                let mut obj = json!({
                    "offset": s.candidate.offset,
                    "byte_length": s.candidate.byte_len,
                    "char_length": s.candidate.char_len,
                    "content": s.content,
                    "encoding": format!("{}", s.candidate.encoding),
                    "score": s.score,
                    "tags": s.tags.iter().map(|t| format!("{}", t)).collect::<Vec<_>>(),
                });

                if self.context_bytes > 0 && source_data.is_some() {
                    if let Some(data) = source_data {
                        if let Some(context) = crate::io::get_hex_dump_context(
                            data,
                            s.candidate.offset,
                            s.candidate.byte_len,
                            self.context_bytes,
                        ) {
                            obj["context"] = json!(context);
                        }
                    }
                }

                obj
            })
            .collect();

        json!(items).to_string()
    }

    /// Output strings to a writer
    pub fn write_strings<W: Write>(
        &self,
        strings: &[AnnotatedString],
        source_data: Option<&[u8]>,
        writer: &mut W,
    ) -> Result<()> {
        if self.json_mode {
            let json = self.format_json_array(strings, source_data);
            writeln!(writer, "{}", json)?;
        } else {
            for formatted in self.format_strings(strings, source_data) {
                writeln!(writer, "{}", formatted)?;
            }
        }
        Ok(())
    }

    /// Output strings to stdout
    pub fn print_strings(
        &self,
        strings: &[AnnotatedString],
        source_data: Option<&[u8]>,
    ) -> Result<()> {
        self.write_strings(strings, source_data, &mut io::stdout())
    }
}

impl Default for OutputFormatter {
    fn default() -> Self {
        Self::new()
    }
}

/// Format hex dump (similar to hexdump -C)
/// base_offset: the absolute file offset of the first byte in data
fn format_hex_dump(data: &[u8], base_offset: usize) -> String {
    let mut output = String::new();

    // Process in chunks of 16 bytes
    let mut offset = base_offset;
    let mut remaining = data;

    while !remaining.is_empty() {
        let chunk_size = std::cmp::min(16, remaining.len());
        let chunk = &remaining[..chunk_size];

        // Offset
        output.push_str(&format!("  {:08x}  ", offset));

        // Hex bytes (8 groups of 2 bytes)
        for i in 0..8 {
            if i * 2 < chunk_size {
                let byte1 = chunk[i * 2];
                let byte2 = if i * 2 + 1 < chunk_size {
                    chunk[i * 2 + 1]
                } else {
                    0
                };

                output.push_str(&format!("{:02x} {:02x}", byte1, byte2));
            } else {
                output.push_str("     ");
            }

            if i < 7 {
                output.push(' ');
            }
        }

        // ASCII representation
        output.push_str("  |");
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7E {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push('|');

        output.push('\n');
        offset += chunk_size;
        remaining = &remaining[chunk_size..];
    }

    output
}

/// Format hex dump in a simpler way for context display
#[allow(dead_code)]
fn format_simple_hex_dump(data: &[u8], center_offset: usize, context_bytes: usize) -> String {
    let mut output = String::new();
    let start = center_offset.saturating_sub(context_bytes);
    let string_start = center_offset;
    let string_end = center_offset + 1; // Assuming 1-byte string for simplicity

    output.push_str("  Hex dump:");
    output.push('\n');

    for (i, &byte) in data.iter().enumerate() {
        let absolute_offset = start + i;

        if i % 16 == 0 {
            output.push_str(&format!("  {:08x}: ", absolute_offset));
        }

        // Highlight string bytes
        if absolute_offset >= string_start && absolute_offset < string_end {
            output.push_str(&format!("{} ", format!("{:02x}", byte).on_yellow().black()));
        } else {
            output.push_str(&format!("{:02x} ", byte));
        }

        if i % 16 == 15 || i == data.len() - 1 {
            output.push('\n');
        }
    }

    output
}

/// Summary statistics
pub struct ExtractionStats {
    pub total_strings: usize,
    pub total_bytes: usize,
    pub by_encoding: HashMap<String, usize>,
    pub by_tag: HashMap<String, usize>,
    pub high_score_count: usize,
}

impl ExtractionStats {
    pub fn new() -> Self {
        Self {
            total_strings: 0,
            total_bytes: 0,
            by_encoding: HashMap::new(),
            by_tag: HashMap::new(),
            high_score_count: 0,
        }
    }
}

impl Default for ExtractionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtractionStats {
    pub fn add_string(&mut self, s: &AnnotatedString) {
        self.total_strings += 1;
        self.total_bytes += s.candidate.byte_len;

        let encoding_str = format!("{}", s.candidate.encoding);
        *self.by_encoding.entry(encoding_str).or_insert(0) += 1;

        for tag in &s.tags {
            let tag_str = format!("{}", tag);
            *self.by_tag.entry(tag_str).or_insert(0) += 1;
        }

        if s.score > 50.0 {
            self.high_score_count += 1;
        }
    }

    pub fn add_strings(&mut self, strings: &[AnnotatedString]) {
        for s in strings {
            self.add_string(s);
        }
    }
}

/// Print summary statistics
pub fn print_summary(
    stats: &ExtractionStats,
    input_name: &str,
    config: &crate::types::PipelineConfig,
) {
    println!();
    println!("{} Summary {}", "=".repeat(20), "=".repeat(20));
    println!("Input: {}", input_name);
    println!("Total strings extracted: {}", stats.total_strings);
    println!("Total bytes: {}", stats.total_bytes);
    println!("Sort order: {}", config.sort_order);
    println!("High score strings (>50): {}", stats.high_score_count);

    if !stats.by_encoding.is_empty() {
        println!("\nBy encoding:");
        for (encoding, count) in &stats.by_encoding {
            println!("  {}: {}", encoding, count);
        }
    }

    if !stats.by_tag.is_empty() {
        println!("\nBy tag:");
        let mut tags: Vec<_> = stats.by_tag.iter().collect();
        tags.sort_by(|a, b| b.1.cmp(a.1));
        for (tag, count) in tags {
            println!("  {}: {}", tag, count);
        }
    }
}

/// Builder for output formatter
pub struct OutputFormatterBuilder {
    json_mode: bool,
    show_encoding: bool,
    context_bytes: usize,
    show_colors: bool,
}

impl OutputFormatterBuilder {
    pub fn new() -> Self {
        Self {
            json_mode: false,
            show_encoding: false,
            context_bytes: 0,
            show_colors: true,
        }
    }

    pub fn json(mut self, json: bool) -> Self {
        self.json_mode = json;
        self
    }

    pub fn show_encoding(mut self, show: bool) -> Self {
        self.show_encoding = show;
        self
    }

    pub fn context_bytes(mut self, bytes: usize) -> Self {
        self.context_bytes = bytes;
        self
    }

    pub fn colors(mut self, show: bool) -> Self {
        self.show_colors = show;
        self
    }

    pub fn build(self) -> OutputFormatter {
        OutputFormatter {
            json_mode: self.json_mode,
            show_encoding: self.show_encoding,
            context_bytes: self.context_bytes,
            show_colors: self.show_colors,
        }
    }
}

impl Default for OutputFormatterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a formatter from CLI arguments
pub fn create_formatter_from_args(args: &crate::cli::Args) -> OutputFormatter {
    OutputFormatterBuilder::new()
        .json(args.json)
        .show_encoding(args.show_encoding)
        .context_bytes(args.context)
        .colors(!args.quiet) // Disable colors in quiet mode
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EncodingType, StringCandidate, Tag};

    #[test]
    fn test_format_text() {
        let formatter = OutputFormatter::new().with_colors(false);
        let s = AnnotatedString {
            candidate: StringCandidate::new(0, 5, 5, EncodingType::Ascii),
            score: 0.0,
            tags: Vec::new(),
            content: "hello".to_string(),
            derived: Vec::new(),
        };

        let formatted = formatter.format_string(&s, None);
        assert!(formatted.contains("0 "));
        assert!(formatted.contains("hello"));
    }

    #[test]
    fn test_format_json() {
        let formatter = OutputFormatter::new().with_json(true);
        let s = AnnotatedString {
            candidate: StringCandidate::new(0, 5, 5, EncodingType::Ascii),
            score: 0.0,
            tags: Vec::new(),
            content: "hello".to_string(),
            derived: Vec::new(),
        };

        let formatted = formatter.format_string(&s, None);
        assert!(formatted.contains("\"offset\""));
        assert!(formatted.contains("\"content\""));
        assert!(formatted.contains("\"hello\""));
    }

    #[test]
    fn test_format_with_tags() {
        let formatter = OutputFormatter::new().with_colors(false);
        let mut s = AnnotatedString {
            candidate: StringCandidate::new(0, 13, 13, EncodingType::Ascii),
            score: 0.0,
            tags: Vec::new(),
            content: "192.168.1.1".to_string(),
            derived: Vec::new(),
        };
        s.add_tag(Tag::IpV4);
        s.add_tag(Tag::DictionaryMatch);

        let formatted = formatter.format_string(&s, None);
        assert!(formatted.contains("[IPv4]"));
        assert!(formatted.contains("[Dict]"));
    }

    #[test]
    fn test_hex_dump() {
        let data = b"Hello, World!";
        let dump = format_simple_hex_dump(data, 0, 16);
        assert!(dump.contains("65 6c 6c 6f"));
    }

    #[test]
    fn test_extraction_stats() {
        let mut stats = ExtractionStats::new();

        let mut s1 = AnnotatedString {
            candidate: StringCandidate::new(0, 5, 5, EncodingType::Ascii),
            score: 0.0,
            tags: Vec::new(),
            content: "hello".to_string(),
            derived: Vec::new(),
        };
        s1.add_tag(Tag::DictionaryMatch);

        let s2 = AnnotatedString {
            candidate: StringCandidate::new(5, 5, 5, EncodingType::Ascii),
            score: 0.0,
            tags: Vec::new(),
            content: "world".to_string(),
            derived: Vec::new(),
        };

        stats.add_strings(&[s1, s2]);

        assert_eq!(stats.total_strings, 2);
        assert_eq!(stats.total_bytes, 10);
        assert_eq!(stats.by_tag.get("Dict"), Some(&1));
    }
}
