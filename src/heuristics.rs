//! Heuristic pipeline for string classification and filtering

use crate::types::{AnnotatedString, Tag};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind};
use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use strsim::levenshtein;

/// Trait for heuristic filters
pub trait HeuristicFilter: Send + Sync {
    /// Evaluate and potentially modify the annotated string
    /// Returns true if the string should be kept, false if it should be discarded
    fn evaluate(&self, s: &mut AnnotatedString) -> bool;

    /// Get the filter name for debugging
    fn name(&self) -> &str;
}

/// Pipeline for applying heuristic filters
pub struct HeuristicPipeline {
    filters: Vec<Arc<dyn HeuristicFilter>>,
}

impl HeuristicPipeline {
    pub fn new() -> Self {
        Self { filters: Vec::new() }
    }

    /// Add a filter to the pipeline
    pub fn add_filter<F: HeuristicFilter + 'static>(&mut self, filter: F) {
        self.filters.push(Arc::new(filter));
    }

    /// Process a string through all filters
    pub fn process(&self, s: &mut AnnotatedString) -> bool {
        for filter in &self.filters {
            if !filter.evaluate(s) {
                return false;
            }
        }
        true
    }

    /// Process multiple strings
    pub fn process_all(&self, strings: &mut Vec<AnnotatedString>) -> Vec<AnnotatedString> {
        strings.retain_mut(|s| self.process(s));
        strings.to_vec()
    }
}

impl Default for HeuristicPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== Individual Filters ====================

/// Entropy filter for noise suppression
pub struct EntropyChecker {
    threshold: f32,
    short_string_threshold: f32,
    short_string_max_len: usize,
}

impl EntropyChecker {
    pub fn new(threshold: f32, short_string_threshold: f32, short_string_max_len: usize) -> Self {
        Self {
            threshold,
            short_string_threshold,
            short_string_max_len,
        }
    }

    pub fn with_defaults() -> Self {
        Self {
            threshold: 4.5,
            short_string_threshold: 3.5,
            short_string_max_len: 10,
        }
    }

    /// Calculate Shannon entropy of a string
    fn calculate_entropy(s: &str) -> f32 {
        if s.is_empty() {
            return 0.0;
        }

        let mut byte_counts = [0usize; 256];
        let total_bytes = s.bytes().count();

        for byte in s.bytes() {
            byte_counts[byte as usize] += 1;
        }

        let mut entropy = 0.0f32;
        for &count in byte_counts.iter() {
            if count > 0 {
                let probability = count as f32 / total_bytes as f32;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }
}

impl HeuristicFilter for EntropyChecker {
    fn evaluate(&self, s: &mut AnnotatedString) -> bool {
        let content = &s.content;
        let entropy = Self::calculate_entropy(content);

        // Apply different thresholds based on string length
        let threshold = if content.len() <= self.short_string_max_len {
            self.short_string_threshold
        } else {
            self.threshold
        };

        if entropy > threshold {
            // Too high entropy - likely random/encoded data
            // Tag it but keep it (user can filter by tag)
            s.add_tag(Tag::HighEntropy);
            return true; // Keep it, but tagged
        }

        s.add_tag(Tag::LowEntropy);
        true
    }

    fn name(&self) -> &str {
        "EntropyChecker"
    }
}

/// Regex tagger for IoC (Indicators of Compromise) patterns
pub struct RegexTagger {
    patterns: Vec<(Regex, Tag)>,
}

impl RegexTagger {
    pub fn new() -> Self {
        Self { patterns: Vec::new() }
    }

    pub fn with_defaults() -> Self {
        let mut tagger = Self::new();

        // IPv4 pattern
        let ipv4_re = Regex::new(r"^(\d{1,3}\.){3}\d{1,3}$").unwrap();
        tagger.add_pattern(ipv4_re, Tag::IpV4);

        // IPv6 pattern (simplified)
        let ipv6_re = Regex::new(
            r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$",
        )
        .unwrap();
        tagger.add_pattern(ipv6_re, Tag::IpV6);

        // URL pattern (simplified)
        let url_re = Regex::new(
            r"^(https?|ftp)://[^\s/$.?#].[^\s]*$",
        )
        .unwrap();
        tagger.add_pattern(url_re, Tag::Url);

        // Email pattern
        let email_re = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        tagger.add_pattern(email_re, Tag::Email);

        // MD5 hash
        let md5_re = Regex::new(r"^[0-9a-fA-F]{32}$").unwrap();
        tagger.add_pattern(md5_re, Tag::Md5Hash);

        // SHA1 hash
        let sha1_re = Regex::new(r"^[0-9a-fA-F]{40}$").unwrap();
        tagger.add_pattern(sha1_re, Tag::Sha1Hash);

        // SHA256 hash
        let sha256_re = Regex::new(r"^[0-9a-fA-F]{64}$").unwrap();
        tagger.add_pattern(sha256_re, Tag::Sha256Hash);

        // Cryptographic key patterns (various formats)
        let crypto_re = Regex::new(
            r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
        )
        .unwrap();
        tagger.add_pattern(crypto_re, Tag::CryptoKey);

        // AI/ML token patterns
        let ai_re = Regex::new(r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>").unwrap();
        tagger.add_pattern(ai_re, Tag::AiToken);

        tagger
    }

    /// Add a custom pattern
    pub fn add_pattern(&mut self, pattern: Regex, tag: Tag) {
        self.patterns.push((pattern, tag));
    }

    /// Add patterns from command-line regex
    pub fn add_custom_patterns(&mut self, patterns: &[String]) {
        for pattern in patterns {
            if let Ok(regex) = Regex::new(pattern) {
                // Default tag for custom patterns
                self.patterns.push((regex, Tag::DictionaryMatch));
            }
        }
    }
}

impl HeuristicFilter for RegexTagger {
    fn evaluate(&self, s: &mut AnnotatedString) -> bool {
        for (pattern, tag) in &self.patterns {
            if pattern.is_match(&s.content) {
                s.add_tag(tag.clone());
            }
        }
        true // Regex matching never discards
    }

    fn name(&self) -> &str {
        "RegexTagger"
    }
}

/// Dictionary matcher using Aho-Corasick algorithm
pub struct DictionaryMatcher {
    automaton: Option<AhoCorasick>,
    words: HashSet<String>,
    fuzzy_matching: bool,
    fuzzy_tolerance: usize,
}

impl DictionaryMatcher {
    pub fn new(fuzzy_matching: bool) -> Self {
        Self {
            automaton: None,
            words: HashSet::new(),
            fuzzy_matching,
            fuzzy_tolerance: 2, // Default tolerance
        }
    }

    /// Load dictionary from file and add words to the collection
    pub fn load_dictionary<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut words: Vec<String> = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                words.push(trimmed);
            }
        }

        self.words.extend(words);
        Ok(())
    }

    /// Load multiple dictionaries and build a single automaton
    pub fn load_dictionaries(&mut self, paths: &[impl AsRef<Path>]) -> Result<()> {
        // Clear existing words and automaton
        self.words.clear();
        self.automaton = None;
        
        // Load all dictionaries
        for path in paths {
            self.load_dictionary(path)?;
        }
        
        // Deduplicate words
        let mut unique_words: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for word in &self.words {
            if !seen.contains(word) {
                seen.insert(word.clone());
                unique_words.push(word.clone());
            }
        }
        
        // Build single Aho-Corasick automaton from all words
        if !unique_words.is_empty() {
            let automaton = AhoCorasickBuilder::new()
                .kind(Some(AhoCorasickKind::DFA))
                .build(&unique_words)?;
            self.automaton = Some(automaton);
        }
        
        Ok(())
    }

    /// Set fuzzy matching tolerance
    pub fn set_fuzzy_tolerance(&mut self, tolerance: usize) {
        self.fuzzy_tolerance = tolerance;
    }
}

impl HeuristicFilter for DictionaryMatcher {
    fn evaluate(&self, s: &mut AnnotatedString) -> bool {
        if let Some(automaton) = &self.automaton {
            // Use Aho-Corasick for exact matching
            for mat in automaton.find_iter(&s.content.to_lowercase()) {
                if mat.len() > 0 {
                    s.add_tag(Tag::DictionaryMatch);
                    return true;
                }
            }

            // If fuzzy matching is enabled
            if self.fuzzy_matching {
                for word in &self.words {
                    let distance = levenshtein(&s.content.to_lowercase(), &word.to_lowercase());
                    if distance <= self.fuzzy_tolerance {
                        s.add_tag(Tag::FuzzyMatch);
                        s.add_tag(Tag::DictionaryMatch);
                        return true;
                    }
                }
            }
        }
        true // Dictionary matching never discards
    }

    fn name(&self) -> &str {
        "DictionaryMatcher"
    }
}

/// Smart peeker for Base64 and Hex decoding
pub struct SmartPeeker {
    base64_engine: general_purpose::GeneralPurpose,
}

impl SmartPeeker {
    pub fn new() -> Self {
        Self {
            base64_engine: general_purpose::STANDARD,
        }
    }

    /// Check if a string looks like Base64
    fn is_base64_like(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }

        // Base64 alphabet
        let base64_chars: HashSet<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            .chars()
            .collect();

        s.chars().all(|c| base64_chars.contains(&c))
    }

    /// Check if a string looks like Hex
    fn is_hex_like(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }

        // Hex string: even length, only hex digits
        if s.len() % 2 != 0 {
            return false;
        }

        s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Decode Base64 string
    fn decode_base64(&self, s: &str) -> Option<String> {
        self.base64_engine
            .decode(s)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    /// Decode Hex string
    fn decode_hex(s: &str) -> Option<String> {
        (0..s.len())
            .step_by(2)
            .map(|i| {
                let byte_str = &s[i..i + 2];
                u8::from_str_radix(byte_str, 16)
            })
            .collect::<Result<Vec<u8>, _>>()
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    /// Check if decoded content has low entropy (likely plaintext)
    fn has_low_entropy(s: &str) -> bool {
        let entropy = EntropyChecker::calculate_entropy(s);
        entropy < 3.0 // Low threshold for decoded content
    }
}

impl Default for SmartPeeker {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicFilter for SmartPeeker {
    fn evaluate(&self, s: &mut AnnotatedString) -> bool {
        let content = s.content.clone();

        // Try Base64 decoding
        // NOTE: SmartPeeker is temporarily disabled to prevent mutation of original evidence
        // as per P1-8 requirement: "Raw Evidence niemals verändern"
        // When re-enabled, it should:
        // 1. Store derived content separately (e.g., in a derived_content field)
        // 2. Never modify candidate.offset, candidate.byte_len, candidate.raw_bytes
        // 3. Add tags for decoded content
        // For now, this is a no-op to maintain correctness

        true // Smart peeking never discards
    }

    fn name(&self) -> &str {
        "SmartPeeker"
    }
}

/// Code and AI token detector
pub struct CodeTokenizer {
    code_patterns: Vec<Regex>,
    ai_patterns: Vec<Regex>,
}

impl CodeTokenizer {
    pub fn new() -> Self {
        Self {
            code_patterns: Vec::new(),
            ai_patterns: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut tokenizer = Self::new();

        // Code patterns
        let code_keywords = [
            r"\b(function|func|def|class|struct|interface|enum|type)\b",
            r"\b(if|else|elif|for|while|do|switch|case|default|return|break|continue)\b",
            r"\b(import|from|require|use|namespace|package)\b",
            r"\b(try|catch|finally|throw|throws)\b",
            r"\b(new|delete|this|super|self|static|const|let|var|final)\b",
            r"\{(.*?)\}", // Braces
            r"\[.*?\]", // Brackets
            r"\b(null|undefined|true|false|nil|None)\b",
        ];

        for pattern in code_keywords {
            if let Ok(re) = Regex::new(pattern) {
                tokenizer.code_patterns.push(re);
            }
        }

        // AI/ML token patterns
        let ai_keywords = [
            r"<\|im_start\|>",
            r"<\|im_end\|>",
            r"<\|system\|>",
            r"<\|user\|>",
            r"<\|assistant\|>",
            r"<\|reserved_token_\d+\|>",
            r"\b(model|token|prompt|completion|inference|embedding)\b",
        ];

        for pattern in ai_keywords {
            if let Ok(re) = Regex::new(pattern) {
                tokenizer.ai_patterns.push(re);
            }
        }

        tokenizer
    }
}

impl HeuristicFilter for CodeTokenizer {
    fn evaluate(&self, s: &mut AnnotatedString) -> bool {
        // Check for code patterns
        for pattern in &self.code_patterns {
            if pattern.is_match(&s.content) {
                s.add_tag(Tag::CodeSnippet);
                break;
            }
        }

        // Check for AI patterns
        for pattern in &self.ai_patterns {
            if pattern.is_match(&s.content) {
                s.add_tag(Tag::AiToken);
                break;
            }
        }

        true // Code/AI detection never discards
    }

    fn name(&self) -> &str {
        "CodeTokenizer"
    }
}

/// Minimum length filter
pub struct MinLengthFilter {
    min_len: usize,
}

impl MinLengthFilter {
    pub fn new(min_len: usize) -> Self {
        Self { min_len }
    }
}

impl HeuristicFilter for MinLengthFilter {
    fn evaluate(&self, s: &mut AnnotatedString) -> bool {
        s.candidate.byte_len >= self.min_len
    }

    fn name(&self) -> &str {
        "MinLengthFilter"
    }
}

/// Maximum length filter
pub struct MaxLengthFilter {
    max_len: usize,
}

impl MaxLengthFilter {
    pub fn new(max_len: usize) -> Self {
        Self { max_len }
    }
}

impl HeuristicFilter for MaxLengthFilter {
    fn evaluate(&self, s: &mut AnnotatedString) -> bool {
        s.candidate.byte_len <= self.max_len
    }

    fn name(&self) -> &str {
        "MaxLengthFilter"
    }
}

// ==================== Pipeline Builder ====================

/// Builder for creating a heuristic pipeline with common configurations
pub struct PipelineBuilder {
    pipeline: HeuristicPipeline,
    fuzzy_matching: bool,
    dictionary_paths: Vec<PathBuf>,
    custom_regex: Vec<String>,
    min_len: usize,
    max_len: usize,
}

impl PipelineBuilder {
    pub fn new() -> Self {
        Self {
            pipeline: HeuristicPipeline::new(),
            fuzzy_matching: false,
            dictionary_paths: Vec::new(),
            custom_regex: Vec::new(),
            min_len: 4,
            max_len: usize::MAX,
        }
    }

    /// Enable fuzzy matching
    pub fn with_fuzzy_matching(mut self, enabled: bool) -> Self {
        self.fuzzy_matching = enabled;
        self
    }

    /// Add dictionary paths
    pub fn with_dictionaries(mut self, paths: Vec<PathBuf>) -> Self {
        self.dictionary_paths = paths;
        self
    }

    /// Add custom regex patterns
    pub fn with_custom_regex(mut self, patterns: Vec<String>) -> Self {
        self.custom_regex = patterns;
        self
    }

    /// Set length constraints
    pub fn with_length_constraints(mut self, min_len: usize, max_len: usize) -> Self {
        self.min_len = min_len;
        self.max_len = max_len;
        self
    }

    /// Build the pipeline
    pub fn build(self) -> Result<HeuristicPipeline> {
        let mut pipeline = HeuristicPipeline::new();

        // Add smart peeker first (decode/normalize)
        // Note: Temporarily disabled for P0 correctness testing
        // pipeline.add_filter(SmartPeeker::new());

        // Add entropy checker (analyze original content)
        pipeline.add_filter(EntropyChecker::with_defaults());

        // Add regex tagger (analyze original content)
        let mut tagger = RegexTagger::with_defaults();
        tagger.add_custom_patterns(&self.custom_regex);
        pipeline.add_filter(tagger);

        // Add dictionary matcher (analyze original content)
        if !self.dictionary_paths.is_empty() {
            let mut matcher = DictionaryMatcher::new(self.fuzzy_matching);
            matcher.load_dictionaries(&self.dictionary_paths)?;
            pipeline.add_filter(matcher);
        }

        // Add code tokenizer (analyze original content)
        pipeline.add_filter(CodeTokenizer::with_defaults());

        // Add length filters
        pipeline.add_filter(MinLengthFilter::new(self.min_len));
        if self.max_len != usize::MAX {
            pipeline.add_filter(MaxLengthFilter::new(self.max_len));
        }

        Ok(pipeline)
    }
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== Tag Filtering ====================

/// Filter strings by required tags
pub fn filter_by_required_tags(strings: &mut Vec<AnnotatedString>, required_tags: &[Tag]) {
    if required_tags.is_empty() {
        return;
    }
    strings.retain(|s| s.has_all_tags(required_tags));
}

/// Filter strings by excluded tags
pub fn filter_by_excluded_tags(strings: &mut Vec<AnnotatedString>, excluded_tags: &[Tag]) {
    if excluded_tags.is_empty() {
        return;
    }
    strings.retain(|s| !s.has_any_tag(excluded_tags));
}

/// Parse tag names from command line arguments
pub fn parse_tag_filters(required: &[String], excluded: &[String]) -> (Vec<Tag>, Vec<Tag>) {
    let mut required_tags = Vec::new();
    let mut excluded_tags = Vec::new();

    for tag_name in required {
        if let Some(tag) = parse_tag_name(tag_name) {
            required_tags.push(tag);
        }
    }

    for tag_name in excluded {
        if let Some(tag) = parse_tag_name(tag_name) {
            excluded_tags.push(tag);
        }
    }

    (required_tags, excluded_tags)
}

/// Parse a tag name string into a Tag enum
pub fn parse_tag_name(name: &str) -> Option<Tag> {
    match name.to_lowercase().as_str() {
        "ipv4" | "ip4" | "ip" => Some(Tag::IpV4),
        "ipv6" | "ip6" => Some(Tag::IpV6),
        "url" => Some(Tag::Url),
        "email" => Some(Tag::Email),
        "base64" | "b64" => Some(Tag::Base64Decoded),
        "hex" => Some(Tag::HexDecoded),
        "crypto" | "cryptokey" => Some(Tag::CryptoKey),
        "md5" => Some(Tag::Md5Hash),
        "sha1" => Some(Tag::Sha1Hash),
        "sha256" => Some(Tag::Sha256Hash),
        "dict" | "dictionary" => Some(Tag::DictionaryMatch),
        "code" | "codesnippet" => Some(Tag::CodeSnippet),
        "ai" | "aitoken" => Some(Tag::AiToken),
        "highentropy" | "high-entropy" => Some(Tag::HighEntropy),
        "lowentropy" | "low-entropy" => Some(Tag::LowEntropy),
        "fuzzy" | "fuzzymatch" => Some(Tag::FuzzyMatch),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_entropy_calculation() {
        // Low entropy string (repetitive)
        let low_entropy = "aaaaaaaaaa";
        let entropy = EntropyChecker::calculate_entropy(low_entropy);
        assert!(entropy < 1.0);

        // High entropy string (random-looking)
        let high_entropy = "abcdefghijklmnopqrstuvwxyz";
        let entropy = EntropyChecker::calculate_entropy(high_entropy);
        assert!(entropy > 3.0);
    }

    #[test]
    fn test_base64_detection() {
        let smart_peeker = SmartPeeker::new();
        assert!(SmartPeeker::is_base64_like("SGVsbG8gV29ybGQ="));
        assert!(!SmartPeeker::is_base64_like("not base64!"));
    }

    #[test]
    fn test_hex_detection() {
        assert!(SmartPeeker::is_hex_like("48656c6c6f"));
        assert!(!SmartPeeker::is_hex_like("48656c6c6")); // odd length
        assert!(!SmartPeeker::is_hex_like("48656c6c6g")); // invalid hex
    }

    #[test]
    fn test_base64_decoding() {
        let smart_peeker = SmartPeeker::new();
        let decoded = smart_peeker.decode_base64("SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(decoded, "Hello World");
    }

    #[test]
    fn test_hex_decoding() {
        let decoded = SmartPeeker::decode_hex("48656c6c6f").unwrap();
        assert_eq!(decoded, "Hello");
    }

    #[test]
    fn test_ipv4_regex() {
        let tagger = RegexTagger::with_defaults();
        let mut s = AnnotatedString::from_candidate(
            StringCandidate::new_simple(0, 13, "192.168.1.1".as_bytes().to_vec(), EncodingType::Ascii),
        );
        
        // This would normally be done through the pipeline
        for (pattern, tag) in &tagger.patterns {
            if pattern.is_match(&s.content) {
                assert_eq!(tag, &Tag::IpV4);
            }
        }
    }

    #[test]
    fn test_email_regex() {
        let tagger = RegexTagger::with_defaults();
        let email = "test@example.com";
        let mut s = AnnotatedString::from_candidate(
            StringCandidate::new_simple(0, email.len(), email.as_bytes().to_vec(), EncodingType::Ascii),
        );
        
        for (pattern, tag) in &tagger.patterns {
            if pattern.is_match(&s.content) {
                assert_eq!(tag, &Tag::Email);
            }
        }
    }

    #[test]
    fn test_tag_parsing() {
        assert_eq!(parse_tag_name("ipv4"), Some(Tag::IpV4));
        assert_eq!(parse_tag_name("IPv4"), Some(Tag::IpV4));
        assert_eq!(parse_tag_name("base64"), Some(Tag::Base64Decoded));
        assert_eq!(parse_tag_name("nonexistent"), None);
    }
}
