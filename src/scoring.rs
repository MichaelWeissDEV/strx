//! Scoring engine for ranking extracted strings

use crate::types::{AnnotatedString, Tag};
use std::collections::HashMap;

/// Scoring configuration
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    /// Base score per character
    pub base_per_char: f32,
    /// Bonus for IoC regex matches
    pub ioc_bonus: f32,
    /// Bonus for custom regex matches
    pub regex_bonus: f32,
    /// Bonus for dictionary matches
    pub dictionary_bonus: f32,
    /// Penalty for high entropy
    pub entropy_penalty: f32,
    /// Bonus for smart peeking (Base64/Hex decoded)
    pub smart_peek_bonus: f32,
    /// Bonus for code snippets
    pub code_bonus: f32,
    /// Bonus for AI tokens
    pub ai_bonus: f32,
    /// Bonus for crypto keys
    pub crypto_bonus: f32,
    /// Bonus for hashes
    pub hash_bonus: f32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            base_per_char: 0.1,
            ioc_bonus: 50.0,
            regex_bonus: 45.0,
            dictionary_bonus: 100.0,
            entropy_penalty: -20.0,
            smart_peek_bonus: 30.0,
            code_bonus: 20.0,
            ai_bonus: 25.0,
            crypto_bonus: 40.0,
            hash_bonus: 15.0,
        }
    }
}

impl ScoringConfig {
    /// Create a high-contrast scoring config for security analysis
    pub fn security_focused() -> Self {
        Self {
            base_per_char: 0.05,
            ioc_bonus: 75.0,
            regex_bonus: 75.0, // High bonus for IoCs
            dictionary_bonus: 50.0,
            entropy_penalty: -10.0,
            smart_peek_bonus: 40.0,
            code_bonus: 10.0,
            ai_bonus: 5.0,
            crypto_bonus: 100.0, // Very high bonus for crypto keys
            hash_bonus: 30.0,
        }
    }

    /// Create a balanced scoring config
    pub fn balanced() -> Self {
        Self::default()
    }

    /// Create a config focused on finding interesting content
    pub fn interesting_focused() -> Self {
        Self {
            base_per_char: 0.2,
            ioc_bonus: 60.0,
            regex_bonus: 60.0,
            dictionary_bonus: 80.0,
            entropy_penalty: -30.0,
            smart_peek_bonus: 50.0,
            code_bonus: 40.0,
            ai_bonus: 45.0,
            crypto_bonus: 80.0,
            hash_bonus: 20.0,
        }
    }
}

/// Scoring engine
pub struct ScoringEngine {
    config: ScoringConfig,
    // Cache for tag bonuses
    tag_bonuses: HashMap<Tag, f32>,
}

impl ScoringEngine {
    /// Create a new scoring engine with default configuration
    pub fn new() -> Self {
        Self::with_config(ScoringConfig::default())
    }

    /// Create a scoring engine with custom configuration
    pub fn with_config(config: ScoringConfig) -> Self {
        let mut tag_bonuses = HashMap::new();

        // IoC tags
        tag_bonuses.insert(Tag::IpV4, config.ioc_bonus);
        tag_bonuses.insert(Tag::IpV6, config.ioc_bonus);
        tag_bonuses.insert(Tag::Url, config.ioc_bonus);
        tag_bonuses.insert(Tag::Email, config.ioc_bonus);

        // Dictionary
        tag_bonuses.insert(Tag::DictionaryMatch, config.dictionary_bonus);
        tag_bonuses.insert(Tag::RegexMatch, config.regex_bonus);
        tag_bonuses.insert(Tag::FuzzyMatch, config.dictionary_bonus * 0.7); // Slightly less

        // Smart peeking
        tag_bonuses.insert(Tag::Base64Decoded, config.smart_peek_bonus);
        tag_bonuses.insert(Tag::HexDecoded, config.smart_peek_bonus);

        // Code
        tag_bonuses.insert(Tag::CodeSnippet, config.code_bonus);
        tag_bonuses.insert(Tag::AiToken, config.ai_bonus);

        // Crypto
        tag_bonuses.insert(Tag::CryptoKey, config.crypto_bonus);
        tag_bonuses.insert(Tag::Md5Hash, config.hash_bonus);
        tag_bonuses.insert(Tag::Sha1Hash, config.hash_bonus);
        tag_bonuses.insert(Tag::Sha256Hash, config.hash_bonus);

        // Entropy
        tag_bonuses.insert(Tag::HighEntropy, config.entropy_penalty);
        // Low entropy doesn't need a bonus as it's the default

        Self {
            config,
            tag_bonuses,
        }
    }

    /// Score a single annotated string
    pub fn score(&self, s: &mut AnnotatedString) {
        let mut score = 0.0f32;

        // Base score: byte length
        score += s.candidate.byte_len as f32 * self.config.base_per_char;

        // Apply tag bonuses
        for tag in &s.tags {
            if let Some(bonus) = self.tag_bonuses.get(tag) {
                score += bonus;
            }
        }

        // Additional modifiers based on content
        score += self.additional_modifiers(s);

        s.score = score;
    }

    /// Additional scoring modifiers based on content analysis
    fn additional_modifiers(&self, s: &AnnotatedString) -> f32 {
        let mut bonus = 0.0f32;

        // Check for multiple IoC patterns
        let ioc_tags = [Tag::IpV4, Tag::IpV6, Tag::Url, Tag::Email];
        let ioc_count = s.tags.iter().filter(|t| ioc_tags.contains(t)).count();
        if ioc_count > 1 {
            bonus += 20.0 * ioc_count as f32; // Extra bonus for multiple IoCs
        }

        // Check for hash + dictionary (potential password)
        if s.has_any_tag(&[Tag::Md5Hash, Tag::Sha1Hash, Tag::Sha256Hash])
            && s.has_any_tag(&[Tag::DictionaryMatch, Tag::FuzzyMatch])
        {
            bonus += 25.0;
        }

        // Check for code + AI (potential model code)
        if s.has_any_tag(&[Tag::CodeSnippet, Tag::AiToken]) {
            bonus += 10.0;
        }

        bonus
    }

    /// Score multiple strings
    pub fn score_all(&self, strings: &mut [AnnotatedString]) {
        for s in strings {
            self.score(s);
        }
    }

    /// Sort strings by score (descending)
    pub fn sort_by_score(strings: &mut [AnnotatedString]) {
        strings.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Get the highest scoring string
    pub fn get_best_match(strings: &[AnnotatedString]) -> Option<&AnnotatedString> {
        strings.iter().max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Normalize scores to 0-100 range
    pub fn normalize_scores(strings: &mut [AnnotatedString]) {
        if strings.is_empty() {
            return;
        }

        let min_score = strings
            .iter()
            .map(|s| s.score)
            .fold(f32::INFINITY, f32::min);
        let max_score = strings
            .iter()
            .map(|s| s.score)
            .fold(f32::NEG_INFINITY, f32::max);

        if min_score == max_score {
            return; // All scores are the same
        }

        for s in strings.iter_mut() {
            s.score = ((s.score - min_score) / (max_score - min_score)) * 100.0;
        }
    }
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Sort strings by various criteria
pub fn sort_strings(strings: &mut [AnnotatedString], sort_order: crate::types::SortOrder) {
    match sort_order {
        crate::types::SortOrder::Offset => {
            strings.sort_by_key(|a| a.candidate.offset);
        }
        crate::types::SortOrder::LengthAsc => {
            strings.sort_by_key(|a| a.candidate.byte_len);
        }
        crate::types::SortOrder::LengthDesc => {
            strings.sort_by_key(|a| std::cmp::Reverse(a.candidate.byte_len));
        }
        crate::types::SortOrder::Score => {
            strings.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        crate::types::SortOrder::Alphabetical => {
            strings.sort_by(|a, b| a.content.cmp(&b.content));
        }
    }
}

/// Filter and score pipeline
pub fn process_and_score(
    strings: Vec<AnnotatedString>,
    sort_order: crate::types::SortOrder,
) -> Vec<AnnotatedString> {
    let mut strings = strings;
    let engine = ScoringEngine::new();

    engine.score_all(&mut strings);
    sort_strings(&mut strings, sort_order);

    strings
}

/// Apply tag-based scoring modifiers
pub fn apply_tag_scores(strings: &mut [AnnotatedString], config: &ScoringConfig) {
    for s in strings {
        let mut score = s.candidate.byte_len as f32 * config.base_per_char;

        for tag in &s.tags {
            match tag {
                Tag::IpV4 | Tag::IpV6 | Tag::Url | Tag::Email => {
                    score += config.ioc_bonus;
                }
                Tag::DictionaryMatch => {
                    score += config.dictionary_bonus;
                }
                Tag::RegexMatch => {
                    score += config.regex_bonus;
                }
                Tag::FuzzyMatch => {
                    score += config.dictionary_bonus * 0.7;
                }
                Tag::Base64Decoded | Tag::HexDecoded => {
                    score += config.smart_peek_bonus;
                }
                Tag::CodeSnippet => {
                    score += config.code_bonus;
                }
                Tag::AiToken => {
                    score += config.ai_bonus;
                }
                Tag::CryptoKey => {
                    score += config.crypto_bonus;
                }
                Tag::Md5Hash | Tag::Sha1Hash | Tag::Sha256Hash => {
                    score += config.hash_bonus;
                }
                Tag::HighEntropy => {
                    score += config.entropy_penalty;
                }
                _ => {}
            }
        }

        s.score = score;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EncodingType, StringCandidate};

    #[test]
    fn test_scoring_engine() {
        let engine = ScoringEngine::new();

        // Create a test string with various tags
        let mut s = AnnotatedString {
            candidate: StringCandidate::new(0, 15, 15, EncodingType::Ascii),
            score: 0.0,
            tags: Vec::new(),
            content: "test@example.com".to_string(),
            derived: Vec::new(),
        };
        s.add_tag(Tag::Email);
        s.add_tag(Tag::DictionaryMatch);

        engine.score(&mut s);

        // Should have base score + ioc bonus + dictionary bonus
        let expected_min = 15.0 * 0.1 + 50.0 + 100.0;
        assert!(s.score >= expected_min);
    }

    #[test]
    fn test_sort_by_score() {
        let mut strings = vec![
            {
                let mut s = AnnotatedString {
                    candidate: StringCandidate::new(0, 5, 5, EncodingType::Ascii),
                    score: 0.0,
                    tags: Vec::new(),
                    content: "short".to_string(),
                    derived: Vec::new(),
                };
                s.score = 10.0;
                s
            },
            {
                let mut s = AnnotatedString {
                    candidate: StringCandidate::new(5, 10, 10, EncodingType::Ascii),
                    score: 0.0,
                    tags: Vec::new(),
                    content: "medium".to_string(),
                    derived: Vec::new(),
                };
                s.score = 50.0;
                s
            },
            {
                let mut s = AnnotatedString {
                    candidate: StringCandidate::new(15, 15, 15, EncodingType::Ascii),
                    score: 0.0,
                    tags: Vec::new(),
                    content: "long".to_string(),
                    derived: Vec::new(),
                };
                s.score = 30.0;
                s
            },
        ];

        ScoringEngine::sort_by_score(&mut strings);

        assert_eq!(strings[0].score, 50.0);
        assert_eq!(strings[1].score, 30.0);
        assert_eq!(strings[2].score, 10.0);
    }

    #[test]
    fn test_get_best_match() {
        let strings = vec![
            {
                let mut s = AnnotatedString {
                    candidate: StringCandidate::new(0, 5, 5, EncodingType::Ascii),
                    score: 0.0,
                    tags: Vec::new(),
                    content: "short".to_string(),
                    derived: Vec::new(),
                };
                s.score = 10.0;
                s
            },
            {
                let mut s = AnnotatedString {
                    candidate: StringCandidate::new(5, 10, 10, EncodingType::Ascii),
                    score: 0.0,
                    tags: Vec::new(),
                    content: "medium".to_string(),
                    derived: Vec::new(),
                };
                s.score = 50.0;
                s
            },
            {
                let mut s = AnnotatedString {
                    candidate: StringCandidate::new(15, 15, 15, EncodingType::Ascii),
                    score: 0.0,
                    tags: Vec::new(),
                    content: "long".to_string(),
                    derived: Vec::new(),
                };
                s.score = 30.0;
                s
            },
        ];

        let best = ScoringEngine::get_best_match(&strings);
        assert!(best.is_some());
        assert_eq!(best.unwrap().score, 50.0);
    }

    #[test]
    fn test_normalize_scores() {
        let mut strings = vec![
            {
                let mut s = AnnotatedString {
                    candidate: StringCandidate::new(0, 5, 5, EncodingType::Ascii),
                    score: 0.0,
                    tags: Vec::new(),
                    content: "short".to_string(),
                    derived: Vec::new(),
                };
                s.score = 0.0;
                s
            },
            {
                let mut s = AnnotatedString {
                    candidate: StringCandidate::new(5, 10, 10, EncodingType::Ascii),
                    score: 0.0,
                    tags: Vec::new(),
                    content: "medium".to_string(),
                    derived: Vec::new(),
                };
                s.score = 50.0;
                s
            },
            {
                let mut s = AnnotatedString {
                    candidate: StringCandidate::new(15, 15, 15, EncodingType::Ascii),
                    score: 0.0,
                    tags: Vec::new(),
                    content: "long".to_string(),
                    derived: Vec::new(),
                };
                s.score = 100.0;
                s
            },
        ];

        ScoringEngine::normalize_scores(&mut strings);

        // Check that scores are normalized to 0-100 range
        for s in &strings {
            assert!(s.score >= 0.0 && s.score <= 100.0);
        }
    }

    #[test]
    fn test_sort_by_length() {
        use crate::types::SortOrder;

        let mut strings = vec![
            AnnotatedString {
                candidate: StringCandidate::new(0, 10, 10, EncodingType::Ascii),
                score: 0.0,
                tags: Vec::new(),
                content: "medium".to_string(),
                derived: Vec::new(),
            },
            AnnotatedString {
                candidate: StringCandidate::new(5, 5, 5, EncodingType::Ascii),
                score: 0.0,
                tags: Vec::new(),
                content: "short".to_string(),
                derived: Vec::new(),
            },
            AnnotatedString {
                candidate: StringCandidate::new(15, 15, 15, EncodingType::Ascii),
                score: 0.0,
                tags: Vec::new(),
                content: "long".to_string(),
                derived: Vec::new(),
            },
        ];

        sort_strings(&mut strings, SortOrder::LengthDesc);

        assert_eq!(strings[0].candidate.byte_len, 15);
        assert_eq!(strings[1].candidate.byte_len, 10);
        assert_eq!(strings[2].candidate.byte_len, 5);
    }

    #[test]
    fn test_sort_by_offset() {
        use crate::types::SortOrder;

        let mut strings = vec![
            AnnotatedString {
                candidate: StringCandidate::new(15, 10, 10, EncodingType::Ascii),
                score: 0.0,
                tags: Vec::new(),
                content: "late".to_string(),
                derived: Vec::new(),
            },
            AnnotatedString {
                candidate: StringCandidate::new(0, 10, 10, EncodingType::Ascii),
                score: 0.0,
                tags: Vec::new(),
                content: "first".to_string(),
                derived: Vec::new(),
            },
            AnnotatedString {
                candidate: StringCandidate::new(5, 10, 10, EncodingType::Ascii),
                score: 0.0,
                tags: Vec::new(),
                content: "middle".to_string(),
                derived: Vec::new(),
            },
        ];

        sort_strings(&mut strings, SortOrder::Offset);

        assert_eq!(strings[0].candidate.offset, 0);
        assert_eq!(strings[1].candidate.offset, 5);
        assert_eq!(strings[2].candidate.offset, 15);
    }

    #[test]
    fn test_security_focused_config() {
        let config = ScoringConfig::security_focused();
        assert_eq!(config.crypto_bonus, 100.0);
        assert_eq!(config.ioc_bonus, 75.0);
    }
}
