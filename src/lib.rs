//! # strx - Strings Extended
//!
//! A high-performance, heuristic drop-in replacement for the Unix `strings` tool.
//! This library provides modular components for string extraction, heuristic analysis,
//! and formatted output.

pub mod cli;
pub mod extract;
pub mod heuristics;
pub mod io;
pub mod output;
pub mod scoring;
pub mod types;

// Re-export main types for convenience
pub use cli::Args;
pub use extract::{extract_strings, ExtractionConfig};
pub use heuristics::{HeuristicFilter, HeuristicPipeline, PipelineBuilder};
pub use io::InputSource;
pub use output::{OutputFormatter, OutputFormatterBuilder, ExtractionStats, print_summary};
pub use scoring::{ScoringEngine, ScoringConfig, sort_strings, process_and_score};
pub use types::{AnnotatedString, EncodingType, PipelineConfig, SortOrder, StringCandidate, Tag};
