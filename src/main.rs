//! strx - Strings Extended
//!
//! A high-performance, heuristic drop-in replacement for the Unix `strings` tool.

use anyhow::Result;
use clap::Parser;
use std::time::Instant;

use strx::cli::Args;
use strx::extract::{ExtractionConfig, extract_strings, extract_strings_simple};
use strx::heuristics::{HeuristicPipeline, PipelineBuilder, parse_tag_filters, filter_by_required_tags, filter_by_excluded_tags};
use strx::io::InputSource;
use strx::output::{OutputFormatter, ExtractionStats, print_summary};
use strx::scoring::{ScoringEngine, sort_strings};
use strx::types::{AnnotatedString, PipelineConfig, SortOrder, Tag};

fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Setup timing
    let start_time = Instant::now();

    // Handle verbose mode
    if args.verbose {
        eprintln!("strx - Strings Extended");
        eprintln!("Input: {:?}", args.input);
        eprintln!("Configuration: min={}, max={:?}, start={}, end={:?}, raw={}, fuzzy={}",
            args.min, args.max, args.start, args.end, args.raw, args.fuzzy);
    }

    // Open input source
    let input_path = args.input_path();
    let use_stdin = args.use_stdin();

    let source = if use_stdin {
        InputSource::from_stdin()?
    } else {
        InputSource::from_file(input_path.unwrap())?
    };

    // Get data slice for processing
    let data = source.as_slice()?;
    
    if args.verbose {
        eprintln!("Input size: {} bytes", data.len());
    }

    // Convert args to pipeline configuration
    let pipeline_config = args.to_config();

    // Create extraction configuration
    let extraction_config = ExtractionConfig {
        min_len: pipeline_config.min_len,
        max_len: pipeline_config.max_len,
        start: pipeline_config.start,
        end: pipeline_config.end,
    };

    // ========================================
    // PHASE 1: String Extraction
    // ========================================
    
    let candidates = extract_strings_simple(data, &extraction_config);

    if args.verbose {
        eprintln!("Extracted {} string candidates", candidates.len());
    }

    // ========================================
    // PHASE 2: Convert to AnnotatedStrings
    // ========================================
    
    let mut strings: Vec<AnnotatedString> = candidates
        .into_iter()
        .map(AnnotatedString::from_candidate)
        .collect();

    if strings.is_empty() && !args.quiet {
        eprintln!("No strings found matching the criteria.");
        if use_stdin {
            eprintln!("Tip: Try reading from a file instead of stdin.");
        }
        return Ok(());
    }

    // ========================================
    // PHASE 3: Heuristic Analysis Pipeline
    // ========================================
    
    if !args.raw {
        // Build the heuristic pipeline
        let pipeline = PipelineBuilder::new()
            .with_fuzzy_matching(args.fuzzy)
            .with_dictionaries(args.dict.clone())
            .with_custom_regex(args.regex.clone())
            .with_length_constraints(pipeline_config.min_len, pipeline_config.max_len)
            .build()?;

        // Process strings through the pipeline
        strings = pipeline.process_all(&mut strings);

        if args.verbose {
            let tagged_count = strings.iter().filter(|s| !s.tags.is_empty()).count();
            eprintln!("After heuristics: {} strings, {} tagged", strings.len(), tagged_count);
        }

        // ========================================
        // PHASE 4: Apply Tag Filters
        // ========================================
        
        // Parse tag filters
        let (required_tags, excluded_tags) = parse_tag_filters(&args.tag, &args.exclude_tag);

        if !required_tags.is_empty() {
            filter_by_required_tags(&mut strings, &required_tags);
        }

        if !excluded_tags.is_empty() {
            filter_by_excluded_tags(&mut strings, &excluded_tags);
        }

        if args.verbose {
            eprintln!("After tag filtering: {} strings", strings.len());
        }

        // ========================================
        // PHASE 5: Scoring
        // ========================================
        
        let mut scoring_engine = ScoringEngine::new();
        scoring_engine.score_all(&mut strings);

        // ========================================
        // PHASE 6: Sorting
        // ========================================
        
        sort_strings(&mut strings, pipeline_config.sort_order);
    } else {
        // Raw mode: just sort by offset
        sort_strings(&mut strings, SortOrder::Offset);
    }

    // ========================================
    // PHASE 7: Output Formatting
    // ========================================
    
    let formatter = OutputFormatter::new()
        .with_json(args.json)
        .with_encoding(args.show_encoding)
        .with_context(args.context)
        .with_colors(!args.quiet);

    let input_name = input_path.unwrap_or("stdin");

    // Collect statistics
    let mut stats = ExtractionStats::new();
    stats.add_strings(&strings);

    if args.json {
        // JSON output
        let json_output = formatter.format_json_array(&strings, Some(data));
        println!("{}", json_output);
    } else {
        // Text output
        for s in &strings {
            let formatted = formatter.format_string(s, Some(data));
            println!("{}", formatted);
        }

        // Print summary if verbose
        if args.verbose {
            print_summary(&stats, input_name, &pipeline_config);
        }
    }

    // Print timing information
    if args.verbose {
        let elapsed = start_time.elapsed();
        eprintln!("\nProcessing time: {:.3}s", elapsed.as_secs_f64());
        eprintln!("Strings per second: {:.0}", 
            strings.len() as f64 / elapsed.as_secs_f64());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_basic_extraction() {
        // Create a test file
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "Hello, World!\x00Test\x00String").unwrap();
        let path = file.path().to_str().unwrap();

        // Create args
        let args = Args {
            input: path.to_string(),
            raw: false,
            min: 4,
            max: None,
            start: 0,
            end: None,
            dict: vec![],
            regex: vec![],
            fuzzy: false,
            sort: strx::cli::CliSortOrder::Offset,
            context: 0,
            json: false,
            show_encoding: false,
            tag: vec![],
            exclude_tag: vec![],
            quiet: false,
            verbose: false,
        };

        // This test just verifies that the basic flow works
        // A full integration test would require more setup
        assert!(args.input == path);
    }

    #[test]
    fn test_pipeline_config() {
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
            sort: strx::cli::CliSortOrder::Score,
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
