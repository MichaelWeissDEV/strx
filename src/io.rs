//! I/O module for handling file and stdin input with memory mapping

use anyhow::{Context, Result};
use memmap2::Mmap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Input source abstraction
/// For the first robust version:
/// - regular file -> mmap
/// - stdin -> read_to_end(Vec<u8>)
pub enum InputSource {
    /// Memory-mapped file
    Mmap(Mmap),
    /// Buffered data (for stdin)
    Buffer(Vec<u8>),
}

impl InputSource {
    /// Open an input source from a path or stdin
    pub fn open(path: Option<&str>) -> Result<Self> {
        match path {
            Some(p) => Self::from_file(p),
            None => Self::from_stdin(),
        }
    }

    /// Open a file and memory-map it
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(&path)
            .with_context(|| format!("Failed to open file: {}", path.as_ref().display()))?;

        // Safety: memmap2::Mmap::map is safe when the file is opened read-only
        // and we don't modify the mapping. The file handle is kept open
        // for the lifetime of the Mmap.
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to memory-map file: {}", path.as_ref().display()))?;

        Ok(InputSource::Mmap(mmap))
    }

    /// Read stdin to a buffer
    pub fn from_stdin() -> Result<Self> {
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .context("Failed to read from stdin")?;
        Ok(InputSource::Buffer(buffer))
    }

    /// Get a reference to the underlying data
    pub fn as_slice(&self) -> &[u8] {
        match self {
            InputSource::Mmap(mmap) => &mmap[..],
            InputSource::Buffer(buf) => &buf[..],
        }
    }

    /// Get the total size of the input
    pub fn size(&self) -> usize {
        match self {
            InputSource::Mmap(mmap) => mmap.len(),
            InputSource::Buffer(buf) => buf.len(),
        }
    }

    /// Check if the input source is memory-mapped
    pub fn is_mmap(&self) -> bool {
        matches!(self, InputSource::Mmap(_))
    }
}

/// Read entire file into a Vec<u8>
pub fn read_file_to_vec<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Check if a file path refers to stdin
pub fn is_stdin(path: &str) -> bool {
    path == "-" || path.is_empty()
}

/// Get context bytes around a given offset
/// This returns context_size bytes before and after the offset
pub fn get_context_bytes(
    source: &InputSource,
    offset: usize,
    context_size: usize,
) -> Option<Vec<u8>> {
    let data = source.as_slice();
    if offset >= data.len() {
        return None;
    }

    let start = offset.saturating_sub(context_size);
    let end = (offset + context_size).min(data.len());
    
    if start >= end {
        return None;
    }

    Some(data[start..end].to_vec())
}

/// Get hex dump context for a candidate string
/// Returns: context_size bytes BEFORE + full candidate + context_size bytes AFTER
pub fn get_hex_dump_context(
    data: &[u8],
    candidate_offset: usize,
    candidate_length: usize,
    context_size: usize,
) -> Option<Vec<u8>> {
    // Calculate start: candidate_offset - context_size
    let start = candidate_offset.saturating_sub(context_size);
    
    // Calculate end: candidate_offset + candidate_length + context_size
    let end = candidate_offset
        .saturating_add(candidate_length)
        .saturating_add(context_size)
        .min(data.len());
    
    if start >= end || start >= data.len() {
        return None;
    }
    
    Some(data[start..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "test content").unwrap();
        let path = file.path().to_str().unwrap();

        let source = InputSource::from_file(path).unwrap();
        assert!(source.is_mmap());
        assert_eq!(source.size(), 12);
    }

    #[test]
    fn test_as_slice() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "hello").unwrap();
        let path = file.path().to_str().unwrap();

        let source = InputSource::from_file(path).unwrap();
        let slice = source.as_slice();
        assert!(slice.starts_with(b"hello"));
    }

    #[test]
    fn test_is_stdin() {
        assert!(is_stdin("-"));
        assert!(is_stdin(""));
        assert!(!is_stdin("file.txt"));
    }
}
