//! I/O module for handling file and stdin input with memory mapping

use anyhow::{Context, Result};
use memmap2::Mmap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

/// Input source abstraction
pub enum InputSource {
    /// Memory-mapped file
    Mmap(Mmap),
    /// Buffered stdin reader with sliding window
    Stdin(StdinReader),
}

/// Buffered stdin reader with sliding window for efficient access
pub struct StdinReader {
    reader: BufReader<io::Stdin>,
    buffer: Vec<u8>,
    position: usize,
    end: bool,
}

impl StdinReader {
    /// Create a new stdin reader
    pub fn new() -> Self {
        Self {
            reader: BufReader::new(io::stdin()),
            buffer: Vec::with_capacity(65536), // 64KB buffer
            position: 0,
            end: false,
        }
    }

    /// Read more data into the buffer
    fn read_more(&mut self) -> Result<()> {
        if self.end {
            return Ok(());
        }

        let mut temp_buf = vec![0u8; 65536];
        let bytes_read = self.reader.read(&mut temp_buf)?;
        
        if bytes_read == 0 {
            self.end = true;
            return Ok(());
        }

        temp_buf.truncate(bytes_read);
        self.buffer.extend_from_slice(&temp_buf);
        Ok(())
    }

    /// Get a reference to the buffer
    pub fn get_ref(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Set the position
    pub fn set_position(&mut self, pos: usize) -> Result<()> {
        if pos > self.buffer.len() {
            // Need to read more
            while pos > self.buffer.len() && !self.end {
                self.read_more()?;
            }
        }
        self.position = pos.min(self.buffer.len());
        Ok(())
    }

    /// Check if we've reached the end
    pub fn is_end(&self) -> bool {
        self.end && self.position >= self.buffer.len()
    }

    /// Get total size (if known)
    pub fn size(&self) -> Option<usize> {
        None // Stdin size is unknown
    }
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

        // Try to memory-map the file
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to memory-map file: {}", path.as_ref().display()))?;

        Ok(InputSource::Mmap(mmap))
    }

    /// Create a stdin reader
    pub fn from_stdin() -> Result<Self> {
        Ok(InputSource::Stdin(StdinReader::new()))
    }

    /// Get a reference to the underlying data
    pub fn as_slice(&self) -> Result<&[u8]> {
        match self {
            InputSource::Mmap(mmap) => Ok(&mmap[..]),
            InputSource::Stdin(reader) => Ok(reader.get_ref()),
        }
    }

    /// Get a reference to the underlying data with bounds checking
    pub fn as_slice_with_range(&self, start: usize, end: usize) -> Result<&[u8]> {
        let data = self.as_slice()?;
        let end = end.min(data.len());
        let start = start.min(end);
        Ok(&data[start..end])
    }

    /// Get the total size of the input
    pub fn size(&self) -> usize {
        match self {
            InputSource::Mmap(mmap) => mmap.len(),
            InputSource::Stdin(_) => 0, // Unknown for stdin
        }
    }

    /// Check if the input source is memory-mapped
    pub fn is_mmap(&self) -> bool {
        matches!(self, InputSource::Mmap(_))
    }

    /// Get the file path if available
    pub fn path(&self) -> Option<String> {
        None // Not tracked in current implementation
    }
}

/// Read entire stdin into a Vec<u8> (for small inputs or when mmap isn't feasible)
pub fn read_stdin_to_vec() -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    Ok(buffer)
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
pub fn get_context_bytes(
    source: &InputSource,
    offset: usize,
    context_size: usize,
) -> Result<Option<Vec<u8>>> {
    let data = source.as_slice()?;
    if offset >= data.len() {
        return Ok(None);
    }

    let _start = offset.saturating_sub(context_size);
    let _end = (offset + context_size).min(data.len());
    
    // We want to capture the string and context, but for context dump
    // we typically want bytes BEFORE and AFTER the string
    let context_start = offset.saturating_sub(context_size);
    let context_end = (offset + context_size).min(data.len());
    
    if context_start >= context_end {
        return Ok(None);
    }

    Ok(Some(data[context_start..context_end].to_vec()))
}

/// Utility to create a sliding window over the input
pub struct SlidingWindow<'a> {
    source: &'a InputSource,
    position: usize,
    window_size: usize,
}

impl<'a> SlidingWindow<'a> {
    pub fn new(source: &'a InputSource, window_size: usize) -> Self {
        Self {
            source,
            position: 0,
            window_size,
        }
    }

    pub fn next(&mut self) -> Result<Option<&'a [u8]>> {
        let data = self.source.as_slice()?;
        if self.position >= data.len() {
            return Ok(None);
        }

        let end = (self.position + self.window_size).min(data.len());
        let window = &data[self.position..end];
        self.position = end;
        
        Ok(Some(window))
    }

    pub fn position(&self) -> usize {
        self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_from_file() {
        // Create a temporary file
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "test content").unwrap();
        let path = file.path().to_str().unwrap();

        let source = InputSource::from_file(path).unwrap();
        assert!(source.is_mmap());
        assert_eq!(source.size(), 12); // "test content\n"
    }

    #[test]
    fn test_from_stdin() {
        let source = InputSource::from_stdin().unwrap();
        assert!(!source.is_mmap());
    }

    #[test]
    fn test_as_slice() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "hello").unwrap();
        let path = file.path().to_str().unwrap();

        let source = InputSource::from_file(path).unwrap();
        let slice = source.as_slice().unwrap();
        assert!(slice.starts_with(b"hello"));
    }

    #[test]
    fn test_is_stdin() {
        assert!(is_stdin("-"));
        assert!(is_stdin(""));
        assert!(!is_stdin("file.txt"));
    }
}
