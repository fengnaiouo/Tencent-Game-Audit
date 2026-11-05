//! Bounded-memory, streaming primitives for Tencent Game Audit.
//!
//! This crate is an experimental engine component. It is deliberately not yet
//! wired into the production Go scanner; parity and performance must be
//! demonstrated before changing the released executable's runtime path.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use sha2::{Digest, Sha256};

pub const DEFAULT_BUFFER_SIZE: usize = 4 * 1024 * 1024;
pub const MIN_BUFFER_SIZE: usize = 256 * 1024;
pub const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;
pub const DEFAULT_MEMORY_BUDGET: usize = 256 * 1024 * 1024;
const WORKER_OVERHEAD_ALLOWANCE: usize = 64 * 1024;

/// Resource limits for a streaming scan. The memory budget covers the
/// per-worker read buffer, pattern overlap, and a conservative fixed allowance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanConfig {
    pub buffer_size: usize,
    pub memory_budget_bytes: usize,
    pub max_workers: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            buffer_size: DEFAULT_BUFFER_SIZE,
            memory_budget_bytes: DEFAULT_MEMORY_BUDGET,
            max_workers: 8,
        }
    }
}

impl ScanConfig {
    /// Returns the maximum worker count allowed by both the configured limit
    /// and the memory budget. At least one worker must fit in the budget.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError::InvalidConfig`] when a setting is outside the
    /// supported range or the memory budget cannot fit one worker.
    pub fn effective_workers(&self, max_pattern_len: usize) -> Result<usize, ScanError> {
        if !(MIN_BUFFER_SIZE..=MAX_BUFFER_SIZE).contains(&self.buffer_size) {
            return Err(ScanError::InvalidConfig(format!(
                "buffer_size must be between {MIN_BUFFER_SIZE} and {MAX_BUFFER_SIZE} bytes"
            )));
        }
        if self.max_workers == 0 {
            return Err(ScanError::InvalidConfig(
                "max_workers must be at least 1".to_owned(),
            ));
        }
        let per_worker = self
            .buffer_size
            .saturating_add(max_pattern_len.saturating_sub(1))
            .saturating_add(WORKER_OVERHEAD_ALLOWANCE);
        let budget_workers = self.memory_budget_bytes / per_worker;
        if budget_workers == 0 {
            return Err(ScanError::InvalidConfig(format!(
                "memory budget must be at least {per_worker} bytes for one worker"
            )));
        }
        Ok(self.max_workers.min(budget_workers))
    }
}

/// A set of byte patterns compiled into a multi-pattern automaton.
#[derive(Debug)]
pub struct PatternSet {
    automaton: Option<AhoCorasick>,
    max_pattern_len: usize,
    pattern_count: usize,
}

impl PatternSet {
    /// Compiles non-empty IOC byte patterns into a multi-pattern automaton.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError::InvalidPattern`] if a pattern is empty, duplicated,
    /// or the automaton cannot be built. Callers that map one byte pattern to
    /// multiple rule IDs should resolve that mapping before constructing this set.
    pub fn new(patterns: &[Vec<u8>]) -> Result<Self, ScanError> {
        if patterns.iter().any(Vec::is_empty) {
            return Err(ScanError::InvalidPattern(
                "empty IOC patterns are not allowed".to_owned(),
            ));
        }
        let mut seen = HashSet::with_capacity(patterns.len());
        if patterns
            .iter()
            .any(|pattern| !seen.insert(pattern.as_slice()))
        {
            return Err(ScanError::InvalidPattern(
                "duplicate IOC patterns must be deduplicated before compilation".to_owned(),
            ));
        }
        let max_pattern_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let automaton = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::Standard)
                    .build(patterns)
                    .map_err(|error| ScanError::InvalidPattern(error.to_string()))?,
            )
        };
        Ok(Self {
            automaton,
            max_pattern_len,
            pattern_count: patterns.len(),
        })
    }

    #[must_use]
    pub fn max_pattern_len(&self) -> usize {
        self.max_pattern_len
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.pattern_count
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pattern_count == 0
    }
}

/// Aggregated match data; memory use is bounded by the number of IOC patterns,
/// not by the number of times a pattern occurs in a large file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatternMatch {
    pub pattern_id: usize,
    pub occurrences: u64,
    pub first_offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanSummary {
    pub bytes_read: u64,
    pub sha256: String,
    pub matches: Vec<PatternMatch>,
}

#[derive(Debug)]
pub enum ScanError {
    InvalidConfig(String),
    InvalidPattern(String),
    Io(io::Error),
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid scan configuration: {message}")
            }
            Self::InvalidPattern(message) => {
                write!(formatter, "invalid IOC pattern set: {message}")
            }
            Self::Io(error) => write!(formatter, "scan I/O error: {error}"),
        }
    }
}

impl Error for ScanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidConfig(_) | Self::InvalidPattern(_) => None,
        }
    }
}

impl From<io::Error> for ScanError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Streams a reader using a fixed-size buffer. It never reads the entire input
/// into memory, preserves matches spanning chunk boundaries, and hashes every
/// byte read. A read error is returned rather than silently truncating results.
///
/// # Errors
///
/// Returns [`ScanError::InvalidConfig`] for invalid resource settings and
/// [`ScanError::Io`] if the reader fails before reaching EOF.
pub fn scan_reader<R: Read>(
    mut reader: R,
    patterns: &PatternSet,
    config: &ScanConfig,
) -> Result<ScanSummary, ScanError> {
    config.effective_workers(patterns.max_pattern_len())?;

    let overlap_capacity = patterns.max_pattern_len().saturating_sub(1);
    // One allocation holds both the retained overlap and the next read. This
    // avoids a second buffer-sized allocation per worker.
    let mut window = vec![0_u8; config.buffer_size.saturating_add(overlap_capacity)];
    let mut tail_len = 0_usize;
    let mut digest = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut matches = vec![None::<PatternMatch>; patterns.len()];

    loop {
        let count = reader.read(&mut window[tail_len..tail_len + config.buffer_size])?;
        if count == 0 {
            break;
        }

        digest.update(&window[tail_len..tail_len + count]);
        let prior_bytes = bytes_read;
        bytes_read = bytes_read.saturating_add(count as u64);

        let window_len = tail_len + count;
        let window_offset = prior_bytes.saturating_sub(tail_len as u64);

        if let Some(automaton) = &patterns.automaton {
            for found in automaton.find_overlapping_iter(&window[..window_len]) {
                // A match is emitted only when its final byte belongs to this
                // read, preventing duplicates from the retained overlap.
                if found.end() <= tail_len {
                    continue;
                }
                let pattern_id = found.pattern().as_usize();
                let offset = window_offset.saturating_add(found.start() as u64);
                match &mut matches[pattern_id] {
                    Some(existing) => {
                        existing.occurrences = existing.occurrences.saturating_add(1);
                    }
                    slot @ None => {
                        *slot = Some(PatternMatch {
                            pattern_id,
                            occurrences: 1,
                            first_offset: offset,
                        });
                    }
                }
            }
        }

        let keep = overlap_capacity.min(window_len);
        if keep > 0 {
            window.copy_within(window_len - keep..window_len, 0);
        }
        tail_len = keep;
    }

    let matches = matches.into_iter().flatten().collect();
    Ok(ScanSummary {
        bytes_read,
        sha256: encode_hex(&digest.finalize()),
        matches,
    })
}

/// Opens and scans a file without buffering its full contents.
///
/// # Errors
///
/// Returns [`ScanError::Io`] for open/read failures and
/// [`ScanError::InvalidConfig`] for invalid resource settings.
pub fn scan_file(
    path: &Path,
    patterns: &PatternSet,
    config: &ScanConfig,
) -> Result<ScanSummary, ScanError> {
    scan_reader(File::open(path)?, patterns, config)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct GeneratedReader {
        remaining: usize,
        largest_request: Arc<AtomicUsize>,
    }

    impl Read for GeneratedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.largest_request
                .fetch_max(output.len(), Ordering::Relaxed);
            let count = self.remaining.min(output.len());
            output[..count].fill(b'G');
            self.remaining -= count;
            Ok(count)
        }
    }

    fn config() -> ScanConfig {
        ScanConfig {
            buffer_size: MIN_BUFFER_SIZE,
            memory_budget_bytes: 8 * MIN_BUFFER_SIZE,
            max_workers: 4,
        }
    }

    #[test]
    fn streams_hash_without_loading_entire_input() {
        let input = vec![b'a'; MIN_BUFFER_SIZE * 3 + 17];
        let patterns = PatternSet::new(&[]).unwrap();
        let result = scan_reader(Cursor::new(&input), &patterns, &config()).unwrap();
        assert_eq!(result.bytes_read, input.len() as u64);
        assert_eq!(result.sha256.len(), 64);
    }

    #[test]
    fn read_requests_never_exceed_the_configured_buffer() {
        let largest_request = Arc::new(AtomicUsize::new(0));
        let reader = GeneratedReader {
            remaining: MIN_BUFFER_SIZE * 12,
            largest_request: Arc::clone(&largest_request),
        };
        let patterns = PatternSet::new(&[b"not-present".to_vec()]).unwrap();
        let result = scan_reader(reader, &patterns, &config()).unwrap();
        assert_eq!(result.bytes_read, (MIN_BUFFER_SIZE * 12) as u64);
        assert_eq!(largest_request.load(Ordering::Relaxed), MIN_BUFFER_SIZE);
    }

    #[test]
    fn finds_pattern_that_crosses_a_buffer_boundary_once() {
        let mut input = vec![b'x'; MIN_BUFFER_SIZE + 8];
        input[MIN_BUFFER_SIZE - 2..MIN_BUFFER_SIZE + 3].copy_from_slice(b"K2F!!");
        let patterns = PatternSet::new(&[b"K2F!!".to_vec()]).unwrap();
        let result = scan_reader(Cursor::new(input), &patterns, &config()).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].first_offset, (MIN_BUFFER_SIZE - 2) as u64);
        assert_eq!(result.matches[0].occurrences, 1);
    }

    #[test]
    fn match_storage_is_aggregated_per_pattern() {
        let input = vec![b'A'; MIN_BUFFER_SIZE * 2];
        let patterns = PatternSet::new(&[b"A".to_vec()]).unwrap();
        let result = scan_reader(Cursor::new(input), &patterns, &config()).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].occurrences, (MIN_BUFFER_SIZE * 2) as u64);
        assert_eq!(result.matches[0].first_offset, 0);
    }

    #[test]
    fn memory_budget_limits_worker_count() {
        let patterns = PatternSet::new(&[b"a-longer-pattern".to_vec()]).unwrap();
        let mut cfg = config();
        cfg.memory_budget_bytes =
            2 * (cfg.buffer_size + patterns.max_pattern_len() + WORKER_OVERHEAD_ALLOWANCE);
        assert_eq!(
            cfg.effective_workers(patterns.max_pattern_len()).unwrap(),
            2
        );
    }

    #[test]
    fn rejects_a_budget_that_cannot_fit_one_worker() {
        let patterns = PatternSet::new(&[b"ioc".to_vec()]).unwrap();
        let mut cfg = config();
        cfg.memory_budget_bytes = 1;
        assert!(cfg.effective_workers(patterns.max_pattern_len()).is_err());
    }

    #[test]
    fn rejects_empty_patterns() {
        assert!(PatternSet::new(&[Vec::new()]).is_err());
    }

    #[test]
    fn rejects_duplicate_patterns() {
        assert!(PatternSet::new(&[b"same".to_vec(), b"same".to_vec()]).is_err());
    }

    #[test]
    fn sha256_matches_known_vector() {
        let patterns = PatternSet::new(&[]).unwrap();
        let result = scan_reader(Cursor::new(b"abc"), &patterns, &config()).unwrap();
        assert_eq!(
            result.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
