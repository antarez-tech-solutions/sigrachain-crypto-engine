//! DocumentHasher - Configurable document hashing

use sha2::{Digest, Sha256};
use std::io::{BufReader, Read};

/// Configuration options for document hashing.
///
#[derive(Clone, Debug)]
pub struct HashConfig {
    /// Buffer size for streaming hashing (in bytes).
    pub buffer_size: usize,

    /// Whether to output lowercase hex (default: true)
    /// Note: Should always be true for SigraChain consistency
    pub lowercase_hex: bool,
}

impl Default for HashConfig {
    fn default() -> Self {
        Self {
            buffer_size: 8 * 1024, // 8 KB - good balance for most files
            lowercase_hex: true,
        }
    }
}

impl HashConfig {
    /// Creates a config optimized for large files.
    pub fn for_large_files() -> Self {
        Self {
            buffer_size: 64 * 1024, // 64 KB buffer
            lowercase_hex: true,
        }
    }

    /// Creates a config optimized for small files.
    pub fn for_small_files() -> Self {
        Self {
            buffer_size: 4 * 1024, // 4 KB buffer
            lowercase_hex: true,
        }
    }
}

