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

/// Configurable document hasher with streaming support.
/// While `hash_document()` is sufficient for most use cases, `DocumentHasher`
/// provides additional features:
///
/// - Custom buffer sizes for memory optimization
/// - Streaming hashing for files too large to fit in memory
/// - Progress callbacks for large operations
#[derive(Clone, Debug)]
pub struct DocumentHasher {
    config: HashConfig,
}

impl DocumentHasher {
    /// Creates a new DocumentHasher with the default configuration.
    pub fn new() -> Self {
        Self {
            config: HashConfig::default(),
        }
    }

    /// Creates a new DocumentHasher with custom configuration.
    pub fn with_config(config: HashConfig) -> Self {
        Self { config }
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &HashConfig {
        &self.config
    }

    /// Hashes raw bytes and returns hex string.
    pub fn hash_bytes(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();

        if self.config.lowercase_hex {
            hex::encode(result)
        } else {
            hex::encode_upper(result)
        }
    }

    /// Hashes a string (UTF-8 encoded).
    pub fn hash_string(&self, data: &str) -> String {
        self.hash_bytes(data.as_bytes())
    }

    /// Hashes data from a reader (for large files).
    /// This method streams data through the hasher in chunks, making it
    /// suitable for files too large to fit in memory.
    pub fn hash_reader<R: Read>(&self, reader: R) -> std::io::Result<String> {
        let mut hasher = Sha256::new();
        let mut buf_reader = BufReader::with_capacity(self.config.buffer_size, reader);
        let mut buffer = vec![0; self.config.buffer_size];

        loop {
            let bytes_read = buf_reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();

        Ok(if self.config.lowercase_hex {
            hex::encode(result)
        } else {
            hex::encode_upper(result)
        })
    }

    /// Hashes data from a reader with progress callback.
    pub fn hash_reader_with_progress<R, F>(
        &self,
        reader: R,
        total_size: u64,
        mut on_progress: F,
    ) -> std::io::Result<String> 
    where
        R: Read,
        F: FnMut(u64, u64),
    {
        let mut hasher = Sha256::new();
        let mut buf_reader = BufReader::with_capacity(self.config.buffer_size, reader);
        let mut buffer = vec![0; self.config.buffer_size];
        let mut bytes_processed: u64 = 0;

        loop {
            let bytes_read = buf_reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            bytes_processed += bytes_read as u64;
            on_progress(bytes_processed, total_size);
        }

        let result = hasher.finalize();

        Ok(if self.config.lowercase_hex {
            hex::encode(result)
        } else {
            hex::encode_upper(result)
        })
    }
}

impl Default for DocumentHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// STREAMING HASHER
/// Incremental hasher for streaming document processing.
///
/// Use this when document data arrives in chunks (network streaming, chunked
/// uploads, etc.).
pub struct StreamingHasher {
    hasher: Sha256,
    bytes_processed: u64,
}

impl StreamingHasher {
    /// Creates a new StreamingHasher.
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes_processed: 0,
        }
    }

    /// Adds a chunk of data to the hash.
    ///
    /// Can be called multiple times with successive chunks.
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        self.bytes_processed += chunk.len() as u64;
    }

    /// Returns the number of bytes processed so far.
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Finalizes the hash and returns the result.
    ///
    /// This consumes the hasher. To reuse, create a new `StreamingHasher`.
    pub fn finalize(self) -> String {
        hex::encode(self.hasher.finalize())
    }

    /// Resets the hasher to its initial state.
    ///
    /// This allows reusing the same hasher instance for multiple documents.
    pub fn reset(&mut self) {
        self.hasher = Sha256::new();
        self.bytes_processed = 0;
    }
}

impl Default for StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hasher_default() {
        let hasher = DocumentHasher::default();
        let hash = hasher.hash_bytes(b"test");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hasher_custom_config() {
        let config = HashConfig {
            buffer_size: 1024,
            lowercase_hex: false,
        };
        let hasher = DocumentHasher::with_config(config);
        let hash = hasher.hash_string("another test");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn test_hasher_consistent_with_hash_document()  {
        let hasher = DocumentHasher::new();
        let data = b"consistent hashing test";
     
        let hash1 = hasher.hash_bytes(data);
        let hash2 =  crate::hashing::hash_document(data);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_reader() {
        use std::io::Cursor;

        let hasher = DocumentHasher::new();
        let data = b"streaming hash test data";

        // Create an in-memory reader
        let cursor = Cursor::new(data);
        let hash1 = hasher.hash_reader(cursor).unwrap();

        // Should match direct hash
        let hash2 = hasher.hash_bytes(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_streaming_hasher() {
        let mut streaming_hasher = StreamingHasher::new();

        // Feed in chuncks
        streamer.update(b"hello");
        streamer.update(b" ");
        streamer.update(b"world");

        assert_eq!(streamer.bytes_processed(), 11);

        let hash = streamer.finalize();

         // Should match single-shot hash
        let expected = crate::hashing::hash_document(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_streaming_hasher_reset() {
        let mut streaming = StreamingHasher::new();

        streaming.update(b"first document");
        streaming.reset();

        // After reset, should behave like new hasher
        let hash = streaming.finalize();

        let expected =  crate::hashing::hash_document(b"second document");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_large_file_config() {
        let config = HashConfig::for_large_files();
        assert_eq!(config.buffer_size, 64 * 1024);
        assert!(config.lowercase_hex);
    }

    #[test]
    fn test_hash_reader_with_progress() {
        use std::io::Cursor;
        use std::sync::atomic::{AtomicU64, Ordering};

        let hasher = DocumentHasher::with_config(HashConfig {
            buffer_size: 4
            lowercase_hex: true,
        });

        let data = b"progress callback test data";
        let cursor = Cursor::new(data);
        let total_size = data.len() as u64;

        let progress_calls = AtomicU64::new(0);
        let last_processed = AtomicU64::new(0);
        
        let hash = hasher
            .hash_reader_with_progress(cursor, total_size, |processed, total| {
                progress_calls.fetch_add(1, Ordering::SeqCst);
                last_processed.store(processed, Ordering::SeqCst);
                assert_eq!(total, total_size);
            })
            .unwrap();

        // Progress should have been called
        assert!(progress_calls.load(Ordering::SeqCst) > 0);

        // Final processed bytes should equal total size
        assert_eq!(last_processed.load(Ordering::SeqCst), total_size);
        
        // Hash should be correct
        let expected = crate::hashing::hash_document(data);
        assert_eq!(hash, expected);
    }
}
