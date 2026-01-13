//! Document Hashing Module
//!
//! Provides SHA-256 hashing for documents with support for:
//! - Single document hashing
//! - Batch hashing (parallel when enabled)
//! - Streaming hashes for large files

mod hasher;

pub use hasher::{DocumentHasher, HashConfig, StreamingHasher};

use sha2::{Digest, Sha256};

/// Computes the SHA-256 hash of document bytes.
///
/// This is the primary hashing function used throughout the crypto engine.
/// The output is a 64-character lowercase hexadecimal string.
pub fn hash_document(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Computes the SHA-256 hash of a UTF-8 string.
///
/// Convenience wrapper around `hash_document` for string input.
pub fn hash_string(data: &str) -> String {
    hash_document(data.as_bytes())
}

/// Hashes multiple documents in a batch.
///
/// When the `parallel` feature is enabled, this uses Rayon for parallel processing,
/// providing significant speedup on multi-core systems.
#[cfg(feature = "parallel")]
pub fn batch_hash_documents(docs: &[&[u8]]) -> Vec<String> {
    use rayon::prelude::*;

    const PARALLEL_THRESHOLD: usize = 100;

    if docs.len() < PARALLEL_THRESHOLD {
        docs.iter().map(|doc| hash_document(doc)).collect()
    } else {
        docs.par_iter().map(|doc| hash_document(doc)).collect()
    }
}

/// Sequential batch hashing (when parallel feature is disabled)
#[cfg(not(feature = "parallel"))]
pub fn batch_hash_documents(docs: &[&[u8]]) -> Vec<String> {
    docs.iter().map(|doc| hash_document(doc)).collect()
}

/// Hashes two hex-encoded hashes together (for Merkle tree internal nodes).
pub fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();

    let left_bytes = hex::decode(left).expect("Invalid hex in left hash");
    let right_bytes = hex::decode(right).expect("Invalid hex in right hash");

    hasher.update(&left_bytes);
    hasher.update(&right_bytes);

    hex::encode(hasher.finalize())
}

/// Safe version of hash_pair that returns Result instead of panicking.
///
/// Use this when hashes come from untrusted sources.
pub fn safe_hash_pair(left: &str, right: &str) -> Result<String, hex::FromHexError> {
    let left_bytes = hex::decode(left).map_err(|_| create::error::HashError::InvalidHex {
        value: left.to_string(),
    })?;

    let right_bytes = hex::decode(right).map_err(|_| create::error::HashError::InvalidHex {
        value: right.to_string(),
    })?;

    let mut hasher = Sha256::new();
    hasher.update(&left_bytes);
    hasher.update(&right_bytes);

    Ok(hex::encode(hasher.finalize()))
}

/// Validates that a string is a valid SHA-256 hex hash.
pub fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase())
}

/// Normalizes a hash to lowercase.
/// Returns normalized hash or error if invalid format
pub fn normalize_hash(hash: &str) -> Result<String, create::error::HashError> {
    if hash.len() != 64 {
        return Err(create::error::HashError::InvalidLength {
            expected: 64,
            actual: hash.len(),
        });
    }

    let normalized = hash.to_lowercase();

    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(create::error::HashError::InvalidCharacters {
            invalid_chars: normalized
                .chars()
                .filter(|c| !c.is_ascii_hexdigit())
                .unwrap_or('?'),
            position: normalized
                .chars()
                .position(|c| !c.is_ascii_hexdigit())
                .unwrap_or(0),
        });
    }
    Ok(normalized)
}


