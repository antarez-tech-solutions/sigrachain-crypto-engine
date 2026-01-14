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
    let left_bytes = hex::decode(left).map_err(|_| crate::error::HashError::InvalidHex {
        value: left.to_string(),
    })?;

    let right_bytes = hex::decode(right).map_err(|_| crate::error::HashError::InvalidHex {
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
pub fn normalize_hash(hash: &str) -> Result<String, crate::error::HashError> {
    if hash.len() != 64 {
        return Err(crate::error::HashError::InvalidLength {
            expected: 64,
            actual: hash.len(),
        });
    }

    let normalized = hash.to_lowercase();

    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(crate::error::HashError::InvalidCharacters {
            invalid_chars: normalized
                .chars()
                .filter(|c| !c.is_ascii_hexdigit())
                .next()
                .unwrap_or('?'),
            position: normalized
                .chars()
                .position(|c| !c.is_ascii_hexdigit())
                .unwrap_or(0),
        });
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known test vector: SHA-256 of empty string
    const EMPTY_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // Known test vector: SHA-256 of "Hello, World!"
    const HELLO_HASH: &str =
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn test_hash_empty() {
        let hash = hash_document(b"");
        assert_eq!(hash, EMPTY_HASH);
    }

    #[test]
    fn test_hash_hello() {
        let hash = hash_document(b"Hello, World!");
        assert_eq!(hash, HELLO_HASH);
    }

    #[test]
    fn test_hash_length() {
        let hash = hash_document(b"any content");
        assert_eq!(hash.len(), 64, "SHA-256 hash must be 64 hex characters");
    }

    #[test]
    fn test_normalize_lowercase() {
        let hash = hash_document(b"test document");
        assert!(
            hash.chars().all(|c| !c.is_uppercase()),
            "Hash should be lowercase"
        )
    }

    #[test]
    fn test_hash_deterministic() {
        let data = b"consistent data";
        let hash1 = hash_document(data);
        let hash2 = hash_document(data);
        assert_eq!(hash1, hash2, "Hashing the same data should yield the same result");
    }

    #[test]
    fn test_hash_avalanche() {
        let data1 = b"document version t";
        let data2 = b"document version T";

        let hash1 = hash_document(data1);
        let hash2 = hash_document(data2);

        // Count differing characters
        let diff_count = hash1
            .chars()
            .zip(hash2.chars())
            .filter(|(c1, c2)| c1 != c2)
            .count();

        // Avalanche effect: expect at least half the bits to differ
        assert!(
            diff_count >= 20,
            "Avalanche effect should cause ~50% change, got {} chars different",
            diff_count
        );    
    }

    #[test]
    fn test_batch_hasg() {
        let docs: Vec<&[u8]> = vec![b"doc1", b"doc2", b"doc3"];
        let hashes = batch_hash_documents(&docs);

        assert_eq!(hashes.len(), docs.len(), "Should hash all documents");
        assert_eq!(hashes[0], hash_document(b"doc1"));
        assert_eq!(hashes[1], hash_document(b"doc2"));  
        assert_eq!(hashes[2], hash_document(b"doc3"));  
    }

    #[test]
    fn test_hash_pair() {
        let left = hash_document(b"left node");
        let right = hash_document(b"right node");

        let parent_hash = hash_pair(&left, &right);

        assert_eq!(
            parent_hash,
            hash_document(&hex::decode(left).unwrap()
                .iter()
                .chain(&hex::decode(right).unwrap())
                .cloned()
                .collect::<Vec<u8>>())
        );
        assert_eq!(parent_hash.len(), 64);
        assert_ne!(parent_hash, left);
        assert_ne!(parent_hash, right);
    }
}




