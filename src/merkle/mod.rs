//! Merkle Tree Module
//!
//! Provides efficient Merkle tree construction for batch document anchoring.
//!
//! # Overview
//!
//! A Merkle tree allows combining thousands of document hashes into a single
//! root hash. This root can be anchored on-chain, and later any individual
//! document can be verified against it using a compact proof.

mod builder;
mod tree;

pub use tree::{MerkleNode, MerkleTree, TreeMetadata};

use crate::error::MerkleError;
use crate::hashing::is_valid_hash;
use serde::{Deserialize, Serialize};

/// Strategies for handling non-power-of-2 leaf counts.
///
/// Merkle trees work best with power-of-2 leaf counts. When you have
/// a different number (e.g., 3 documents), padding is needed.
///
/// # Strategies
///
/// - `DuplicateLast` (default): Copy the last hash to fill gaps
/// - `ZeroPadding`: Use all-zero hashes
/// - `EmptyHash`: Use SHA-256 of empty string
/// - `None`: No padding (creates unbalanced tree)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PaddingStrategy {
    /// Duplicate the last leaf until power of 2 (default)
    #[default]
    DuplicateLast,

    /// Use zero hash (64 zeros) for padding
    ZeroPadding,

    /// Use hash of empty string for padding
    EmptyHash,

    /// No padding - creates potentially unbalanced tree
    None,
}

impl PaddingStrategy {
    /// Returns the padding hash for this strategy.
    ///
    /// # Arguments
    ///
    /// * `last_hash` - The last actual hash (used for DuplicateLast)
    pub fn padding_hash(&self, last_hash: &str) -> String {
        match self {
            Self::DuplicateLast => last_hash.to_string(),
            Self::ZeroPadding => "0".repeat(64),
            Self::EmptyHash => {
                // SHA-256 of empty string
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
            }
            Self::None => panic!("None padding strategy should not request padding hash"),
        }
    }

    /// Returns true if this strategy requires padding.
    pub fn requires_padding(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Builds a Merkle tree from a list of document hashes.
///
/// This is the primary entry point for tree construction.
///
/// # Arguments
///
/// * `hashes` - Vector of SHA-256 hashes (64-character hex strings)
///
/// # Returns
///
/// A `MerkleTree` containing the root and all intermediate nodes
///
/// # Errors
///
/// - `MerkleError::EmptyLeaves` if the hash list is empty
/// - `MerkleError::InvalidHash` if any hash is not valid SHA-256 format
pub fn build_merkle_tree(_hashes: Vec<String>) -> Result<MerkleTree, MerkleError> {
    todo!("Builder implementation comes on Day 3")
}

/// Validates that all hashes in a slice are valid SHA-256 format.
pub(crate) fn validate_hashes(hashes: &[String]) -> Result<(), MerkleError> {
    for (index, hash) in hashes.iter().enumerate() {
        if !is_valid_hash(hash) {
            return Err(MerkleError::InvalidHash {
                index,
                hash: hash.clone(),
            });
        }
    }
    Ok(())
}
