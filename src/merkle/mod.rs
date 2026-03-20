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

pub use builder::MerkleTreeBuilder;
pub use tree::{CompactTree, MerkleNode, MerkleTree, TreeMetadata};

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
            Self::EmptyHash => crate::hashing::hash_document(b""),
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
pub fn build_merkle_tree(hashes: Vec<String>) -> Result<MerkleTree, MerkleError> {
    MerkleTreeBuilder::new()
        .add_hashes(hashes)
        .with_padding(PaddingStrategy::DuplicateLast)
        .build()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_document;

    fn sample_hashes(n: usize) -> Vec<String> {
        (0..n).map(|i| hash_document(&i.to_le_bytes())).collect()
    }

    #[test]
    fn test_build_single_leaf() {
        let hashes = sample_hashes(1);
        let tree = build_merkle_tree(hashes.clone()).unwrap();

        assert_eq!(tree.leaf_count(), 1);
        // Single leaf tree: root equals the leaf
        assert_eq!(tree.root(), &hashes[0]);
    }

    #[test]
    fn test_build_two_leaves() {
        let hashes = sample_hashes(2);
        let tree = build_merkle_tree(hashes.clone()).unwrap();

        assert_eq!(tree.leaf_count(), 2);
        assert_ne!(tree.root(), &hashes[0]);
        assert_ne!(tree.root(), &hashes[1]);
    }

    #[test]
    fn test_empty_leaves_error() {
        let result = build_merkle_tree(Vec::new());
        assert!(matches!(result, Err(MerkleError::EmptyLeaves)));
    }

    #[test]
    fn test_invalid_hash_error() {
        let hashes = vec!["not_a_valid_hash".to_string()];
        let result = build_merkle_tree(hashes);
        assert!(matches!(result, Err(MerkleError::InvalidHash { .. })));
    }

    #[test]
    fn test_build_power_of_two() {
        for n in [2, 4, 8, 16, 32] {
            let hashes = sample_hashes(n);
            let tree = build_merkle_tree(hashes).unwrap();
            assert_eq!(tree.leaf_count(), n);
        }
    }

    #[test]
    fn test_build_non_power_of_two() {
        for n in [3, 5, 7, 9, 15, 17, 100, 1000] {
            let hashes = sample_hashes(n);
            let tree = build_merkle_tree(hashes).unwrap();
            assert_eq!(tree.leaf_count(), n);
        }
    }

    #[test]
    fn test_tree_deterministic() {
        let hashes = sample_hashes(10);
        let tree1 = build_merkle_tree(hashes.clone()).unwrap();
        let tree2 = build_merkle_tree(hashes).unwrap();

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_tree_contains() {
        let hashes = sample_hashes(5);
        let tree = build_merkle_tree(hashes.clone()).unwrap();

        for hash in &hashes {
            assert!(tree.contains(hash), "Tree should contain {}", hash);
        }

        let missing = hash_document(b"not in tree");
        assert!(!tree.contains(&missing));
    }

    #[test]
    fn test_padding_strategy_duplicate() {
        let strategy = PaddingStrategy::DuplicateLast;
        let last = "a".repeat(64);
        assert_eq!(strategy.padding_hash(&last), last);
    }

    #[test]
    fn test_padding_strategy_zero() {
        let strategy = PaddingStrategy::ZeroPadding;
        let padding = strategy.padding_hash("ignored");
        assert_eq!(padding, "0".repeat(64));
    }

    #[test]
    fn test_padding_strategy_empty() {
        let strategy = PaddingStrategy::EmptyHash;
        let padding = strategy.padding_hash("ignored");
        assert_eq!(
            padding,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
