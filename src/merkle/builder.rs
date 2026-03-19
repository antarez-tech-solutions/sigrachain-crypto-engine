//! MerkleTreeBuilder - Fluent builder pattern for tree construction

use super::tree::{MerkleNode, MerkleTree, TreeMetadata};
use super::{validate_hashes, PaddingStrategy};
use crate::error::MerkleError;

/// Maximum number of leaves allowed in a tree.
///
/// With 2^20 leaves (~1 million), the tree has:
/// - Height: 21 levels
/// - Memory: ~100MB for nodes
/// - Build time: ~10 seconds
pub const MAX_TREE_SIZE: usize = 1 << 20; // ~1 million

/// Builder for constructing Merkle trees.
///
/// Provides a fluent interface for tree construction with configurable options.
#[derive(Debug, Default)]
pub struct MerkleTreeBuilder {
    hashes: Vec<String>,
    padding_strategy: PaddingStrategy,
}

impl MerkleTreeBuilder {
    /// Creates a new empty builder.
    pub fn new() -> Self {
        Self {
            hashes: Vec::new(),
            padding_strategy: PaddingStrategy::DuplicateLast,
        }
    }

    /// Adds a single hash to the tree.
    pub fn add_hash(mut self, hash: impl Into<String>) -> Self {
        self.hashes.push(hash.into());
        self
    }

    /// Adds multiple hashes to the tree.
    pub fn add_hashes(mut self, hashes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.hashes.extend(hashes.into_iter().map(|h| h.into()));
        self
    }

    /// Sets the padding strategy for non-power-of-2 leaf counts.
    pub fn with_padding(mut self, strategy: PaddingStrategy) -> Self {
        self.padding_strategy = strategy;
        self
    }

    /// Returns the current number of hashes.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Returns true if no hashes have been added.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Builds the Merkle tree.
    ///
    /// # Errors
    ///
    /// - `MerkleError::EmptyLeaves` if no hashes were added
    /// - `MerkleError::InvalidHash` if any hash is not valid format
    /// - `MerkleError::TreeTooLarge` if exceeds MAX_TREE_SIZE
    pub fn build(self) -> Result<MerkleTree, MerkleError> {
        // Check for empty input
        if self.hashes.is_empty() {
            return Err(MerkleError::EmptyLeaves);
        }

        // Check size limit
        if self.hashes.len() > MAX_TREE_SIZE {
            return Err(MerkleError::TreeTooLarge {
                size: self.hashes.len(),
                max: MAX_TREE_SIZE,
            });
        }

        // Validate all hashes
        validate_hashes(&self.hashes)?;

        let original_count = self.hashes.len();
        let mut leaves = self.hashes;

        // Apply padding to reach power of 2
        let target_size = leaves.len().next_power_of_two();
        if leaves.len() < target_size && self.padding_strategy.requires_padding() {
            let padding_hash = self.padding_strategy.padding_hash(leaves.last().unwrap());
            while leaves.len() < target_size {
                leaves.push(padding_hash.clone());
            }
        }

        // Build tree levels
        let (levels, root) = build_tree_levels(&leaves);

        let height = levels.len();

        let metadata = TreeMetadata {
            original_leaf_count: original_count,
            padded_leaf_count: leaves.len(),
            height,
            created_at: crate::current_timestamp(),
            padding_strategy: self.padding_strategy,
        };

        Ok(MerkleTree::from_parts(root, leaves, levels, metadata))
    }
}

/// Builds tree levels from leaves to root.
///
/// Returns (levels, root_hash) where levels[0] = leaf nodes.
fn build_tree_levels(leaves: &[String]) -> (Vec<Vec<MerkleNode>>, String) {
    let mut levels: Vec<Vec<MerkleNode>> = Vec::new();

    // Level 0: Create leaf nodes
    let leaf_nodes: Vec<MerkleNode> = leaves
        .iter()
        .enumerate()
        .map(|(i, hash)| MerkleNode::leaf(hash.clone(), i))
        .collect();
    levels.push(leaf_nodes);

    // Build subsequent levels until we reach the root
    while levels.last().unwrap().len() > 1 {
        let current_level = levels.last().unwrap();
        let mut next_level = Vec::new();

        // Process pairs of nodes
        for (i, chunk) in current_level.chunks(2).enumerate() {
            let left = &chunk[0];
            let right = if chunk.len() > 1 {
                &chunk[1]
            } else {
                // Odd number of nodes: duplicate the last one
                &chunk[0]
            };

            let parent = MerkleNode::internal(left, right, i);
            next_level.push(parent);
        }

        levels.push(next_level);
    }

    // Extract root hash
    let root = levels.last().unwrap()[0].hash.clone();

    (levels, root)
}
