//! MerkleTree data structure and operations

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::PaddingStrategy;
use crate::hashing::hash_pair;

/// Represents a node in the Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleNode {
    /// The SHA-256 hash of this node
    pub hash: String,

    /// Index within its level
    pub index: usize,

    /// Level in the tree (0 = leaves, max = root)
    pub level: usize,
}

impl MerkleNode {
    /// Creates a leaf node from a document hash.
    pub fn leaf(hash: String, index: usize) -> Self {
        Self {
            hash,
            index,
            level: 0,
        }
    }

    /// Creates an internal node from two children.
    ///
    /// The hash is computed as `H(left.hash || right.hash)`.
    pub fn internal(left: &MerkleNode, right: &MerkleNode, index: usize) -> Self {
        let hash = hash_pair(&left.hash, &right.hash);
        Self {
            hash,
            index,
            level: left.level + 1,
        }
    }

    /// Returns true if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }
}

/// Metadata about the Merkle tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeMetadata {
    /// Number of original leaves (before padding)
    pub original_leaf_count: usize,

    /// Total number of leaves (after padding)
    pub padded_leaf_count: usize,

    /// Height of the tree (number of levels)
    pub height: usize,

    /// Unix timestamp when tree was created (milliseconds)
    pub created_at: u64,

    /// Padding strategy used
    pub padding_strategy: PaddingStrategy,
}

/// Complete Merkle tree structure.
///
/// Stores all nodes organized by level for efficient proof generation.
///
/// # Memory Layout
///
/// ```text
/// Level 3 (root):  [Root]
/// Level 2:         [H12] [H34]
/// Level 1:         [H1] [H2] [H3] [H4]
/// Level 0 (leaves):[D1] [D2] [D3] [D4]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// The root hash of the tree
    pub(crate) root: String,

    /// All leaf hashes in order (including padding)
    pub(crate) leaves: Vec<String>,

    /// All nodes organized by level (level 0 = leaves)
    pub(crate) levels: Vec<Vec<MerkleNode>>,

    /// Quick lookup: leaf hash -> leaf index (excludes padding)
    #[serde(skip)]
    pub(crate) leaf_indices: HashMap<String, usize>,

    /// Tree metadata
    pub(crate) metadata: TreeMetadata,
}

impl MerkleTree {
    /// Returns the root hash of the tree.
    ///
    /// This is the value that should be anchored on-chain.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Returns the number of original documents (excluding padding).
    pub fn leaf_count(&self) -> usize {
        self.metadata.original_leaf_count
    }

    /// Returns the total leaf count including padding.
    pub fn padded_leaf_count(&self) -> usize {
        self.metadata.padded_leaf_count
    }

    /// Returns the tree height (number of levels).
    ///
    /// A tree with 4 leaves has height 3:
    /// - Level 0: 4 leaves
    /// - Level 1: 2 nodes
    /// - Level 2: 1 root
    pub fn height(&self) -> usize {
        self.metadata.height
    }

    /// Returns the tree metadata.
    pub fn metadata(&self) -> &TreeMetadata {
        &self.metadata
    }

    /// Checks if a hash exists in the tree as an original leaf.
    ///
    /// # Arguments
    ///
    /// * `hash` - The document hash to check
    ///
    /// # Returns
    ///
    /// `true` if the hash is an original leaf (not padding)
    pub fn contains(&self, hash: &str) -> bool {
        self.leaf_indices.contains_key(hash)
    }

    /// Gets the index of a leaf hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The document hash to find
    ///
    /// # Returns
    ///
    /// `Some(index)` if found, `None` if not in tree
    pub fn get_leaf_index(&self, hash: &str) -> Option<usize> {
        self.leaf_indices.get(hash).copied()
    }

    /// Returns all original leaf hashes (excluding padding).
    pub fn leaves(&self) -> &[String] {
        &self.leaves[..self.metadata.original_leaf_count]
    }

    /// Returns all leaves including padding.
    pub fn all_leaves(&self) -> &[String] {
        &self.leaves
    }

    /// Gets a node at a specific level and index.
    pub fn get_node(&self, level: usize, index: usize) -> Option<&MerkleNode> {
        self.levels.get(level)?.get(index)
    }

    /// Gets the sibling node for a given position.
    ///
    /// Used for proof generation.
    pub fn get_sibling(&self, level: usize, index: usize) -> Option<&MerkleNode> {
        let sibling_index = if index.is_multiple_of(2) { index + 1 } else { index - 1 };
        self.get_node(level, sibling_index)
    }

    /// Rebuilds the leaf index after deserialization.
    pub fn rebuild_index(&mut self) {
        self.leaf_indices = self
            .leaves
            .iter()
            .take(self.metadata.original_leaf_count)
            .enumerate()
            .map(|(i, h)| (h.clone(), i))
            .collect();
    }

    /// Creates the tree from internal data (used by builder).
    pub(crate) fn from_parts(
        root: String,
        leaves: Vec<String>,
        levels: Vec<Vec<MerkleNode>>,
        metadata: TreeMetadata,
    ) -> Self {
        // Build leaf index map
        let leaf_indices: HashMap<String, usize> = leaves
            .iter()
            .take(metadata.original_leaf_count)
            .enumerate()
            .map(|(i, h)| (h.clone(), i))
            .collect();

        Self {
            root,
            leaves,
            levels,
            leaf_indices,
            metadata,
        }
    }
}
