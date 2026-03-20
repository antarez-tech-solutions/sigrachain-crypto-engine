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

    /// Verifies the tree's internal consistency.
    ///
    /// Recomputes all internal hashes and compares with stored values.
    ///
    /// # Returns
    ///
    /// `Ok(())` if tree is valid, error describing the inconsistency otherwise
    pub fn verify_integrity(&self) -> Result<(), crate::error::MerkleError> {
        use crate::error::MerkleError;

        for level in 0..self.levels.len() - 1 {
            let current = &self.levels[level];
            let parent = &self.levels[level + 1];

            for (i, chunk) in current.chunks(2).enumerate() {
                let left = &chunk[0];
                let right = chunk.get(1).unwrap_or(&chunk[0]);

                let expected_hash = hash_pair(&left.hash, &right.hash);
                let actual_hash = &parent[i].hash;

                if expected_hash != *actual_hash {
                    return Err(MerkleError::IntegrityCheckFailed { level, index: i });
                }
            }
        }

        Ok(())
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

// ============================================================================
// SERIALIZATION
// ============================================================================

impl MerkleTree {
    /// Serializes the tree to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes a tree from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let mut tree: Self = serde_json::from_str(json)?;
        tree.rebuild_index();
        Ok(tree)
    }

    /// Returns a compact representation (root + leaves only).
    ///
    /// The full tree can be reconstructed from this using `expand()`.
    pub fn to_compact(&self) -> CompactTree {
        CompactTree {
            root: self.root.clone(),
            leaves: self.leaves[..self.metadata.original_leaf_count].to_vec(),
            padding_strategy: self.metadata.padding_strategy,
        }
    }
}

/// Compact tree representation for storage.
///
/// Contains only the essential data; full tree can be reconstructed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactTree {
    /// The root hash
    pub root: String,

    /// Original leaf hashes (no padding)
    pub leaves: Vec<String>,

    /// Padding strategy used
    pub padding_strategy: PaddingStrategy,
}

impl CompactTree {
    /// Reconstructs the full tree from compact form.
    pub fn expand(&self) -> Result<MerkleTree, crate::error::MerkleError> {
        use super::MerkleTreeBuilder;

        let tree = MerkleTreeBuilder::new()
            .add_hashes(self.leaves.clone())
            .with_padding(self.padding_strategy)
            .build()?;

        // Verify reconstruction matches original root
        if tree.root() != self.root {
            return Err(crate::error::MerkleError::IntegrityCheckFailed {
                level: 0,
                index: 0,
            });
        }

        Ok(tree)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_document;

    fn build_test_tree(n: usize) -> MerkleTree {
        let hashes: Vec<String> = (0..n).map(|i| hash_document(&i.to_le_bytes())).collect();
        crate::merkle::build_merkle_tree(hashes).unwrap()
    }

    #[test]
    fn test_node_leaf() {
        let hash = hash_document(b"test");
        let node = MerkleNode::leaf(hash.clone(), 0);

        assert!(node.is_leaf());
        assert_eq!(node.hash, hash);
        assert_eq!(node.level, 0);
        assert_eq!(node.index, 0);
    }

    #[test]
    fn test_node_internal() {
        let left = MerkleNode::leaf(hash_document(b"left"), 0);
        let right = MerkleNode::leaf(hash_document(b"right"), 1);

        let parent = MerkleNode::internal(&left, &right, 0);

        assert!(!parent.is_leaf());
        assert_eq!(parent.level, 1);
        assert_eq!(parent.index, 0);

        let expected = hash_pair(&left.hash, &right.hash);
        assert_eq!(parent.hash, expected);
    }

    #[test]
    fn test_tree_height() {
        let cases = [
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 3),
            (5, 4),
            (8, 4),
            (9, 5),
        ];

        for (n, expected_height) in cases {
            let tree = build_test_tree(n);
            assert_eq!(
                tree.height(),
                expected_height,
                "Tree with {} leaves should have height {}",
                n,
                expected_height
            );
        }
    }

    #[test]
    fn test_get_sibling() {
        let tree = build_test_tree(4);

        let sibling_0 = tree.get_sibling(0, 0).unwrap();
        let node_1 = tree.get_node(0, 1).unwrap();
        assert_eq!(sibling_0.hash, node_1.hash);

        let sibling_1 = tree.get_sibling(0, 1).unwrap();
        let node_0 = tree.get_node(0, 0).unwrap();
        assert_eq!(sibling_1.hash, node_0.hash);
    }

    #[test]
    fn test_verify_integrity() {
        let tree = build_test_tree(8);
        assert!(tree.verify_integrity().is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let tree = build_test_tree(5);
        let json = tree.to_json().unwrap();
        let restored = MerkleTree::from_json(&json).unwrap();

        assert_eq!(tree.root(), restored.root());
        assert_eq!(tree.leaf_count(), restored.leaf_count());
        assert_eq!(tree.height(), restored.height());

        for hash in tree.leaves() {
            assert!(restored.contains(hash));
        }
    }

    #[test]
    fn test_compact_roundtrip() {
        let tree = build_test_tree(7);
        let compact = tree.to_compact();

        assert_eq!(compact.leaves.len(), 7);
        assert_eq!(compact.root, tree.root());

        let expanded = compact.expand().unwrap();
        assert_eq!(expanded.root(), tree.root());
        assert_eq!(expanded.leaf_count(), tree.leaf_count());
    }
}
