//! Merkle Proof Generator
//!
//! Generates inclusion proofs for documents in a Merkle tree.

use super::{MerkleProof, ProofDirection, ProofMetadata, ProofStep};
use crate::error::ProofError;
use crate::merkle::MerkleTree;

/// Generates a Merkle proof for a document.
///
/// The proof contains the sibling hashes along the path from the document's
/// leaf position to the root, allowing anyone to verify inclusion.
///
/// # Errors
///
/// - `ProofError::DocumentNotFound` if hash is not in the tree
/// - `ProofError::InvalidTreeStructure` if tree is malformed
pub fn generate_merkle_proof(
    document_hash: &str,
    tree: &MerkleTree,
) -> Result<MerkleProof, ProofError> {
    ProofGenerator::generate(document_hash, tree)
}

/// Proof generator with reusable logic.
pub struct ProofGenerator;

impl ProofGenerator {
    /// Generates a proof for a document hash in the tree.
    pub fn generate(document_hash: &str, tree: &MerkleTree) -> Result<MerkleProof, ProofError> {
        let leaf_index = tree.get_leaf_index(document_hash).ok_or_else(|| {
            ProofError::DocumentNotFound {
                hash: document_hash.to_string(),
            }
        })?;

        let path = Self::build_path(tree, leaf_index)?;

        Ok(MerkleProof {
            document_hash: document_hash.to_string(),
            path,
            root: tree.root().to_string(),
            leaf_index,
            metadata: Some(ProofMetadata {
                batch_id: None,
                generated_at: crate::current_timestamp(),
                batch_size: tree.leaf_count(),
                attestation_uid: None,
            }),
        })
    }

    /// Builds the authentication path from leaf to root.
    ///
    /// At each level: find the sibling, record its hash and direction, move up.
    fn build_path(tree: &MerkleTree, leaf_index: usize) -> Result<Vec<ProofStep>, ProofError> {
        let mut path = Vec::new();
        let mut current_index = leaf_index;

        for level in 0..tree.height() - 1 {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = tree.get_node(level, sibling_index).ok_or(
                ProofError::InvalidTreeStructure {
                    level,
                    index: sibling_index,
                }
            )?;

            let direction = if current_index.is_multiple_of(2) {
                ProofDirection::Right
            } else {
                ProofDirection::Left
            };

            path.push(ProofStep {
                hash: sibling.hash.clone(),
                direction,
                level: Some(level),
            });

            current_index /= 2;
        }

        Ok(path)
    }

    /// Generates proofs for all original documents in the tree.
    pub fn generate_all(tree: &MerkleTree) -> Result<Vec<MerkleProof>, ProofError> {
        tree.leaves()
            .iter()
            .map(|hash| Self::generate(hash, tree))
            .collect()
    }

    /// Generates proofs for a subset of documents.
    pub fn generate_batch(
        hashes: &[String],
        tree: &MerkleTree,
    ) -> Result<Vec<MerkleProof>, ProofError> {
        hashes.iter().map(|hash| Self::generate(hash, tree)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_document;
    use crate::merkle::build_merkle_tree;

    fn setup_tree(n: usize) -> (Vec<String>, MerkleTree) {
        let hashes: Vec<String> = (0..n).map(|i| hash_document(&i.to_le_bytes())).collect();
        let tree = build_merkle_tree(hashes.clone()).unwrap();
        (hashes, tree)
    }

    #[test]
    fn test_generate_proof_simple() {
        let (hashes, tree) = setup_tree(4);
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        assert_eq!(proof.document_hash, hashes[0]);
        assert_eq!(proof.root, tree.root());
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.size(), 2);
    }

    #[test]
    fn test_generate_proof_all_positions() {
        let (hashes, tree) = setup_tree(8);

        for (i, hash) in hashes.iter().enumerate() {
            let proof = generate_merkle_proof(hash, &tree).unwrap();

            assert_eq!(proof.document_hash, *hash);
            assert_eq!(proof.leaf_index, i);
            assert_eq!(proof.root, tree.root());
            assert_eq!(proof.size(), 3, "Proof for index {} should have 3 steps", i);
        }
    }

    #[test]
    fn test_generate_proof_not_found() {
        let (_, tree) = setup_tree(4);
        let missing_hash = hash_document(b"not in tree");
        let result = generate_merkle_proof(&missing_hash, &tree);

        assert!(matches!(result, Err(ProofError::DocumentNotFound { .. })));
    }

    #[test]
    fn test_generate_proof_single_leaf() {
        let (hashes, tree) = setup_tree(1);
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        assert_eq!(proof.size(), 0);
        assert_eq!(proof.root, hashes[0]);
    }

    #[test]
    fn test_generate_proof_non_power_of_two() {
        let (hashes, tree) = setup_tree(5);

        for hash in &hashes {
            let proof = generate_merkle_proof(hash, &tree).unwrap();
            assert!(proof.is_well_formed());
        }
    }

    #[test]
    fn test_proof_directions() {
        let (hashes, tree) = setup_tree(4);

        let proof0 = generate_merkle_proof(&hashes[0], &tree).unwrap();
        assert_eq!(proof0.path[0].direction, ProofDirection::Right);

        let proof1 = generate_merkle_proof(&hashes[1], &tree).unwrap();
        assert_eq!(proof1.path[0].direction, ProofDirection::Left);
    }

    #[test]
    fn test_generate_all() {
        let (hashes, tree) = setup_tree(10);
        let proofs = ProofGenerator::generate_all(&tree).unwrap();

        assert_eq!(proofs.len(), 10);
        for (i, proof) in proofs.iter().enumerate() {
            assert_eq!(proof.document_hash, hashes[i]);
        }
    }

    #[test]
    fn test_generate_batch() {
        let (hashes, tree) = setup_tree(10);
        let subset = vec![hashes[0].clone(), hashes[5].clone(), hashes[9].clone()];
        let proofs = ProofGenerator::generate_batch(&subset, &tree).unwrap();

        assert_eq!(proofs.len(), 3);
        assert_eq!(proofs[0].leaf_index, 0);
        assert_eq!(proofs[1].leaf_index, 5);
        assert_eq!(proofs[2].leaf_index, 9);
    }

    #[test]
    fn test_proof_metadata() {
        let (hashes, tree) = setup_tree(4);
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();
        let metadata = proof.metadata.as_ref().unwrap();

        assert_eq!(metadata.batch_size, 4);
        assert!(metadata.generated_at > 0);
    }
}
