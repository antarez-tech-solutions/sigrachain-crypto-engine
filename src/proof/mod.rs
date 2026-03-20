//! Merkle Proof Module
//!
//! Provides proof generation and verification for document inclusion.
//!
//! After building a Merkle tree and anchoring its root on-chain, proofs allow
//! verifying that individual documents were part of the anchored batch.

mod generator;
mod verifier;

use serde::{Deserialize, Serialize};

/// Direction of sibling in proof path.
///
/// Indicates which side the sibling hash is on relative to the current node.
/// This is critical for correct hash ordering during verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofDirection {
    /// Sibling is to the left (current node is on right)
    Left,
    /// Sibling is to the right (current node is on left)
    Right,
}

impl ProofDirection {
    /// Returns the opposite direction.
    pub fn opposite(&self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

/// A single step in the proof path.
///
/// Each step contains:
/// - The sibling hash at that level
/// - Which side the sibling is on
/// - Optionally, the level number
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    /// The sibling hash
    pub hash: String,

    /// Direction: is sibling on left or right?
    pub direction: ProofDirection,

    /// Tree level (0 = leaf level, optional for compact proofs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<usize>,
}

impl ProofStep {
    /// Creates a new proof step.
    pub fn new(hash: String, direction: ProofDirection, level: Option<usize>) -> Self {
        Self {
            hash,
            direction,
            level,
        }
    }
}

/// Metadata about the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Batch identifier (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,

    /// Unix timestamp when proof was generated (milliseconds)
    pub generated_at: u64,

    /// Total documents in the batch
    pub batch_size: usize,

    /// EAS attestation UID (if anchored)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_uid: Option<String>,
}

/// Complete Merkle proof for document inclusion.
///
/// Contains everything needed to verify a document was part of an anchored batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Hash of the document this proof is for
    pub document_hash: String,

    /// The authentication path (sibling hashes from leaf to root)
    pub path: Vec<ProofStep>,

    /// The Merkle root (should match on-chain value)
    pub root: String,

    /// Index of the document in the original batch
    pub leaf_index: usize,

    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProofMetadata>,
}

impl MerkleProof {
    /// Returns the number of steps in the proof (tree height - 1).
    pub fn size(&self) -> usize {
        self.path.len()
    }

    /// Returns the proof depth (same as size).
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Checks if the proof structure is well-formed.
    ///
    /// Validates:
    /// - Document hash is valid SHA-256 format
    /// - Root hash is valid SHA-256 format
    /// - All path hashes are valid SHA-256 format
    pub fn is_well_formed(&self) -> bool {
        use crate::hashing::is_valid_hash;

        is_valid_hash(&self.document_hash)
            && is_valid_hash(&self.root)
            && self.path.iter().all(|step| is_valid_hash(&step.hash))
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_document;

    fn sample_proof() -> MerkleProof {
        MerkleProof {
            document_hash: hash_document(b"test"),
            path: vec![
                ProofStep::new(hash_document(b"sibling1"), ProofDirection::Right, Some(0)),
                ProofStep::new(hash_document(b"sibling2"), ProofDirection::Left, Some(1)),
            ],
            root: hash_document(b"root"),
            leaf_index: 0,
            metadata: Some(ProofMetadata {
                batch_id: Some("batch_001".to_string()),
                generated_at: 1702234567000,
                batch_size: 4,
                attestation_uid: None,
            }),
        }
    }

    #[test]
    fn test_proof_size() {
        let proof = sample_proof();
        assert_eq!(proof.size(), 2);
        assert_eq!(proof.depth(), 2);
    }

    #[test]
    fn test_proof_well_formed() {
        let proof = sample_proof();
        assert!(proof.is_well_formed());
    }

    #[test]
    fn test_proof_well_formed_invalid() {
        let mut proof = sample_proof();
        proof.document_hash = "invalid".to_string();
        assert!(!proof.is_well_formed());
    }

    #[test]
    fn test_proof_direction_opposite() {
        assert_eq!(ProofDirection::Left.opposite(), ProofDirection::Right);
        assert_eq!(ProofDirection::Right.opposite(), ProofDirection::Left);
    }
}
