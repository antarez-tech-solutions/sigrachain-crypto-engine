//! Merkle Proof Verifier
//!
//! Verifies that a document is included in a Merkle tree given its proof.

use sha2::{Digest, Sha256};

use super::{MerkleProof, ProofDirection};
use crate::error::ProofError;
use crate::hashing::is_valid_hash;

/// Verifies a Merkle proof against an expected root.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Returns
///
/// - `Ok(true)` if proof is valid
/// - `Ok(false)` if proof is invalid (document was not in tree)
/// - `Err(...)` if inputs are malformed
pub fn verify_merkle_proof(
    document_hash: &str,
    proof: &MerkleProof,
    expected_root: &str,
) -> Result<bool, ProofError> {
    ProofVerifier::verify(document_hash, proof, expected_root)
}

/// Proof verifier with detailed error handling.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Verifies a proof against an expected root.
    pub fn verify(
        document_hash: &str,
        proof: &MerkleProof,
        expected_root: &str,
    ) -> Result<bool, ProofError> {
        Self::validate_inputs(document_hash, proof, expected_root)?;
        let computed_root = Self::compute_root(document_hash, &proof.path)?;
        Self::hashes_equal(&computed_root, expected_root)
    }

    /// Validates all inputs before verification.
    fn validate_inputs(
        document_hash: &str,
        proof: &MerkleProof,
        expected_root: &str,
    ) -> Result<(), ProofError> {
        if !is_valid_hash(document_hash) {
            return Err(ProofError::InvalidDocumentHash {
                hash: document_hash.to_string(),
            });
        }

        if !is_valid_hash(expected_root) {
            return Err(ProofError::InvalidRootHash {
                hash: expected_root.to_string(),
            });
        }

        for (i, step) in proof.path.iter().enumerate() {
            if !is_valid_hash(&step.hash) {
                return Err(ProofError::InvalidProofStep {
                    index: i,
                    hash: step.hash.clone(),
                });
            }
        }

        Ok(())
    }

    /// Computes the root hash by traversing the proof path.
    fn compute_root(
        document_hash: &str,
        path: &[super::ProofStep],
    ) -> Result<String, ProofError> {
        let mut current = document_hash.to_string();

        for step in path {
            current = match step.direction {
                ProofDirection::Left => Self::hash_pair(&step.hash, &current)?,
                ProofDirection::Right => Self::hash_pair(&current, &step.hash)?,
            };
        }

        Ok(current)
    }

    /// Hashes two hex-encoded hashes together.
    fn hash_pair(left: &str, right: &str) -> Result<String, ProofError> {
        let left_bytes = hex::decode(left).map_err(|_| ProofError::HexEncoding)?;
        let right_bytes = hex::decode(right).map_err(|_| ProofError::HexEncoding)?;

        let mut hasher = Sha256::new();
        hasher.update(&left_bytes);
        hasher.update(&right_bytes);

        Ok(hex::encode(hasher.finalize()))
    }

    /// Constant-time comparison of two hashes.
    ///
    /// Uses XOR-fold to prevent timing attacks where an attacker could
    /// measure comparison duration to leak information about the expected
    /// value. Every byte is always compared regardless of mismatch position.
    pub fn hashes_equal(computed: &str, expected: &str) -> Result<bool, ProofError> {
        let computed_bytes = hex::decode(computed).map_err(|_| ProofError::HexEncoding)?;
        let expected_bytes = hex::decode(expected).map_err(|_| ProofError::HexEncoding)?;

        if computed_bytes.len() != expected_bytes.len() {
            return Ok(false);
        }

        let diff = computed_bytes
            .iter()
            .zip(expected_bytes.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));

        Ok(diff == 0)
    }

    /// Verifies a proof and returns detailed result including the computed root.
    pub fn verify_detailed(
        document_hash: &str,
        proof: &MerkleProof,
        expected_root: &str,
    ) -> Result<VerificationResult, ProofError> {
        Self::validate_inputs(document_hash, proof, expected_root)?;

        let computed_root = Self::compute_root(document_hash, &proof.path)?;
        let is_valid = Self::hashes_equal(&computed_root, expected_root)?;

        Ok(VerificationResult {
            is_valid,
            computed_root,
            expected_root: expected_root.to_string(),
            document_hash: document_hash.to_string(),
            proof_depth: proof.path.len(),
        })
    }
}

/// Detailed verification result for debugging/logging.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub is_valid: bool,

    /// The root computed from the proof
    pub computed_root: String,

    /// The expected root
    pub expected_root: String,

    /// The document hash that was verified
    pub document_hash: String,

    /// Number of steps in the proof
    pub proof_depth: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_document;
    use crate::merkle::build_merkle_tree;
    use crate::proof::generate_merkle_proof;

    fn setup_tree(n: usize) -> (Vec<String>, crate::merkle::MerkleTree) {
        let hashes: Vec<String> = (0..n).map(|i| hash_document(&i.to_le_bytes())).collect();
        let tree = build_merkle_tree(hashes.clone()).unwrap();
        (hashes, tree)
    }

    #[test]
    fn test_verify_valid_proof() {
        let (hashes, tree) = setup_tree(8);

        for hash in &hashes {
            let proof = generate_merkle_proof(hash, &tree).unwrap();
            let is_valid = verify_merkle_proof(hash, &proof, tree.root()).unwrap();
            assert!(is_valid, "Proof for {} should be valid", hash);
        }
    }

    #[test]
    fn test_verify_wrong_document() {
        let (hashes, tree) = setup_tree(4);
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        let wrong_hash = hash_document(b"wrong document");
        let is_valid = verify_merkle_proof(&wrong_hash, &proof, tree.root()).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_wrong_root() {
        let (hashes, tree) = setup_tree(4);
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        let wrong_root = hash_document(b"wrong root");
        let is_valid = verify_merkle_proof(&hashes[0], &proof, &wrong_root).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_tampered_proof() {
        let (hashes, tree) = setup_tree(4);
        let mut proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        if !proof.path.is_empty() {
            proof.path[0].hash = hash_document(b"tampered");
        }

        let is_valid = verify_merkle_proof(&hashes[0], &proof, tree.root()).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_invalid_document_hash() {
        let (hashes, tree) = setup_tree(4);
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        let result = verify_merkle_proof("invalid", &proof, tree.root());
        assert!(matches!(result, Err(ProofError::InvalidDocumentHash { .. })));
    }

    #[test]
    fn test_verify_invalid_root_hash() {
        let (hashes, tree) = setup_tree(4);
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        let result = verify_merkle_proof(&hashes[0], &proof, "invalid");
        assert!(matches!(result, Err(ProofError::InvalidRootHash { .. })));
    }

    #[test]
    fn test_verify_single_leaf() {
        let (hashes, tree) = setup_tree(1);
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        let is_valid = verify_merkle_proof(&hashes[0], &proof, tree.root()).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_detailed() {
        let (hashes, tree) = setup_tree(4);
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        let result = ProofVerifier::verify_detailed(&hashes[0], &proof, tree.root()).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.computed_root, tree.root());
        assert_eq!(result.document_hash, hashes[0]);
    }

    #[test]
    fn test_constant_time_comparison() {
        let hash1 = hash_document(b"test1");
        let hash2 = hash_document(b"test2");
        let hash1_copy = hash_document(b"test1");

        assert!(ProofVerifier::hashes_equal(&hash1, &hash1_copy).unwrap());
        assert!(!ProofVerifier::hashes_equal(&hash1, &hash2).unwrap());
    }
}
