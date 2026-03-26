//! Known Answer Tests (KAT) for cross-implementation compatibility.
//!
//! These tests use well-known reference values to ensure correctness
//! and enable verification across different implementations.

use sigrachain_crypto::hashing::{hash_document, hash_pair, is_valid_hash};
use sigrachain_crypto::{build_merkle_tree, generate_merkle_proof, verify_merkle_proof};

/// NIST FIPS 180-4 SHA-256 test vectors.
mod sha256_vectors {
    use super::*;

    #[test]
    fn test_nist_vectors() {
        let vectors: &[(&[u8], &str)] = &[
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];

        for (input, expected) in vectors {
            let actual = hash_document(input);
            assert_eq!(&actual, expected, "Failed for input: {:?}", input);
        }
    }

    #[test]
    fn test_million_a() {
        // SHA-256("a" x 1,000,000)
        let input = vec![b'a'; 1_000_000];
        let expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

        let actual = hash_document(&input);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_hash_format_invariants() {
        let hash = hash_document(b"format check");
        assert_eq!(hash.len(), 64, "SHA-256 must produce 64 hex chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            hash.chars().all(|c| c.is_lowercase() || c.is_ascii_digit()),
            "Hash must be lowercase hex"
        );
        assert!(is_valid_hash(&hash));
    }

    #[test]
    fn test_single_byte_values() {
        // Verify single-byte inputs produce distinct, valid hashes
        let hashes: Vec<String> = (0u8..=255).map(|b| hash_document(&[b])).collect();

        for hash in &hashes {
            assert!(is_valid_hash(hash));
        }

        // All 256 hashes must be unique (no collisions)
        let unique: std::collections::HashSet<&String> = hashes.iter().collect();
        assert_eq!(unique.len(), 256);
    }
}

/// Deterministic Merkle tree test vectors.
mod merkle_vectors {
    use super::*;

    #[test]
    fn test_two_leaf_tree() {
        let h0 = hash_document(b"leaf_0");
        let h1 = hash_document(b"leaf_1");

        let tree = build_merkle_tree(vec![h0.clone(), h1.clone()]).unwrap();

        // Root = H(h0 || h1)
        let expected_root = hash_pair(&h0, &h1);
        assert_eq!(tree.root(), &expected_root);
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.height(), 2);
    }

    #[test]
    fn test_four_leaf_tree() {
        let leaves: Vec<String> = (0u8..4).map(|i| hash_document(&[i])).collect();

        let tree = build_merkle_tree(leaves.clone()).unwrap();

        // Level 1: H(L0||L1), H(L2||L3)
        let h01 = hash_pair(&leaves[0], &leaves[1]);
        let h23 = hash_pair(&leaves[2], &leaves[3]);

        // Root: H(H01 || H23)
        let expected_root = hash_pair(&h01, &h23);
        assert_eq!(tree.root(), &expected_root);
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.height(), 3);
    }

    #[test]
    fn test_proof_structure_for_leaf_zero() {
        // Verify the exact proof path for a 4-leaf tree.
        let leaves: Vec<String> = (0u8..4).map(|i| hash_document(&[i])).collect();

        let tree = build_merkle_tree(leaves.clone()).unwrap();
        let proof = generate_merkle_proof(&leaves[0], &tree).unwrap();

        // Proof for leaf[0]: sibling at level 0 is leaves[1], sibling at level 1 is H(leaves[2]||leaves[3])
        assert_eq!(proof.path.len(), 2);
        assert_eq!(proof.path[0].hash, leaves[1]);

        let h23 = hash_pair(&leaves[2], &leaves[3]);
        assert_eq!(proof.path[1].hash, h23);

        assert!(verify_merkle_proof(&leaves[0], &proof, tree.root()).unwrap());
    }

    #[test]
    fn test_single_leaf_tree() {
        let hash = hash_document(b"only leaf");
        let tree = build_merkle_tree(vec![hash.clone()]).unwrap();

        // Single leaf: root == leaf
        assert_eq!(tree.root(), &hash);
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.height(), 1);

        let proof = generate_merkle_proof(&hash, &tree).unwrap();
        assert!(verify_merkle_proof(&hash, &proof, tree.root()).unwrap());
    }

    #[test]
    fn test_eight_leaf_tree_all_proofs() {
        let leaves: Vec<String> = (0u8..8).map(|i| hash_document(&[i])).collect();
        let tree = build_merkle_tree(leaves.clone()).unwrap();

        assert_eq!(tree.leaf_count(), 8);
        assert_eq!(tree.height(), 4); // log2(8) + 1

        // Every leaf must produce a valid proof
        for leaf in &leaves {
            let proof = generate_merkle_proof(leaf, &tree).unwrap();
            assert_eq!(proof.size(), 3); // log2(8) = 3 proof steps
            assert!(verify_merkle_proof(leaf, &proof, tree.root()).unwrap());
        }
    }

    #[test]
    fn test_non_power_of_two_leaves() {
        // 5 leaves → padded to 8 internally
        let leaves: Vec<String> = (0u8..5).map(|i| hash_document(&[i])).collect();
        let tree = build_merkle_tree(leaves.clone()).unwrap();

        assert_eq!(tree.leaf_count(), 5);

        for leaf in &leaves {
            let proof = generate_merkle_proof(leaf, &tree).unwrap();
            assert!(verify_merkle_proof(leaf, &proof, tree.root()).unwrap());
        }
    }

    #[test]
    fn test_tampered_document_fails_verification() {
        let leaves: Vec<String> = (0u8..4).map(|i| hash_document(&[i])).collect();
        let tree = build_merkle_tree(leaves.clone()).unwrap();

        let proof = generate_merkle_proof(&leaves[0], &tree).unwrap();

        // Tampered hash should fail verification
        let tampered = hash_document(b"definitely not in the tree");
        assert!(!verify_merkle_proof(&tampered, &proof, tree.root()).unwrap());

        // Wrong root should fail verification
        let wrong_root = hash_document(b"wrong root");
        assert!(!verify_merkle_proof(&leaves[0], &proof, &wrong_root).unwrap());
    }
}
