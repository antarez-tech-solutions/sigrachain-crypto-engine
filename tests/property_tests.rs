//! Property-based tests for Merkle tree invariants
//!
//! Uses `proptest` to verify cryptographic properties hold for arbitrary inputs.

use proptest::prelude::*;
use sigrachain_crypto::{
    build_merkle_tree, generate_merkle_proof, hash_document, verify_merkle_proof,
};

proptest! {
    /// Root of any tree is a valid SHA-256 hash (64 lowercase hex chars).
    #[test]
    fn prop_root_is_valid_hash(n in 1usize..500) {
        let hashes: Vec<String> = (0..n)
            .map(|i| hash_document(&i.to_le_bytes()))
            .collect();

        let tree = build_merkle_tree(hashes).unwrap();
        let root = tree.root();

        prop_assert_eq!(root.len(), 64);
        prop_assert!(root.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Same inputs always produce the same root (determinism).
    #[test]
    fn prop_deterministic_root(data in prop::collection::vec(any::<u8>(), 1..100)) {
        let hash = hash_document(&data);
        let hashes = vec![hash];

        let root1 = build_merkle_tree(hashes.clone()).unwrap().root().to_string();
        let root2 = build_merkle_tree(hashes).unwrap().root().to_string();

        prop_assert_eq!(root1, root2);
    }

    /// Different inputs produce different roots (collision resistance).
    #[test]
    fn prop_different_inputs_different_roots(
        data1 in prop::collection::vec(any::<u8>(), 1..100),
        data2 in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        prop_assume!(data1 != data2);

        let hash1 = hash_document(&data1);
        let hash2 = hash_document(&data2);

        let root1 = build_merkle_tree(vec![hash1]).unwrap().root().to_string();
        let root2 = build_merkle_tree(vec![hash2]).unwrap().root().to_string();

        prop_assert_ne!(root1, root2);
    }

    /// Every proof generated from a tree verifies against that tree's root.
    #[test]
    fn prop_all_proofs_valid(n in 1usize..100) {
        let hashes: Vec<String> = (0..n)
            .map(|i| hash_document(&i.to_le_bytes()))
            .collect();

        let tree = build_merkle_tree(hashes.clone()).unwrap();

        for hash in &hashes {
            let proof = generate_merkle_proof(hash, &tree).unwrap();
            let is_valid = verify_merkle_proof(hash, &proof, tree.root()).unwrap();

            prop_assert!(is_valid);
        }
    }

    /// Proofs from one tree do not verify against a different tree's root.
    #[test]
    fn prop_wrong_root_fails(n in 2usize..50) {
        let hashes1: Vec<String> = (0..n)
            .map(|i| hash_document(&i.to_le_bytes()))
            .collect();

        let hashes2: Vec<String> = (n..2 * n)
            .map(|i| hash_document(&i.to_le_bytes()))
            .collect();

        let tree1 = build_merkle_tree(hashes1.clone()).unwrap();
        let tree2 = build_merkle_tree(hashes2).unwrap();

        let proof = generate_merkle_proof(&hashes1[0], &tree1).unwrap();
        let is_valid = verify_merkle_proof(&hashes1[0], &proof, tree2.root()).unwrap();

        prop_assert!(!is_valid);
    }

    /// Proof size is logarithmic in the number of leaves.
    #[test]
    fn prop_proof_size_logarithmic(n in 1usize..5000) {
        let hashes: Vec<String> = (0..n)
            .map(|i| hash_document(&i.to_le_bytes()))
            .collect();

        let tree = build_merkle_tree(hashes.clone()).unwrap();
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

        // Proof depth ≤ ceil(log2(n)) + 1
        let max_depth = if n == 1 { 1 } else { ((n as f64).log2().ceil() as usize) + 1 };

        prop_assert!(
            proof.size() <= max_depth,
            "Proof depth {} exceeds max {} for {} leaves",
            proof.size(),
            max_depth,
            n
        );
    }

    /// Leaf ordering matters: reversing leaves changes the root.
    #[test]
    fn prop_order_sensitive(n in 3usize..50) {
        let hashes: Vec<String> = (0..n)
            .map(|i| hash_document(&i.to_le_bytes()))
            .collect();

        let mut reversed = hashes.clone();
        reversed.reverse();

        let root1 = build_merkle_tree(hashes).unwrap().root().to_string();
        let root2 = build_merkle_tree(reversed).unwrap().root().to_string();

        prop_assert_ne!(root1, root2);
    }
}
