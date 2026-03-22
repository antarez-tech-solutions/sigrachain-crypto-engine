//! Integration tests for sigrachain-crypto
//!
//! End-to-end flows: hash → tree → proof → verify.

use sigrachain_crypto::{
    batch_hash_documents, build_merkle_tree, generate_merkle_proof, hash_document,
    verify_merkle_proof,
};

#[test]
fn test_complete_proof_flow() {
    // 1. Hash documents
    let documents: Vec<&[u8]> = vec![
        b"Contract: Employment Agreement",
        b"Contract: NDA",
        b"Contract: Service Agreement",
        b"Invoice: INV-2024-001",
        b"Invoice: INV-2024-002",
    ];
    let hashes = batch_hash_documents(&documents);

    // 2. Build Merkle tree
    let tree = build_merkle_tree(hashes.clone()).unwrap();
    let root = tree.root().to_string();

    // 3. Generate + verify proof for each document
    for (i, hash) in hashes.iter().enumerate() {
        let proof = generate_merkle_proof(hash, &tree).unwrap();
        let is_valid = verify_merkle_proof(hash, &proof, &root).unwrap();
        assert!(is_valid, "Document {} should verify", i);
    }

    // 4. Tampered document fails
    let tampered = hash_document(b"Contract: Employment Agreement MODIFIED");
    let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();
    let is_valid = verify_merkle_proof(&tampered, &proof, &root).unwrap();
    assert!(!is_valid, "Tampered document should fail verification");
}

#[test]
fn test_single_document_flow() {
    let hash = hash_document(b"Single document");
    let tree = build_merkle_tree(vec![hash.clone()]).unwrap();
    let proof = generate_merkle_proof(&hash, &tree).unwrap();
    assert!(verify_merkle_proof(&hash, &proof, tree.root()).unwrap());
}

#[test]
fn test_large_batch_flow() {
    let hashes: Vec<String> = (0..1000)
        .map(|i| hash_document(format!("Document #{}", i).as_bytes()))
        .collect();
    let tree = build_merkle_tree(hashes.clone()).unwrap();

    // Spot-check a few proofs
    for i in [0, 499, 999] {
        let proof = generate_merkle_proof(&hashes[i], &tree).unwrap();
        assert!(verify_merkle_proof(&hashes[i], &proof, tree.root()).unwrap());
    }
}
