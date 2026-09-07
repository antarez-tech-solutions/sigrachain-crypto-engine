//! Domain-separation tests (RFC 6962 style leaf/node tagging).
//!
//! The tree tags leaves with 0x00 and internal nodes with 0x01, so an
//! internal node value can never be presented as a document leaf
//! (second-preimage resistance). The public `hash_document` fingerprint
//! stays untagged — `sha256sum file.pdf` must keep matching.

use sigrachain_crypto::hashing::{hash_document, hash_leaf, hash_node};
use sigrachain_crypto::proof::MerkleProof;
use sigrachain_crypto::{build_merkle_tree, generate_merkle_proof, verify_merkle_proof};

#[test]
fn leaf_and_node_domains_are_disjoint() {
    // The whole point: a node hash can never collide with a leaf hash.
    let a = hash_document(b"a");
    let b = hash_document(b"b");
    assert_ne!(hash_leaf(&a).unwrap(), hash_node(&a, &b).unwrap());
}

#[test]
fn internal_node_cannot_be_presented_as_a_document() {
    // Build a 2-leaf tree; the root IS the internal node over (hL, hR).
    let hl = hash_document(b"contract L");
    let hr = hash_document(b"contract R");
    let tree = build_merkle_tree(vec![hl.clone(), hr.clone()]).unwrap();
    let root = tree.root().to_string();

    // The forged "document" is the 64 RAW bytes  bytes(hL) ‖ bytes(hR)  —
    // NOT the 128-char hex string. hash_pair hex-DECODES its inputs
    // before hashing, so the node value is SHA-256 over 64 raw bytes.
    // Hashing the hex text instead would produce a different digest and
    // would NOT reproduce the attack.
    let mut forged_doc = hex::decode(&hl).unwrap();
    forged_doc.extend_from_slice(&hex::decode(&hr).unwrap());
    let forged_hash = hash_document(&forged_doc);

    // Under the OLD (untagged) scheme this is exactly the root value, and a
    // proof with an EMPTY path verifies, because compute_root(leaf) == leaf.
    // Under domain separation the leaf commitment is hash_leaf(forged_hash)
    // (tag 0x00) while the root is a hash_node (tag 0x01) — they can never
    // be equal, so the forgery dies.
    let empty_proof = MerkleProof {
        document_hash: forged_hash.clone(),
        path: vec![], // 0 siblings ⇒ compute_root(leaf) == leaf
        root: root.clone(),
        leaf_index: 0,
        metadata: None,
    };
    assert!(!verify_merkle_proof(&forged_hash, &empty_proof, &root).unwrap());

    // Honest leaves are unaffected.
    let real_proof = generate_merkle_proof(&hl, &tree).unwrap();
    assert!(verify_merkle_proof(&hl, &real_proof, &root).unwrap());
}

#[test]
fn honest_documents_still_roundtrip() {
    let hashes: Vec<String> =
        (0..5).map(|i| hash_document(format!("doc {i}").as_bytes())).collect();
    let tree = build_merkle_tree(hashes.clone()).unwrap();
    let root = tree.root().to_string();
    for h in &hashes {
        let p = generate_merkle_proof(h, &tree).unwrap();
        assert!(verify_merkle_proof(h, &p, &root).unwrap());
    }
}
