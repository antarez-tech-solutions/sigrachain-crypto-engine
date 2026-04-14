# SigraChain Crypto Engine

A Rust library for cryptographic document anchoring using Merkle trees.

Hash documents, batch them into a Merkle tree, and generate compact inclusion proofs that can be verified independently — without access to the original tree or any other documents in the batch.

## What it does

1. **Hash** — SHA-256 hash of any document or byte stream
2. **Batch** — Combine hashes into a Merkle tree, producing a single root hash
3. **Prove** — Generate a small proof (log₂(n) steps) that a specific document is part of the tree
4. **Verify** — Anyone with the proof and the root hash can verify inclusion

## Use cases

This pattern applies anywhere you need to prove data integrity without exposing the full dataset:

- **Supply chain audits** — A manufacturer hashes certificates of origin for a shipment. The root is recorded on a public ledger. A customs authority can verify any single certificate without seeing the rest.
- **Academic credential verification** — A university batches diploma hashes. Employers verify a candidate's degree against the published root.
- **Regulatory compliance** — Financial records are batched and anchored. An auditor verifies specific transactions without accessing the full ledger.
- **Software build provenance** — Build artifacts are hashed and anchored. Users verify a binary was part of an audited build.

## Quick start

```rust
use sigrachain_crypto::{
    hash_document, batch_hash_documents, build_merkle_tree,
    generate_merkle_proof, verify_merkle_proof,
};

// Hash documents
let hashes = batch_hash_documents(&[
    b"Document A" as &[u8],
    b"Document B",
    b"Document C",
]);

// Build tree
let tree = build_merkle_tree(hashes.clone()).unwrap();

// Generate proof for one document
let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();

// Verify (can happen anywhere, anytime)
let valid = verify_merkle_proof(&hashes[0], &proof, tree.root()).unwrap();
assert!(valid);
```

## Key properties

- **Tamper-evident** — changing a single byte in any document produces a different root
- **Efficient** — proof size is logarithmic: 20 steps covers over a million documents
- **Independent** — verification requires only the proof and the root, not the full tree
- **Timing-safe** — hash comparison uses constant-time XOR to prevent side-channel attacks

## License

This repository and all contributions are licensed under the [LGPL 3.0](https://www.gnu.org/licenses/lgpl-3.0.html), unless otherwise specified in subdirectory LICENSE files.
