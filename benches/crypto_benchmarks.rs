use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sigrachain_crypto::{
    batch_hash_documents, build_merkle_tree, generate_merkle_proof, hash_document,
    verify_merkle_proof,
};

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    for size in [100, 1_000, 10_000, 100_000, 1_000_000] {
        let data = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("hash_document", size), &data, |b, data| {
            b.iter(|| hash_document(black_box(data)));
        });
    }

    group.finish();
}

fn bench_batch_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_hashing");

    for n in [10, 100, 1_000, 10_000] {
        let docs: Vec<Vec<u8>> = (0..n).map(|i| format!("doc_{}", i).into_bytes()).collect();
        let refs: Vec<&[u8]> = docs.iter().map(|d| d.as_slice()).collect();

        group.bench_with_input(BenchmarkId::new("batch_hash", n), &refs, |b, refs| {
            b.iter(|| batch_hash_documents(black_box(refs)));
        });
    }

    group.finish();
}

fn bench_merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree");

    for n in [10, 100, 1_000, 10_000] {
        let hashes: Vec<String> = (0..n).map(|i: i32| hash_document(&i.to_le_bytes())).collect();

        group.bench_with_input(BenchmarkId::new("build_tree", n), &hashes, |b, hashes| {
            b.iter(|| build_merkle_tree(black_box(hashes.clone())));
        });
    }

    group.finish();
}

fn bench_proof_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof");

    for n in [100, 1_000, 10_000] {
        let hashes: Vec<String> = (0..n).map(|i: i32| hash_document(&i.to_le_bytes())).collect();
        let tree = build_merkle_tree(hashes.clone()).unwrap();
        let proof = generate_merkle_proof(&hashes[0], &tree).unwrap();
        let root = tree.root().to_string();

        group.bench_with_input(
            BenchmarkId::new("generate_proof", n),
            &(&hashes[0], &tree),
            |b, (hash, tree)| {
                b.iter(|| generate_merkle_proof(black_box(hash), black_box(tree)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("verify_proof", n),
            &(&hashes[0], &proof, &root),
            |b, (hash, proof, root)| {
                b.iter(|| verify_merkle_proof(black_box(hash), black_box(proof), black_box(root)));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_hashing,
    bench_batch_hashing,
    bench_merkle_tree,
    bench_proof_operations
);

criterion_main!(benches);
