

pub mod error;
pub mod hashing;

pub use error::{CryptoError, HashError};
pub use hashing::{hash_document, hash_string, batch_hash_documents, DocumentHasher, HashConfig, StreamingHasher};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn is_valid_sha256_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
}

pub(crate) fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let v = version();
        assert!(!v.is_empty());
        // Version should be semver format
        assert!(v.contains('.'));
    }

    #[test]
    fn test_valid_hash_validation() {
        // Valid hash (SHA-256 of empty string)
        let valid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(is_valid_sha256_hash(valid));

        // Invalid: too short
        assert!(!is_valid_sha256_hash("e3b0c44298fc"));

        // Invalid: too long
        assert!(!is_valid_sha256_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855extra"
        ));

        // Invalid: uppercase
        assert!(!is_valid_sha256_hash(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        ));

        // Invalid: non-hex characters
        assert!(!is_valid_sha256_hash(
            "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn test_timestamp() {
        let ts1 = current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let ts2 = current_timestamp();
        assert!(ts2 > ts1);
    }
}
