use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Hashing error: {0}")]
    Hash(#[from] HashError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("Internal error: {message}")]
    Internal { message: String },

    #[error("Merkle error: {0}")]
    Merkle(#[from] MerkleError),

    #[error("Proof error: {0}")]
    Proof(#[from] ProofError),

    #[error("Signing error: {0}")]
    Signing(#[from] SigningError),
}

#[derive(Debug, Error)]
pub enum HashError {
    #[error("Cannot hash empty input")]
    EmptyInput,

    #[error("Invalid hash format: expected 64 hex characters, got {length}")]
    InvalidFormat { length: usize },

    #[error("Invalid hex encoding: {details}")]
    HexEncoding { details: String },

    #[error("Input too large: {size} bytes exceeds limit of {limit} bytes")]
    InputTooLarge { size: usize, limit: usize },

    #[error("Failed to read file '{path}': {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid hasher state: {reason}")]
    InvalidState { reason: String },
}

impl HashError {
    pub fn invalid_format(hash: &str) -> Self {
        Self::InvalidFormat {
            length: hash.len(),
        }
    }

    pub fn file_read(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::FileRead {
            path: path.into(),
            source,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MerkleError {
    #[error("cannot build tree from empty leaves")]
    EmptyLeaves,

    #[error("invalid hash at index {index}: {hash}")]
    InvalidHash { index: usize, hash: String },

    #[error("tree integrity check failed at level {level}, index {index}")]
    IntegrityCheckFailed { level: usize, index: usize },

    #[error("tree too large: {size} leaves exceeds maximum {max}")]
    TreeTooLarge { size: usize, max: usize },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProofError {
    #[error("document not found in tree: {hash}")]
    DocumentNotFound { hash: String },

    #[error("invalid document hash: {hash}")]
    InvalidDocumentHash { hash: String },

    #[error("invalid root hash: {hash}")]
    InvalidRootHash { hash: String },

    #[error("invalid proof step at index {index}: {hash}")]
    InvalidProofStep { index: usize, hash: String },

    #[error("invalid tree structure at level {level}, index {index}")]
    InvalidTreeStructure { level: usize, index: usize },

    #[error("hex encoding error")]
    HexEncoding,

    #[error("verification failed: computed {computed}, expected {expected}")]
    VerificationFailed { computed: String, expected: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Hash errors: 1xxx
    EmptyInput = 1001,
    InvalidHashFormat = 1002,
    InvalidHexEncoding = 1003,
    InputTooLarge = 1004,
    FileReadError = 1005,

    // Merkle errors: 2xxx
    EmptyTreeInput = 2001,
    TooManyLeaves = 2002,
    InvalidHashInTree = 2003,
    DuplicateHash = 2004,
    TreeCorrupted = 2005,

    // Proof errors: 3xxx
    DocumentNotFound = 3001,
    InvalidDocumentHash = 3002,
    InvalidRootHash = 3003,
    InvalidProofStep = 3004,
    VerificationFailed = 3005,

    // Signing errors: 4xxx
    KeyGenerationFailed = 4001,
    InvalidKey = 4002,
    SigningFailed = 4003,
    VerificationFailed2 = 4004,

    // General errors: 9xxx
    IoError = 9001,
    SerializationError = 9002,
    ConfigError = 9003,
    InternalError = 9999,
}

impl CryptoError {
    /// Returns the error code for this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            CryptoError::Hash(e) => match e {
                HashError::EmptyInput => ErrorCode::EmptyInput,
                HashError::InvalidFormat { .. } => ErrorCode::InvalidHashFormat,
                HashError::HexEncoding { .. } => ErrorCode::InvalidHexEncoding,
                HashError::InputTooLarge { .. } => ErrorCode::InputTooLarge,
                HashError::FileRead { .. } => ErrorCode::FileReadError,
                HashError::InvalidState { .. } => ErrorCode::InternalError,
            },
            CryptoError::Io(_) => ErrorCode::IoError,
            CryptoError::Serialization(_) => ErrorCode::SerializationError,
            CryptoError::Config { .. } => ErrorCode::ConfigError,
            CryptoError::Internal { .. } => ErrorCode::InternalError,
        }
    }

    /// Returns true if this error is recoverable.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            CryptoError::Io(_)
                | CryptoError::Hash(HashError::FileRead { .. })
                | CryptoError::Config { .. }
        )
    }
}
