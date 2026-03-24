//! Digital Signing Module
//!
//! Provides Ed25519 digital signature operations using the `ring` crate.
//!
//! Ed25519 properties:
//! - 32-byte keys, 64-byte signatures
//! - Constant-time operations (immune to timing attacks)
//! - Deterministic signing (no RNG needed at sign time)
//! - ~50,000 signatures/sec, ~17,000 verifications/sec

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use zeroize::Zeroizing;

use crate::error::SigningError;

/// Ed25519 signature size in bytes.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Ed25519 public key size in bytes.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// An Ed25519 digital signature (64 bytes).
#[derive(Debug, Clone)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Returns the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the signature as a hex-encoded string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Creates a signature from raw bytes.
    ///
    /// Returns an error if the byte slice is not exactly 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigningError> {
        if bytes.len() != ED25519_SIGNATURE_LEN {
            return Err(SigningError::InvalidSignatureFormat {
                expected: ED25519_SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// Ed25519 key pair for signing operations.
///
/// Wraps `ring::signature::Ed25519KeyPair` with PKCS#8 storage
/// and automatic zeroization of key material on drop.
pub struct SigningKeyPair {
    key_pair: Ed25519KeyPair,
    pkcs8_bytes: Zeroizing<Vec<u8>>,
}

impl SigningKeyPair {
    /// Generates a new random Ed25519 key pair.
    pub fn generate() -> Result<Self, SigningError> {
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| {
            SigningError::KeyGenerationFailed {
                reason: e.to_string(),
            }
        })?;
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();
        let key_pair =
            Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref()).map_err(|e| {
                SigningError::KeyParsingFailed {
                    reason: e.to_string(),
                }
            })?;
        Ok(Self {
            key_pair,
            pkcs8_bytes: Zeroizing::new(pkcs8_bytes),
        })
    }

    /// Loads a key pair from PKCS#8 encoded bytes.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, SigningError> {
        let key_pair =
            Ed25519KeyPair::from_pkcs8(bytes).map_err(|e| SigningError::KeyParsingFailed {
                reason: e.to_string(),
            })?;
        Ok(Self {
            key_pair,
            pkcs8_bytes: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// Returns the PKCS#8 encoded private key bytes.
    ///
    /// Handle with care — this is sensitive key material.
    pub fn to_pkcs8(&self) -> &[u8] {
        &self.pkcs8_bytes
    }

    /// Signs a message, returning a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.key_pair.sign(message);
        Signature(sig.as_ref().to_vec())
    }

    /// Returns the public key bytes (32 bytes).
    pub fn public_key(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Returns the public key as a hex-encoded string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }
}

/// Verifies an Ed25519 signature against a message and public key.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if the signature does not match.
/// Returns `Err` only for malformed inputs.
pub fn verify_signature(
    message: &[u8],
    signature: &Signature,
    public_key: &[u8],
) -> Result<bool, SigningError> {
    if public_key.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(SigningError::InvalidSignatureFormat {
            expected: ED25519_PUBLIC_KEY_LEN,
            actual: public_key.len(),
        });
    }

    let peer_public_key = UnparsedPublicKey::new(&ED25519, public_key);
    match peer_public_key.verify(message, signature.as_bytes()) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = SigningKeyPair::generate().unwrap();
        assert_eq!(kp.public_key().len(), ED25519_PUBLIC_KEY_LEN);
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = SigningKeyPair::generate().unwrap();
        let sig = kp.sign(b"hello world");
        assert_eq!(sig.as_bytes().len(), ED25519_SIGNATURE_LEN);

        let valid = verify_signature(b"hello world", &sig, kp.public_key()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = SigningKeyPair::generate().unwrap();
        let sig = kp.sign(b"original message");

        let valid = verify_signature(b"tampered message", &sig, kp.public_key()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = SigningKeyPair::generate().unwrap();
        let kp2 = SigningKeyPair::generate().unwrap();
        let sig = kp1.sign(b"message");

        let valid = verify_signature(b"message", &sig, kp2.public_key()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_pkcs8_roundtrip() {
        let kp1 = SigningKeyPair::generate().unwrap();
        let pkcs8 = kp1.to_pkcs8().to_vec();
        let kp2 = SigningKeyPair::from_pkcs8(&pkcs8).unwrap();

        // Same public key after reimport
        assert_eq!(kp1.public_key(), kp2.public_key());

        // Signature from kp1 verifies with kp2's public key
        let sig = kp1.sign(b"test");
        let valid = verify_signature(b"test", &sig, kp2.public_key()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_public_key_hex() {
        let kp = SigningKeyPair::generate().unwrap();
        let hex_key = kp.public_key_hex();
        assert_eq!(hex_key.len(), ED25519_PUBLIC_KEY_LEN * 2);
        assert!(hex_key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_signature_from_bytes_roundtrip() {
        let kp = SigningKeyPair::generate().unwrap();
        let sig = kp.sign(b"message");
        let bytes = sig.as_bytes().to_vec();
        let restored = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_invalid_signature_format() {
        let result = Signature::from_bytes(&[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pkcs8() {
        let result = SigningKeyPair::from_pkcs8(b"not valid pkcs8 data");
        assert!(result.is_err());
    }
}
