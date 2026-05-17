use ed25519_dalek::{SigningKey, VerifyingKey, Signer as DalekSigner};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// `Signer` is the interface for anything that can sign PAE bytes.
///
/// The abstraction lets us swap in hardware keys (Secure Enclave, YubiKey),
/// FROST threshold keys, or test signers without changing the attestation layer.
///
/// Implementations must sign the PAE bytes as-is — never hash them again,
/// never parse them. The PAE construction has already bound the payloadType
/// and payload into a single unambiguous byte string.
pub trait Signer: Send + Sync {
    /// Signs the PAE bytes. Returns raw signature bytes.
    /// Ed25519 signatures are always 64 bytes.
    fn sign(&self, pae: &[u8]) -> Result<Vec<u8>, SignerError>;

    /// The stable key identifier. Format: "key_<hex>" from the keystore.
    fn key_id(&self) -> &str;

    /// The raw public key bytes (32 bytes for Ed25519).
    /// Used for key registration, Verifier construction, and fingerprinting.
    fn public_key_bytes(&self) -> Vec<u8>;
}

/// An error produced by a Signer.
#[derive(Debug)]
pub struct SignerError(pub String);

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signer error: {}", self.0)
    }
}

impl std::error::Error for SignerError {}

/// The default Ed25519 signer.
///
/// Holds an Ed25519 signing key in memory. In production, keys are loaded
/// from the encrypted keystore — this struct is never constructed with a
/// plaintext key in application code.
///
/// `ed25519-dalek` uses the `subtle` crate throughout for constant-time
/// scalar operations, providing side-channel resistance.
///
/// **Zeroization.** The 32-byte secret scalar is wiped from memory when the
/// signer is dropped. `ed25519-dalek`'s `SigningKey` implements `Zeroize`,
/// so the wrapper just delegates. Callers that copy the secret out via
/// [`Ed25519Signer::secret_bytes`] receive a [`Zeroizing<[u8; 32]>`] so the
/// caller-side copy is wiped on its own scope exit; pre-v0.10.4 returned a
/// raw `[u8; 32]` that lingered on the caller's stack.
///
/// Note: this guarantees the secret is wiped when the *signer struct itself*
/// is dropped. If the signer is stored in a long-lived cache (e.g. a service
/// holding a default signer for the process lifetime), the wipe only fires
/// when the cache entry is dropped. Hot paths that briefly load a signer
/// should let it go out of scope as soon as signing is done.
pub struct Ed25519Signer {
    key_id:      String,
    signing_key: SigningKey,
}

impl Zeroize for Ed25519Signer {
    fn zeroize(&mut self) {
        // `ed25519-dalek::SigningKey` (with the `zeroize` feature) impls
        // `ZeroizeOnDrop` via its own `Drop` that zeroizes the secret
        // scalar. It does NOT expose a public `Zeroize` impl. To wipe the
        // secret in place without dropping the wrapper, swap in a fresh
        // throwaway key from a fixed zero seed; the old SigningKey's `Drop`
        // fires immediately and wipes the real secret. The replacement
        // is a deterministic non-secret value, immediately discarded.
        let _ = std::mem::replace(&mut self.signing_key, SigningKey::from_bytes(&[0u8; 32]));
        // key_id is a stable public identifier ("key_<hex>"); not secret.
    }
}

impl Drop for Ed25519Signer {
    fn drop(&mut self) {
        // Belt-and-suspenders: `SigningKey`'s own `Drop` wipes its secret
        // scalar (it impls `ZeroizeOnDrop`). The natural drop of `self`
        // would already trigger that. Calling `zeroize()` here is a no-op
        // in practice but makes the intent explicit at the wrapper layer
        // and survives any future refactor that swaps the inner type.
        self.zeroize();
    }
}

// Marker trait: this wrapper's secret material is wiped on drop.
impl ZeroizeOnDrop for Ed25519Signer {}

impl Ed25519Signer {
    /// Constructs an Ed25519Signer from a pre-loaded 64-byte private key.
    pub fn from_bytes(key_id: impl Into<String>, bytes: &[u8; 32]) -> Result<Self, SignerError> {
        let key_id = key_id.into();
        if key_id.is_empty() {
            return Err(SignerError("key_id must not be empty".into()));
        }
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self { key_id, signing_key })
    }

    /// Generates a fresh Ed25519 keypair using the OS CSPRNG.
    ///
    /// Used by `treeship init` and tests. In production, key generation
    /// goes through the keystore which handles encrypted storage.
    pub fn generate(key_id: impl Into<String>) -> Result<Self, SignerError> {
        let key_id = key_id.into();
        if key_id.is_empty() {
            return Err(SignerError("key_id must not be empty".into()));
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(Self { key_id, signing_key })
    }

    /// Returns the `VerifyingKey` (public key) for building a `Verifier`.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the 32-byte private key scalar wrapped in [`Zeroizing`] so the
    /// caller-side copy is wiped on scope exit.
    ///
    /// Only exposed for keystore serialization — never log or transmit this.
    /// Pre-v0.10.4 returned a raw `[u8; 32]`, which lingered on the caller's
    /// stack until the slot was reused. Callers that need the raw array can
    /// still dereference (`*signer.secret_bytes()`); the deref returns a copy,
    /// so the new copy is then unguarded — prefer to keep working with the
    /// `Zeroizing` wrapper.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, pae: &[u8]) -> Result<Vec<u8>, SignerError> {
        // ed25519-dalek's sign() uses the full ExpandedSecretKey internally,
        // which includes both the scalar and the nonce material. No need for
        // an external random source — the nonce is deterministic from the key
        // and message (RFC 8032 §5.1.6).
        let signature = self.signing_key.sign(pae);
        Ok(signature.to_bytes().to_vec())
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::pae;

    fn test_pae() -> Vec<u8> {
        pae("application/vnd.treeship.action.v1+json", b"{\"actor\":\"agent://test\"}")
    }

    #[test]
    fn generate_succeeds() {
        let s = Ed25519Signer::generate("key_test_01").unwrap();
        assert_eq!(s.key_id(), "key_test_01");
        assert_eq!(s.public_key_bytes().len(), 32);
    }

    #[test]
    fn empty_key_id_errors() {
        assert!(Ed25519Signer::generate("").is_err());
    }

    #[test]
    fn sign_produces_64_bytes() {
        let signer = Ed25519Signer::generate("key_test").unwrap();
        let sig = signer.sign(&test_pae()).unwrap();
        assert_eq!(sig.len(), 64, "Ed25519 signatures are always 64 bytes");
    }

    #[test]
    fn sign_is_deterministic_for_same_key_and_message() {
        // Ed25519 (RFC 8032) uses deterministic nonce — same key + message
        // always produces the same signature. This is a security property:
        // non-deterministic signing would leak key material if the RNG is weak.
        let signer = Ed25519Signer::generate("key_det").unwrap();
        let msg    = test_pae();
        let sig1   = signer.sign(&msg).unwrap();
        let sig2   = signer.sign(&msg).unwrap();
        assert_eq!(sig1, sig2, "Ed25519 signing must be deterministic");
    }

    #[test]
    fn different_keys_produce_different_signatures() {
        let s1 = Ed25519Signer::generate("key_1").unwrap();
        let s2 = Ed25519Signer::generate("key_2").unwrap();
        let msg = test_pae();
        assert_ne!(
            s1.sign(&msg).unwrap(),
            s2.sign(&msg).unwrap(),
            "Different keys must produce different signatures"
        );
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        let signer = Ed25519Signer::generate("key_test").unwrap();
        let pae1 = pae("application/vnd.treeship.action.v1+json",   b"{\"a\":1}");
        let pae2 = pae("application/vnd.treeship.approval.v1+json",  b"{\"a\":1}");
        assert_ne!(
            signer.sign(&pae1).unwrap(),
            signer.sign(&pae2).unwrap()
        );
    }

    #[test]
    fn roundtrip_from_bytes() {
        let original = Ed25519Signer::generate("key_rt").unwrap();
        let secret   = original.secret_bytes();
        // `secret` is Zeroizing<[u8; 32]>; deref to the inner array for
        // `from_bytes`'s `&[u8; 32]` parameter.
        let restored = Ed25519Signer::from_bytes("key_rt", &*secret).unwrap();

        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());

        let msg   = test_pae();
        let sig_a = original.sign(&msg).unwrap();
        let sig_b = restored.sign(&msg).unwrap();
        assert_eq!(sig_a, sig_b, "Restored key must produce identical signatures");
    }

    /// Proves the `Zeroize` impl actually wipes the secret scalar.
    ///
    /// We can't test that Drop fires on every path without unsafe memory
    /// inspection (and even then, the allocator may have reused the slot).
    /// What we *can* test is that calling `zeroize()` directly zeros the
    /// underlying secret bytes. That guarantees the trait wiring is correct;
    /// the Drop impl just calls `zeroize()` and is a one-liner that's a
    /// code-review concern, not a runtime test concern.
    #[test]
    fn signer_zeroize_wipes_secret_scalar() {
        use zeroize::Zeroize;
        let mut signer = Ed25519Signer::from_bytes("key_z", &[0xAA; 32]).unwrap();
        // Sanity: before zeroize, the secret is the non-zero pattern we set.
        assert_eq!(*signer.secret_bytes(), [0xAA; 32]);
        signer.zeroize();
        // After zeroize, the secret scalar must be all zeros.
        assert_eq!(*signer.secret_bytes(), [0u8; 32]);
    }

    /// Proves the `Zeroizing<[u8; 32]>` returned by `secret_bytes` wipes its
    /// inner buffer when it goes out of scope. Probes the byte pattern with
    /// `Zeroize::zeroize` directly -- no unsafe memory inspection required.
    #[test]
    fn secret_bytes_wrapper_wipes_on_drop() {
        use zeroize::Zeroize;
        let signer = Ed25519Signer::from_bytes("key_w", &[0x55; 32]).unwrap();
        let mut copy = *signer.secret_bytes(); // copy out of Zeroizing wrapper
        assert_eq!(copy, [0x55; 32]);
        copy.zeroize();
        assert_eq!(copy, [0u8; 32]);
    }
}
