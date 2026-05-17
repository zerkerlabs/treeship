use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::attestation::{Signer, SignerError};
use crate::statements::unix_to_rfc3339;
use crate::trust::{TrustRootKind, TrustRootStore};

use super::tree::MerkleTree;

/// A signed snapshot of the Merkle tree at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub index: u64,
    /// Root hash in `sha256:<hex>` format.
    pub root: String,
    pub tree_size: usize,
    pub height: usize,
    /// RFC 3339 timestamp.
    pub signed_at: String,
    /// Key ID of the signer.
    pub signer: String,
    /// Base64url-encoded public key bytes.
    pub public_key: String,
    /// Base64url-encoded Ed25519 signature of the canonical form.
    pub signature: String,
    /// Merkle algorithm used. Missing = v1 (sha256-duplicate-last).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Optional ZK chain proof result (added when proof is ready).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zk_proof: Option<ChainProofSummary>,
}

/// Summary of a RISC Zero chain proof, embedded in a Merkle checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProofSummary {
    pub image_id: String,
    pub all_signatures_valid: bool,
    pub chain_intact: bool,
    pub approval_nonces_matched: bool,
    pub artifact_count: u64,
    pub public_key_digest: String,
    pub proved_at: String,
}

/// Errors from checkpoint creation.
#[derive(Debug)]
pub enum CheckpointError {
    EmptyTree,
    Signing(SignerError),
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTree => write!(f, "cannot checkpoint an empty tree"),
            Self::Signing(e) => write!(f, "checkpoint signing failed: {}", e),
        }
    }
}

impl std::error::Error for CheckpointError {}
impl From<SignerError> for CheckpointError {
    fn from(e: SignerError) -> Self {
        Self::Signing(e)
    }
}

impl Checkpoint {
    /// Create a signed checkpoint from the current tree state.
    ///
    /// The canonical form for signing is: `{root}|{tree_size}|{signed_at}`
    pub fn create(
        index: u64,
        tree: &MerkleTree,
        signer: &dyn Signer,
    ) -> Result<Self, CheckpointError> {
        let root_bytes = tree.root().ok_or(CheckpointError::EmptyTree)?;
        let root = format!("sha256:{}", hex::encode(root_bytes));

        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let signed_at = unix_to_rfc3339(secs);

        let canonical = format!("{}|{}|{}|{}|{}|{}", index, root, tree.len(), tree.height(), signer.key_id(), signed_at);
        let sig_bytes = signer.sign(canonical.as_bytes())?;
        let signature = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let public_key = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());

        Ok(Self {
            index,
            root,
            tree_size: tree.len(),
            height: tree.height(),
            signed_at,
            signer: signer.key_id().to_string(),
            public_key,
            signature,
            algorithm: Some(super::tree::MERKLE_ALGORITHM_V2.to_string()),
            zk_proof: None,
        })
    }

    /// Verify the checkpoint signature AND require the embedded public key
    /// to be present in `trust` under kind `HubCheckpoint`. Returns `false`
    /// on any failure (bad encoding, wrong key size, invalid signature,
    /// untrusted issuer, no trust configured). Never panics.
    ///
    /// Trust pinning is mandatory. A self-signed checkpoint (an attacker
    /// minting their own keypair, embedding the pubkey, and signing the
    /// canonical bytes) used to satisfy this function -- it now does not,
    /// because `trust.contains` rejects unknown issuers.
    pub fn verify(&self, trust: &TrustRootStore) -> bool {
        let pub_bytes = match URL_SAFE_NO_PAD.decode(&self.public_key) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let pub_array: [u8; 32] = match pub_bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let vk = match VerifyingKey::from_bytes(&pub_array) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Trust pin: the embedded pubkey must be a configured root.
        // An empty store or no matching root rejects -- closes the
        // self-signed loophole.
        if !trust.contains(&vk, TrustRootKind::HubCheckpoint) {
            return false;
        }

        let canonical = format!("{}|{}|{}|{}|{}|{}", self.index, self.root, self.tree_size, self.height, self.signer, self.signed_at);

        let sig_bytes = match URL_SAFE_NO_PAD.decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_array);

        vk.verify(canonical.as_bytes(), &sig).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Trust-pin tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod trust_pin_tests {
    use super::*;
    use crate::attestation::{Ed25519Signer, Signer};
    use crate::merkle::MerkleTree;
    use crate::trust::{encode_ed25519_pubkey, TrustRoot, TrustRootKind, TrustRootStore};

    fn signer_and_tree() -> (Ed25519Signer, MerkleTree) {
        let mut tree = MerkleTree::new();
        tree.append("art_alpha");
        tree.append("art_beta");
        let signer = Ed25519Signer::generate("key_test").unwrap();
        (signer, tree)
    }

    fn trust_with(signer: &Ed25519Signer) -> TrustRootStore {
        use ed25519_dalek::VerifyingKey;
        let pk_bytes: [u8; 32] = signer.public_key_bytes().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        TrustRootStore::with_roots(vec![TrustRoot {
            key_id:     signer.key_id().to_string(),
            public_key: encode_ed25519_pubkey(&vk),
            kind:       TrustRootKind::HubCheckpoint,
            label:      "trusted hub".into(),
            added_at:   "2026-05-15T00:00:00Z".into(),
        }])
    }

    /// The headline case from the audit: a checkpoint signed by a key
    /// the operator never trusted MUST NOT verify, even though the
    /// signature math is internally consistent.
    #[test]
    fn verify_rejects_unknown_pubkey() {
        let (signer, tree) = signer_and_tree();
        let cp = Checkpoint::create(1, &tree, &signer).unwrap();

        // Different signer's key is the only one in the store.
        let other = Ed25519Signer::generate("other").unwrap();
        let trust = trust_with(&other);

        assert!(!cp.verify(&trust),
                "unknown issuer must be rejected even with valid signature");
    }

    /// Happy path: the issuer is pinned, the signature math is good,
    /// verify returns true.
    #[test]
    fn verify_accepts_trusted_pubkey() {
        let (signer, tree) = signer_and_tree();
        let cp = Checkpoint::create(1, &tree, &signer).unwrap();
        let trust = trust_with(&signer);
        assert!(cp.verify(&trust), "trusted issuer + good signature must verify");
    }

    /// No trust configured at all (empty store) is the operator's
    /// fresh-install state. Verification must fail closed: a verifier
    /// without a trust set cannot vouch for anyone.
    #[test]
    fn verify_rejects_with_no_trust_configured() {
        let (signer, tree) = signer_and_tree();
        let cp = Checkpoint::create(1, &tree, &signer).unwrap();
        let trust = TrustRootStore::empty();
        assert!(!cp.verify(&trust),
                "empty trust store must reject all checkpoints");
    }

    /// Trust pinning is kind-scoped: a key trusted for AgentCert is
    /// NOT trusted for a Merkle checkpoint. This is the firewall
    /// between certificate issuance and journal anchoring.
    #[test]
    fn verify_rejects_pubkey_pinned_for_wrong_kind() {
        let (signer, tree) = signer_and_tree();
        let cp = Checkpoint::create(1, &tree, &signer).unwrap();

        use ed25519_dalek::VerifyingKey;
        let pk_bytes: [u8; 32] = signer.public_key_bytes().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let mismatched = TrustRootStore::with_roots(vec![TrustRoot {
            key_id:     signer.key_id().to_string(),
            public_key: encode_ed25519_pubkey(&vk),
            kind:       TrustRootKind::AgentCert, // wrong kind!
            label:      "trusted for agent certs only".into(),
            added_at:   "2026-05-15T00:00:00Z".into(),
        }]);
        assert!(!cp.verify(&mismatched),
                "kind discrimination must keep AgentCert roots out of checkpoint trust");
    }

    /// Forge attempt -- attacker re-signs with a non-trusted key.
    /// The signature is internally valid (sig was made over canonical
    /// bytes by the embedded pubkey) but the pubkey is unknown to the
    /// operator. Pre-pin this passed; post-pin it must not.
    #[test]
    fn verify_rejects_attacker_self_signed_forgery() {
        // Attacker mints their own keypair, builds a checkpoint over
        // their own canonical bytes, embeds their own pubkey, signs.
        let (attacker_signer, tree) = signer_and_tree();
        let forgery = Checkpoint::create(99, &tree, &attacker_signer).unwrap();

        // Honest operator has trusted a DIFFERENT issuer.
        let honest = Ed25519Signer::generate("honest_hub").unwrap();
        let trust = trust_with(&honest);

        assert!(!forgery.verify(&trust),
                "self-signed forgery must not verify against operator's trust set");
    }
}
