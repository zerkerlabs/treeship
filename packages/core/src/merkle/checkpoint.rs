use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::attestation::{Signer, SignerError};
use crate::statements::unix_to_rfc3339;

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
        })
    }

    /// Verify the checkpoint signature. Returns `false` on any failure
    /// (bad encoding, wrong key size, invalid signature). Never panics.
    pub fn verify(&self) -> bool {
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
