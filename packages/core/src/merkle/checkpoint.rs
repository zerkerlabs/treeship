use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attestation::{Signer, SignerError};
use crate::statements::unix_to_rfc3339;
use crate::trust::{TrustRootKind, TrustRootStore};

use super::tree::{MerkleTree, MERKLE_VERSION_V1};

/// Canonical signing format versions. The merkle version (the bytes the
/// tree is hashed under, see `MERKLE_VERSION_V1`/`MERKLE_VERSION_V2`) and
/// the canonical signing version (the bytes the checkpoint's signature
/// covers) are independent.
///
/// - `1` — legacy pre-v0.10.3 form, `"{index}|{root}|...|{signed_at}"`.
///   No merkle_version, algorithm, or zk_proof in the canonical.
/// - `2` — v0.10.3, `"v2|{merkle_version}|{index}|..."`. Binds
///   merkle_version to close the v1/v2 hashing downgrade.
/// - `3` — v0.10.4, also binds `algorithm`, `zk_proof_digest`, and the
///   canonical_version itself. Closes wire-mutation on those fields.
pub const CANONICAL_VERSION_V1: u8 = 1;
pub const CANONICAL_VERSION_V2: u8 = 2;
pub const CANONICAL_VERSION_V3: u8 = 3;

/// Default canonical_version for `#[serde(default)]` so v0.10.3-era
/// checkpoints (signed under v2) continue to verify when loaded by
/// v0.10.4+ code. Pre-v0.10.3 checkpoints have `merkle_version == 1`
/// which overrides this and forces v1 dispatch.
pub fn default_canonical_version_v2() -> u8 {
    CANONICAL_VERSION_V2
}

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
    ///
    /// Currently this string is fully derived from `merkle_version`
    /// (`v1 → "sha256-duplicate-last"`, `v2 → "sha256-rfc9162"`) so it
    /// is informationally redundant with `merkle_version`. It is still
    /// bound into the v3 canonical to lock the on-wire value: even
    /// redundant fields become tampering surface once they're displayed
    /// or fed into downstream tooling. Removable in a future canonical
    /// (v4) once a deprecation window has passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Merkle format version byte (RFC 9162 domain separation). Absent
    /// on v0.10.2-and-earlier checkpoints — `#[serde(default)]` fills it
    /// with `1` so legacy checkpoints continue to verify under v1
    /// hashing. New checkpoints emit `2`.
    #[serde(default = "super::tree::default_merkle_version_v1")]
    pub merkle_version: u8,
    /// Optional ZK chain proof result (added when proof is ready).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zk_proof: Option<ChainProofSummary>,
    /// Canonical signing format version (independent of `merkle_version`).
    /// Pre-v0.10.4 checkpoints don't carry this; `#[serde(default)]` fills
    /// it with `2` so v0.10.3-era checkpoints continue to verify under the
    /// v2 canonical. v0.10.4+ checkpoints emit `3`. Pre-v0.10.3 checkpoints
    /// have `merkle_version == 1`, which overrides this and dispatches the
    /// legacy v1 canonical regardless. This field is itself bound into the
    /// v3 canonical to prevent a downgrade-by-relabel attack.
    #[serde(default = "default_canonical_version_v2")]
    pub canonical_version: u8,
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
    /// Build the canonical string for signing/verification.
    ///
    /// Three formats coexist by design. Dispatch is governed entirely by
    /// the (trusted) `canonical_version` argument — never inferred from
    /// wire-controllable field presence — *with one exception*: a
    /// `merkle_version == 1` checkpoint always uses the v1 legacy form
    /// regardless of `canonical_version`, because pre-v0.10.3 checkpoints
    /// never carried `canonical_version` and were signed under the bare
    /// pipe-delimited bytes.
    ///
    /// * **v1 (`merkle_version == 1`):** the original pre-v0.10.3 form,
    ///   `"{index}|{root}|{tree_size}|{height}|{signer}|{signed_at}"`. Old
    ///   checkpoints in the wild were signed under this exact string and
    ///   must continue to verify byte-identically.
    ///
    /// * **v2 (`canonical_version == 2`, `merkle_version >= 2`):** v0.10.3
    ///   form,
    ///   `"v2|{merkle_version}|{index}|{root}|{tree_size}|{height}|{signer}|{signed_at}"`.
    ///   Binds `merkle_version` to close the v1/v2 hashing downgrade.
    ///   `algorithm` and `zk_proof` are NOT bound in v2; they were
    ///   wire-mutable in v0.10.3, which is the v0.10.4 audit finding this
    ///   v3 form closes.
    ///
    /// * **v3 (`canonical_version == 3`, `merkle_version >= 2`):** v0.10.4
    ///   form,
    ///   `"v3|{canonical_version}|{merkle_version}|{algorithm_or_empty}|{zk_proof_digest_or_empty}|{index}|{root}|{tree_size}|{height}|{signer}|{signed_at}"`.
    ///   - `canonical_version` is itself bound to prevent downgrade-by-
    ///     relabel: an attacker flipping `canonical_version: 3 → 2` on
    ///     the wire breaks the signature because the bytes recanonicalize
    ///     differently under v2 dispatch.
    ///   - `algorithm_or_empty` is the verbatim algorithm string, or empty
    ///     when the field is `None`. Currently redundant with
    ///     `merkle_version` but bound to lock the on-wire value.
    ///   - `zk_proof_digest_or_empty` is the hex-encoded SHA-256 of the
    ///     sorted-key JSON serialization of `zk_proof`, or empty for `None`.
    ///     Hash-of-canonical-JSON rather than direct embedding because
    ///     `ChainProofSummary` is a multi-field struct that doesn't
    ///     compose with pipe-delimiting.
    ///
    /// **Breaking change note:** any third-party verifier that reproduces
    /// the canonical string outside this Rust core (hand-rolled JS/Go/Python
    /// checkers) must mirror this dispatch. The `verify-js` package
    /// consumes WASM and inherits the change automatically.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn canonical_for_signing(
        canonical_version: u8,
        merkle_version: u8,
        algorithm: Option<&str>,
        zk_proof: Option<&ChainProofSummary>,
        index: u64,
        root: &str,
        tree_size: usize,
        height: usize,
        signer: &str,
        signed_at: &str,
    ) -> String {
        // Legacy v1 path is forced by merkle_version, not canonical_version.
        // Pre-v0.10.3 checkpoints never carried canonical_version and were
        // signed under the bare pipe-delimited bytes.
        if merkle_version == MERKLE_VERSION_V1 {
            return format!(
                "{}|{}|{}|{}|{}|{}",
                index, root, tree_size, height, signer, signed_at,
            );
        }

        match canonical_version {
            CANONICAL_VERSION_V2 => format!(
                "v2|{}|{}|{}|{}|{}|{}|{}",
                merkle_version, index, root, tree_size, height, signer, signed_at,
            ),
            // v3 (and any unrecognized newer version we treat as v3 here;
            // the dispatcher in `verify` rejects unknown canonical_versions
            // up front, so this branch is only reached for known v3).
            _ => {
                let algo_field = algorithm.unwrap_or("");
                let zk_digest = zk_proof
                    .map(zk_proof_digest_hex)
                    .unwrap_or_default();
                format!(
                    "v3|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                    canonical_version,
                    merkle_version,
                    algo_field,
                    zk_digest,
                    index,
                    root,
                    tree_size,
                    height,
                    signer,
                    signed_at,
                )
            }
        }
    }

    /// Create a signed checkpoint from the current tree state.
    ///
    /// New checkpoints are signed under canonical v3, which binds
    /// `merkle_version`, `algorithm`, and `zk_proof` in addition to the
    /// v2-bound fields. `zk_proof` is `None` at create time; if the
    /// daemon later attaches a ZK proof summary it must re-sign (which
    /// today it doesn't — see `update_checkpoint_with_proof`; that path
    /// is now considered tamper-surface and will be fixed in a follow-up).
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

        // New v0.10.4 checkpoints emit canonical v3 unless the tree is
        // v1 (in which case canonical_for_signing forces the legacy form
        // and the canonical_version field is informational only).
        let canonical_version = if tree.version() == MERKLE_VERSION_V1 {
            CANONICAL_VERSION_V1
        } else {
            CANONICAL_VERSION_V3
        };
        let algorithm = Some(super::tree::MERKLE_ALGORITHM_V2.to_string());
        let zk_proof: Option<ChainProofSummary> = None;

        let canonical = Self::canonical_for_signing(
            canonical_version,
            tree.version(),
            algorithm.as_deref(),
            zk_proof.as_ref(),
            index,
            &root,
            tree.len(),
            tree.height(),
            signer.key_id(),
            &signed_at,
        );
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
            algorithm,
            merkle_version: tree.version(),
            zk_proof,
            canonical_version,
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

        // Reject unknown canonical_versions up front. Pre-v0.10.3
        // checkpoints have merkle_version == 1 which forces the legacy
        // v1 canonical regardless of this field; for newer checkpoints
        // canonical_version must be 2 or 3. Anything else is either a
        // misconfigured signer or a future format this verifier doesn't
        // understand — fail closed in both cases.
        if self.merkle_version != MERKLE_VERSION_V1
            && self.canonical_version != CANONICAL_VERSION_V2
            && self.canonical_version != CANONICAL_VERSION_V3
        {
            return false;
        }

        let canonical = Self::canonical_for_signing(
            self.canonical_version,
            self.merkle_version,
            self.algorithm.as_deref(),
            self.zk_proof.as_ref(),
            self.index,
            &self.root,
            self.tree_size,
            self.height,
            &self.signer,
            &self.signed_at,
        );

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

/// SHA-256 digest of the canonical (sorted-key) JSON serialization of a
/// `ChainProofSummary`, hex-encoded. Used to fold the multi-field zk_proof
/// struct into the pipe-delimited v3 canonical signing string.
///
/// We use `serde_json::to_value` to materialize the value, then
/// re-serialize via `BTreeMap` to force sorted keys. `serde_json` writes
/// struct fields in declaration order by default, which is stable in
/// practice but is a Rust-source-level invariant rather than a wire-format
/// one. Sorted-key JSON is the format-level invariant (akin to RFC 8785's
/// `keys_in_alphabetical_order` rule) and is what any third-party
/// verifier must reproduce.
///
/// Caller's contract: pass `Some(&summary)` for present, omit entirely
/// (the canonical writes an empty field) for `None`. We do not call this
/// for `None` so the sentinel can't collide with a real digest.
fn zk_proof_digest_hex(summary: &ChainProofSummary) -> String {
    let value = serde_json::to_value(summary)
        .expect("ChainProofSummary serializes to JSON value");
    // Re-serialize through BTreeMap to enforce sorted keys at every level.
    // For ChainProofSummary specifically this is a flat object of scalars,
    // but doing it through the generic walker keeps the function honest
    // if the struct grows nested fields later.
    let canonical = canonical_json_string(&value);
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

/// Sorted-key canonical JSON. Compact (no whitespace). For object keys
/// the ordering is bytewise on the UTF-8 representation, matching what
/// `BTreeMap<String, _>` produces. Arrays preserve order. Numbers,
/// booleans, strings, and null serialize as serde_json's default
/// (which is JSON-spec compliant; we do not need RFC 8785's full
/// numeric normalization for `ChainProofSummary` because every numeric
/// field there is an integer).
fn canonical_json_string(value: &serde_json::Value) -> String {
    use std::collections::BTreeMap;
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&String, String> = map
                .iter()
                .map(|(k, v)| (k, canonical_json_string(v)))
                .collect();
            let mut out = String::from("{");
            let mut first = true;
            for (k, v) in sorted {
                if !first {
                    out.push(',');
                }
                first = false;
                // Re-serialize the key as a JSON string to handle escapes.
                let key_json = serde_json::to_string(k)
                    .expect("string serializes to JSON");
                out.push_str(&key_json);
                out.push(':');
                out.push_str(&v);
            }
            out.push('}');
            out
        }
        serde_json::Value::Array(items) => {
            let mut out = String::from("[");
            let mut first = true;
            for item in items {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&canonical_json_string(item));
            }
            out.push(']');
            out
        }
        other => serde_json::to_string(other)
            .expect("scalar serializes to JSON"),
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

// ---------------------------------------------------------------------------
// v0.10.4 canonical v3 tests
//
// These pin the fix for the second canonical break: v0.10.3's v2 form bound
// merkle_version but left `algorithm` and `zk_proof` wire-mutable. v3 binds
// both, plus the canonical_version itself (to prevent downgrade-by-relabel).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod canonical_v3_tests {
    use super::*;
    use crate::attestation::{Ed25519Signer, Signer};
    use crate::merkle::tree::{MerkleTree, MERKLE_ALGORITHM_V2, MERKLE_VERSION_V1, MERKLE_VERSION_V2};
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

    fn sample_zk_proof() -> ChainProofSummary {
        ChainProofSummary {
            image_id: "sha256:beef".into(),
            all_signatures_valid: true,
            chain_intact: true,
            approval_nonces_matched: true,
            artifact_count: 7,
            public_key_digest: "sha256:cafe".into(),
            proved_at: "2026-05-17T01:23:45Z".into(),
        }
    }

    /// Sanity: a freshly-created checkpoint is v3.
    #[test]
    fn fresh_checkpoint_is_v3() {
        let (signer, tree) = signer_and_tree();
        let cp = Checkpoint::create(1, &tree, &signer).unwrap();
        assert_eq!(cp.canonical_version, CANONICAL_VERSION_V3);
        assert_eq!(cp.merkle_version, MERKLE_VERSION_V2);
        assert!(cp.algorithm.is_some());
    }

    /// The headline v0.10.4 audit fix: mutating `algorithm` on the wire
    /// of a v3-signed checkpoint must invalidate the signature.
    #[test]
    fn algorithm_tamper_detected() {
        let (signer, tree) = signer_and_tree();
        let trust = trust_with(&signer);
        let mut cp = Checkpoint::create(1, &tree, &signer).unwrap();
        assert!(cp.verify(&trust), "baseline must verify");

        cp.algorithm = Some("sha256-attacker".into());
        assert!(
            !cp.verify(&trust),
            "algorithm field mutation on the wire must break the v3 signature"
        );

        // Also: clearing the field to None must break it.
        let mut cp2 = Checkpoint::create(1, &tree, &signer).unwrap();
        cp2.algorithm = None;
        assert!(
            !cp2.verify(&trust),
            "removing algorithm on the wire must break the v3 signature"
        );
    }

    /// Same fix for `zk_proof`: an attacker attaching, swapping, or
    /// removing a ChainProofSummary on the wire must invalidate the
    /// signature.
    #[test]
    fn zk_proof_tamper_detected() {
        let (signer, tree) = signer_and_tree();
        let trust = trust_with(&signer);

        // Case A: attacker attaches a fabricated proof to a checkpoint
        // that was signed with zk_proof: None.
        let mut cp_attach = Checkpoint::create(1, &tree, &signer).unwrap();
        assert!(cp_attach.zk_proof.is_none(), "fresh checkpoint must have no proof");
        cp_attach.zk_proof = Some(sample_zk_proof());
        assert!(
            !cp_attach.verify(&trust),
            "attaching a zk_proof on the wire must break the v3 signature"
        );

        // Case B: sign a checkpoint, then mutate a field inside the
        // proof on the wire. Needs a small re-sign helper because
        // Checkpoint::create only sets zk_proof to None.
        let (signer_b, tree_b) = signer_and_tree();
        let trust_b = trust_with(&signer_b);
        let mut cp_swap = checkpoint_signed_with_proof(
            &signer_b, &tree_b, 1, Some(sample_zk_proof()),
        );
        assert!(cp_swap.verify(&trust_b), "freshly signed v3+proof must verify");

        // Mutate one field on the embedded proof.
        let mut tampered = sample_zk_proof();
        tampered.chain_intact = false;
        cp_swap.zk_proof = Some(tampered);
        assert!(
            !cp_swap.verify(&trust_b),
            "mutating a zk_proof field on the wire must break the v3 signature"
        );

        // Case C: strip the proof entirely.
        let mut cp_strip = checkpoint_signed_with_proof(
            &signer_b, &tree_b, 1, Some(sample_zk_proof()),
        );
        cp_strip.zk_proof = None;
        assert!(
            !cp_strip.verify(&trust_b),
            "stripping zk_proof on the wire must break the v3 signature"
        );
    }

    /// v0.10.3-era v2 checkpoints (no canonical_version field on disk;
    /// algorithm present, zk_proof absent) must continue to verify under
    /// v0.10.4 code. This is the legacy-compat guarantee.
    #[test]
    fn v2_legacy_checkpoint_still_verifies() {
        let (signer, tree) = signer_and_tree();
        let trust = trust_with(&signer);

        let cp_v2 = sign_legacy_v2(&signer, &tree, 1);
        assert_eq!(cp_v2.canonical_version, CANONICAL_VERSION_V2);
        assert_eq!(cp_v2.merkle_version, MERKLE_VERSION_V2);
        assert!(
            cp_v2.verify(&trust),
            "v0.10.3-era v2-canonical checkpoint must still verify"
        );

        // And the wire form (no canonical_version field at all) round-trips
        // through #[serde(default)] back to canonical_version: 2.
        let mut json = serde_json::to_value(&cp_v2).unwrap();
        json.as_object_mut().unwrap().remove("canonical_version");
        let reparsed: Checkpoint = serde_json::from_value(json).unwrap();
        assert_eq!(reparsed.canonical_version, CANONICAL_VERSION_V2);
        assert!(
            reparsed.verify(&trust),
            "v2 checkpoint deserialized without canonical_version field must verify"
        );
    }

    /// Pre-v0.10.3 v1 checkpoints (legacy hashing, no canonical tag,
    /// no merkle_version on the wire) must continue to verify under
    /// v0.10.4 code.
    #[test]
    fn v1_legacy_checkpoint_still_verifies() {
        let signer = Ed25519Signer::generate("legacy_key").unwrap();
        let trust = trust_with(&signer);

        // Build a v1 tree so the canonical dispatch forces the legacy
        // form. canonical_version field is informational only for v1.
        let cp_v1 = sign_legacy_v1(&signer, 99, "sha256:legacy_root", 4, 2);
        assert_eq!(cp_v1.merkle_version, MERKLE_VERSION_V1);
        assert!(
            cp_v1.verify(&trust),
            "pre-v0.10.3 v1-canonical checkpoint must still verify"
        );

        // And the wire form without the v1-vintage missing-fields still
        // round-trips and verifies.
        let mut json = serde_json::to_value(&cp_v1).unwrap();
        json.as_object_mut().unwrap().remove("canonical_version");
        json.as_object_mut().unwrap().remove("merkle_version");
        json.as_object_mut().unwrap().remove("algorithm");
        let reparsed: Checkpoint = serde_json::from_value(json).unwrap();
        assert_eq!(reparsed.merkle_version, MERKLE_VERSION_V1);
        assert!(
            reparsed.verify(&trust),
            "pre-v0.10.3 v1 checkpoint stripped of new fields must verify"
        );
    }

    /// Cross-version downgrade: an attacker takes a legitimately
    /// v3-signed checkpoint, relabels it as canonical_version: 2 on
    /// the wire (and strips the new bindings to make the v2 canonical
    /// reproducible), and tries to verify. Must fail — the signature
    /// covers v3-canonical bytes, not v2-canonical bytes.
    #[test]
    fn cross_version_downgrade_v3_to_v2_rejected() {
        let (signer, tree) = signer_and_tree();
        let trust = trust_with(&signer);
        let mut cp = Checkpoint::create(1, &tree, &signer).unwrap();
        assert_eq!(cp.canonical_version, CANONICAL_VERSION_V3);
        assert!(cp.verify(&trust), "baseline v3 must verify");

        // Attacker downgrade: flip the canonical_version tag.
        cp.canonical_version = CANONICAL_VERSION_V2;
        assert!(
            !cp.verify(&trust),
            "v3->v2 canonical_version downgrade must fail (signature covers v3 bytes)"
        );

        // And the attacker can't recover by also stripping algorithm
        // (since v2 doesn't bind it, they might hope the v2 canonical
        // matches the original v3 signature anyway — it must not).
        let (signer2, tree2) = signer_and_tree();
        let trust2 = trust_with(&signer2);
        let mut cp2 = Checkpoint::create(1, &tree2, &signer2).unwrap();
        cp2.canonical_version = CANONICAL_VERSION_V2;
        cp2.algorithm = None;
        assert!(
            !cp2.verify(&trust2),
            "v3->v2 downgrade + strip algorithm must still fail"
        );
    }

    /// Unknown canonical_version (a future format this verifier doesn't
    /// understand) must fail closed.
    #[test]
    fn unknown_canonical_version_rejected() {
        let (signer, tree) = signer_and_tree();
        let trust = trust_with(&signer);
        let mut cp = Checkpoint::create(1, &tree, &signer).unwrap();
        cp.canonical_version = 99;
        assert!(
            !cp.verify(&trust),
            "unknown canonical_version must fail closed (no silent fallback)"
        );
    }

    // ── test helpers ─────────────────────────────────────────────────

    /// Sign a v3 checkpoint with a chosen zk_proof. Mirrors
    /// `Checkpoint::create` but lets the test supply zk_proof so it
    /// can be tampered with after the fact.
    fn checkpoint_signed_with_proof(
        signer: &Ed25519Signer,
        tree: &MerkleTree,
        index: u64,
        zk_proof: Option<ChainProofSummary>,
    ) -> Checkpoint {
        let root_bytes = tree.root().expect("non-empty tree");
        let root = format!("sha256:{}", hex::encode(root_bytes));
        let signed_at = "2026-05-17T00:00:00Z".to_string();
        let algorithm = Some(MERKLE_ALGORITHM_V2.to_string());

        let canonical = Checkpoint::canonical_for_signing(
            CANONICAL_VERSION_V3,
            tree.version(),
            algorithm.as_deref(),
            zk_proof.as_ref(),
            index,
            &root,
            tree.len(),
            tree.height(),
            signer.key_id(),
            &signed_at,
        );
        let sig_bytes = signer.sign(canonical.as_bytes()).unwrap();
        Checkpoint {
            index,
            root,
            tree_size: tree.len(),
            height: tree.height(),
            signed_at,
            signer: signer.key_id().to_string(),
            public_key: URL_SAFE_NO_PAD.encode(signer.public_key_bytes()),
            signature: URL_SAFE_NO_PAD.encode(&sig_bytes),
            algorithm,
            merkle_version: tree.version(),
            zk_proof,
            canonical_version: CANONICAL_VERSION_V3,
        }
    }

    /// Sign a checkpoint under the v0.10.3-era v2 canonical (no
    /// algorithm/zk_proof binding, no canonical_version on the wire).
    /// Used to verify legacy compat.
    fn sign_legacy_v2(
        signer: &Ed25519Signer,
        tree: &MerkleTree,
        index: u64,
    ) -> Checkpoint {
        let root_bytes = tree.root().expect("non-empty tree");
        let root = format!("sha256:{}", hex::encode(root_bytes));
        let signed_at = "2026-05-17T00:00:00Z".to_string();

        // Reproduce the v0.10.3 v2 canonical byte-for-byte. Note: in v2
        // the canonical function takes neither algorithm nor zk_proof.
        let canonical = Checkpoint::canonical_for_signing(
            CANONICAL_VERSION_V2,
            tree.version(),
            None,   // ignored under v2 dispatch
            None,   // ignored under v2 dispatch
            index,
            &root,
            tree.len(),
            tree.height(),
            signer.key_id(),
            &signed_at,
        );
        // Sanity: v2 canonical must NOT include algorithm even if
        // we passed Some() here — the v2 branch ignores it.
        assert!(canonical.starts_with("v2|"));

        let sig_bytes = signer.sign(canonical.as_bytes()).unwrap();
        Checkpoint {
            index,
            root,
            tree_size: tree.len(),
            height: tree.height(),
            signed_at,
            signer: signer.key_id().to_string(),
            public_key: URL_SAFE_NO_PAD.encode(signer.public_key_bytes()),
            signature: URL_SAFE_NO_PAD.encode(&sig_bytes),
            // v0.10.3-era checkpoints had algorithm present even though
            // it wasn't bound — that's the on-wire shape we need to
            // reproduce.
            algorithm: Some(MERKLE_ALGORITHM_V2.to_string()),
            merkle_version: MERKLE_VERSION_V2,
            zk_proof: None,
            canonical_version: CANONICAL_VERSION_V2,
        }
    }

    /// Sign a pre-v0.10.3 v1 checkpoint using the bare legacy canonical.
    /// The tree must NOT be exercised through MerkleTree::new (which is
    /// v2 by default); instead we construct the canonical directly.
    fn sign_legacy_v1(
        signer: &Ed25519Signer,
        index: u64,
        root: &str,
        tree_size: usize,
        height: usize,
    ) -> Checkpoint {
        let signed_at = "2026-04-01T00:00:00Z".to_string();
        // Bare legacy canonical.
        let canonical = Checkpoint::canonical_for_signing(
            CANONICAL_VERSION_V1,
            MERKLE_VERSION_V1,
            None,
            None,
            index,
            root,
            tree_size,
            height,
            signer.key_id(),
            &signed_at,
        );
        assert_eq!(
            canonical,
            format!(
                "{}|{}|{}|{}|{}|{}",
                index, root, tree_size, height, signer.key_id(), signed_at
            ),
            "v1 canonical must remain byte-identical to legacy"
        );

        let sig_bytes = signer.sign(canonical.as_bytes()).unwrap();
        Checkpoint {
            index,
            root: root.to_string(),
            tree_size,
            height,
            signed_at,
            signer: signer.key_id().to_string(),
            public_key: URL_SAFE_NO_PAD.encode(signer.public_key_bytes()),
            signature: URL_SAFE_NO_PAD.encode(&sig_bytes),
            algorithm: None,
            merkle_version: MERKLE_VERSION_V1,
            zk_proof: None,
            // Pre-v0.10.4 checkpoints have no canonical_version on the
            // wire; serde would default it to 2, but merkle_version == 1
            // forces v1 dispatch anyway. We set it to 1 here for clarity.
            canonical_version: CANONICAL_VERSION_V1,
        }
    }
}
