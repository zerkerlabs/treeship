//! Trust root pinning for self-signed verification surfaces.
//!
//! Three verification paths in Treeship trust a public key that travels
//! inside the artifact they're verifying:
//!
//! 1. `Checkpoint::verify` — the Merkle checkpoint's `public_key` field.
//! 2. `verify_hub_checkpoint_signature` — the `hub_public_key` field of a
//!    `JournalCheckpoint` of kind `hub-org`.
//! 3. `verify_certificate` — the Agent Certificate's
//!    `signature.public_key` field.
//!
//! Without an external pin every one of these is self-signed: an attacker
//! who mints a new keypair, embeds the public key in the artifact, signs
//! over the canonical bytes, and presents the result will verify.
//!
//! `TrustRootStore` is the pin: a small JSON file at
//! `~/.treeship/trust_roots.json` listing every public key the operator
//! has decided to trust as an issuer, keyed by `kind`. The three
//! verification functions reject any embedded public key that is not in
//! the store for the matching kind.
//!
//! The store deliberately mirrors the keystore: same `~/.treeship`
//! directory, same `0o600` permission expectation, same JSON-on-disk
//! shape. There is no remote sync in this release — operators add roots
//! by hand via `treeship trust add` after verifying the key fingerprint
//! out-of-band (`treeship hub sync-trust` is referenced in error
//! messages as the forward-looking automation hook).

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// What this trust root is allowed to verify. Encoded kebab-case in JSON
/// because the rest of the codebase (CheckpointKind, etc.) does the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRootKind {
    /// Merkle `Checkpoint` produced by `treeship merkle checkpoint`. This is
    /// the ship-local journal checkpoint, distinct from the hub-org
    /// JournalCheckpoint kind below.
    HubCheckpoint,
    /// `JournalCheckpoint` of kind `hub-org` -- signed by a remote Hub to
    /// promote a local journal claim to a global single-use claim.
    Ship,
    /// `AgentCertificate` issued by a ship to one of its agents.
    AgentCert,
}

impl TrustRootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HubCheckpoint => "hub_checkpoint",
            Self::Ship          => "ship",
            Self::AgentCert     => "agent_cert",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hub_checkpoint" => Some(Self::HubCheckpoint),
            "ship"           => Some(Self::Ship),
            "agent_cert"     => Some(Self::AgentCert),
            _                => None,
        }
    }
}

/// One pinned trust root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRoot {
    /// Opaque identifier. Matches the existing `KeyId` format used elsewhere,
    /// but the trust store does not require any particular shape -- any
    /// non-empty string is accepted so operators can use human labels like
    /// `hub_zerker_labs`.
    pub key_id: String,

    /// Public key encoded as `ed25519:<base64url-no-pad>`. The prefix is
    /// required so the format stays algorithm-agnostic when we add more
    /// signature schemes; today only `ed25519` is recognized.
    pub public_key: String,

    /// What this root is allowed to verify.
    pub kind: TrustRootKind,

    /// Human-readable label. Shown by `treeship trust list`. Optional in
    /// the file format; defaults to the empty string.
    #[serde(default)]
    pub label: String,

    /// RFC 3339 timestamp the root was added. Useful for auditing.
    #[serde(default)]
    pub added_at: String,
}

/// On-disk wire format. A separate type so we can evolve the file without
/// breaking the public `TrustRoot` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustRootFile {
    /// Schema version. Currently `1`.
    pub version: u8,
    pub roots:   Vec<TrustRoot>,
}

const SCHEMA_VERSION: u8 = 1;

/// In-memory view of the trust root file.
#[derive(Debug, Clone, Default)]
pub struct TrustRootStore {
    roots: Vec<TrustRoot>,
}

/// Errors loading or operating on a trust root file.
#[derive(Debug)]
pub enum TrustRootError {
    /// The file does not exist. The caller should surface the actionable
    /// remediation: run `treeship trust add` (or sync from a hub).
    NotConfigured { path: PathBuf },
    /// JSON parse or schema validation failed.
    Malformed { path: PathBuf, msg: String },
    /// The file exists and is well-formed but contains zero roots. Treated
    /// the same as `NotConfigured` by verifiers but kept distinct so the
    /// CLI can show a more targeted error.
    Empty { path: PathBuf },
    /// File mode allows group or world access. Refuse to load.
    PermissionsTooOpen { path: PathBuf, mode: u32 },
    /// Underlying I/O failure (read, write, mkdir).
    Io(io::Error),
}

impl std::fmt::Display for TrustRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured { path } => write!(
                f,
                "no trust roots configured (looked for {}). \
                 Run `treeship trust add <key_id> <pubkey> --kind <kind>` \
                 or sync from your hub via `treeship hub sync-trust`.",
                path.display(),
            ),
            Self::Malformed { path, msg } => write!(
                f,
                "trust root file {} is malformed: {msg}",
                path.display(),
            ),
            Self::Empty { path } => write!(
                f,
                "trust root file {} has no roots configured. \
                 Run `treeship trust add <key_id> <pubkey> --kind <kind>` \
                 to add an issuer.",
                path.display(),
            ),
            Self::PermissionsTooOpen { path, mode } => write!(
                f,
                "trust root file {} has insecure permissions (mode {:o}); \
                 chmod 600 the file and try again.",
                path.display(),
                mode & 0o777,
            ),
            Self::Io(e) => write!(f, "trust root io: {e}"),
        }
    }
}

impl std::error::Error for TrustRootError {}

impl From<io::Error> for TrustRootError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}

impl TrustRootStore {
    /// Default file location: `~/.treeship/trust_roots.json`.
    pub fn default_path() -> PathBuf {
        std::env::var_os("TREESHIP_TRUST_ROOTS")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_default();
                PathBuf::from(home).join(".treeship").join("trust_roots.json")
            })
    }

    /// Construct an empty in-memory store. Useful for tests; the
    /// verification path treats an empty store the same as a missing
    /// file (no trust configured).
    pub fn empty() -> Self {
        Self { roots: Vec::new() }
    }

    /// Construct a store from an explicit list of roots. Tests use this
    /// to thread a known trust set into the verifier; production callers
    /// should `open` the on-disk file.
    pub fn with_roots(roots: Vec<TrustRoot>) -> Self {
        Self { roots }
    }

    /// Open the trust root file at `path`. Returns `NotConfigured` if it
    /// does not exist, `Empty` if it exists but has zero roots.
    pub fn open(path: &Path) -> Result<Self, TrustRootError> {
        if !path.exists() {
            return Err(TrustRootError::NotConfigured { path: path.to_path_buf() });
        }
        check_trust_file_perms(path)?;
        let bytes = fs::read(path)?;
        let file: TrustRootFile = serde_json::from_slice(&bytes)
            .map_err(|e| TrustRootError::Malformed {
                path: path.to_path_buf(),
                msg:  e.to_string(),
            })?;
        if file.version != SCHEMA_VERSION {
            return Err(TrustRootError::Malformed {
                path: path.to_path_buf(),
                msg:  format!(
                    "schema version mismatch: file has v{}, this binary supports v{}",
                    file.version, SCHEMA_VERSION,
                ),
            });
        }
        // Validate every embedded public key parses now -- catch a
        // malformed key at load time rather than at verify time.
        for root in &file.roots {
            decode_ed25519_pubkey(&root.public_key)
                .map_err(|msg| TrustRootError::Malformed {
                    path: path.to_path_buf(),
                    msg:  format!("root {}: {msg}", root.key_id),
                })?;
        }
        if file.roots.is_empty() {
            return Err(TrustRootError::Empty { path: path.to_path_buf() });
        }
        Ok(Self { roots: file.roots })
    }

    /// Save the store to `path`. Creates parent directories with mode
    /// 0o700 and writes the file with mode 0o600.
    pub fn save(&self, path: &Path) -> Result<(), TrustRootError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let file = TrustRootFile {
            version: SCHEMA_VERSION,
            roots:   self.roots.clone(),
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| TrustRootError::Malformed {
                path: path.to_path_buf(),
                msg:  e.to_string(),
            })?;
        fs::write(path, &json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Returns true if `key` is pinned for `kind`. The CLI helper does
    /// not pre-decode; callers that already hold a `VerifyingKey` should
    /// use this directly.
    pub fn contains(&self, key: &VerifyingKey, kind: TrustRootKind) -> bool {
        let key_bytes = key.to_bytes();
        self.roots.iter().any(|r| {
            r.kind == kind
                && decode_ed25519_pubkey(&r.public_key)
                    .map(|k| k.to_bytes() == key_bytes)
                    .unwrap_or(false)
        })
    }

    /// Convenience: lookup against a raw 32-byte Ed25519 key without first
    /// constructing a `VerifyingKey`. Returns false if the bytes are not
    /// a valid public key (mirrors the verifier's reject-on-decode-failure
    /// behavior).
    pub fn contains_bytes(&self, key_bytes: &[u8; 32], kind: TrustRootKind) -> bool {
        match VerifyingKey::from_bytes(key_bytes) {
            Ok(vk) => self.contains(&vk, kind),
            Err(_) => false,
        }
    }

    /// True when the store carries zero pinned roots. Verifiers reject
    /// any artifact when this returns true with a clear "configure trust"
    /// error.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// True when the store has no pinned root of `kind`. Used by
    /// verifiers to surface a kind-specific error message when an
    /// operator has set up `agent_cert` trust but is verifying a
    /// `hub_checkpoint` (or vice versa).
    pub fn is_empty_for_kind(&self, kind: TrustRootKind) -> bool {
        !self.roots.iter().any(|r| r.kind == kind)
    }

    /// Append a root. Idempotent: re-adding the same `(key_id, kind)`
    /// pair replaces the previous entry. The CLI `treeship trust add`
    /// goes through here.
    pub fn add(&mut self, root: TrustRoot) {
        self.roots.retain(|r| !(r.key_id == root.key_id && r.kind == root.kind));
        self.roots.push(root);
    }

    /// Remove a root by `key_id`. Returns true if a root was removed.
    /// Removes every entry matching the id across all kinds.
    pub fn remove(&mut self, key_id: &str) -> bool {
        let before = self.roots.len();
        self.roots.retain(|r| r.key_id != key_id);
        self.roots.len() != before
    }

    /// Iterate over every root.
    pub fn roots(&self) -> &[TrustRoot] {
        &self.roots
    }

    /// Number of roots configured.
    pub fn len(&self) -> usize {
        self.roots.len()
    }
}

/// Decode an `ed25519:<base64url>` or bare base64url public key into a
/// `VerifyingKey`. The `ed25519:` prefix is the canonical form; the bare
/// form is accepted for forward-compatibility with operator-typed input.
pub fn decode_ed25519_pubkey(s: &str) -> Result<VerifyingKey, String> {
    let b64 = s.strip_prefix("ed25519:").unwrap_or(s);
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("base64url decode failed: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 32-byte public key, got {} bytes", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("not a valid Ed25519 public key: {e}"))
}

/// Encode a `VerifyingKey` into the canonical `ed25519:<base64url>` form.
pub fn encode_ed25519_pubkey(key: &VerifyingKey) -> String {
    format!("ed25519:{}", URL_SAFE_NO_PAD.encode(key.to_bytes()))
}

fn check_trust_file_perms(path: &Path) -> Result<(), TrustRootError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Honour the same bypass the keystore honors -- CI sandboxes and
        // recovery flows occasionally need to load on a loose-perm file.
        if std::env::var_os("TREESHIP_ALLOW_INSECURE_KEY_PERMS")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            return Ok(());
        }
        let meta = fs::metadata(path)?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(TrustRootError::PermissionsTooOpen {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    let _ = path;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut b = [0u8; 4];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut b);
        p.push(format!("treeship-trust-test-{tag}-{}", hex::encode(b)));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn cleanup(p: &Path) {
        let _ = fs::remove_dir_all(p);
    }

    fn fresh_root(key_id: &str, kind: TrustRootKind) -> (SigningKey, TrustRoot) {
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let pk = sk.verifying_key();
        let root = TrustRoot {
            key_id:     key_id.into(),
            public_key: encode_ed25519_pubkey(&pk),
            kind,
            label:      format!("test root {key_id}"),
            added_at:   "2026-05-15T00:00:00Z".into(),
        };
        (sk, root)
    }

    #[test]
    fn roundtrip_save_load() {
        let dir = tmp_dir("roundtrip");
        let path = dir.join("trust_roots.json");
        let (_, r1) = fresh_root("hub_a", TrustRootKind::HubCheckpoint);
        let (_, r2) = fresh_root("ship_b", TrustRootKind::Ship);
        let store = TrustRootStore::with_roots(vec![r1.clone(), r2.clone()]);
        store.save(&path).unwrap();
        let loaded = TrustRootStore::open(&path).unwrap();
        assert_eq!(loaded.roots().len(), 2);
        assert_eq!(loaded.roots()[0], r1);
        assert_eq!(loaded.roots()[1], r2);
        cleanup(&dir);
    }

    #[test]
    fn rejects_missing_file() {
        let dir = tmp_dir("missing");
        let path = dir.join("nope.json");
        match TrustRootStore::open(&path).unwrap_err() {
            TrustRootError::NotConfigured { path: p } => assert_eq!(p, path),
            other => panic!("expected NotConfigured, got {other:?}"),
        }
        cleanup(&dir);
    }

    #[test]
    fn rejects_malformed_json() {
        let dir = tmp_dir("malformed");
        let path = dir.join("trust_roots.json");
        fs::write(&path, b"{ this is not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        match TrustRootStore::open(&path).unwrap_err() {
            TrustRootError::Malformed { path: p, .. } => assert_eq!(p, path),
            other => panic!("expected Malformed, got {other:?}"),
        }
        cleanup(&dir);
    }

    #[test]
    fn rejects_empty_roots() {
        let dir = tmp_dir("empty");
        let path = dir.join("trust_roots.json");
        let file = serde_json::json!({"version": 1, "roots": []});
        fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        match TrustRootStore::open(&path).unwrap_err() {
            TrustRootError::Empty { path: p } => assert_eq!(p, path),
            other => panic!("expected Empty, got {other:?}"),
        }
        cleanup(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn permission_too_open_warns() {
        use std::os::unix::fs::PermissionsExt;
        // Ensure the bypass env var isn't leaking in from the host.
        std::env::remove_var("TREESHIP_ALLOW_INSECURE_KEY_PERMS");

        let dir = tmp_dir("perms");
        let path = dir.join("trust_roots.json");
        let (_, r) = fresh_root("hub_a", TrustRootKind::HubCheckpoint);
        let file = TrustRootFile { version: SCHEMA_VERSION, roots: vec![r] };
        fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        match TrustRootStore::open(&path).unwrap_err() {
            TrustRootError::PermissionsTooOpen { path: p, mode } => {
                assert_eq!(p, path);
                assert_eq!(mode & 0o777, 0o644);
            }
            other => panic!("expected PermissionsTooOpen, got {other:?}"),
        }
        cleanup(&dir);
    }

    #[test]
    fn contains_matches_kind_correctly() {
        let (sk, r) = fresh_root("hub_a", TrustRootKind::HubCheckpoint);
        let store = TrustRootStore::with_roots(vec![r]);
        let vk = sk.verifying_key();

        assert!(store.contains(&vk, TrustRootKind::HubCheckpoint),
                "must accept matching kind");
        assert!(!store.contains(&vk, TrustRootKind::Ship),
                "must reject mismatching kind");
        assert!(!store.contains(&vk, TrustRootKind::AgentCert),
                "must reject mismatching kind");
    }

    #[test]
    fn add_replaces_same_key_id_and_kind() {
        let mut store = TrustRootStore::empty();
        let (_, r1) = fresh_root("hub_a", TrustRootKind::HubCheckpoint);
        let (_, r1b) = fresh_root("hub_a", TrustRootKind::HubCheckpoint);
        store.add(r1);
        store.add(r1b.clone());
        assert_eq!(store.len(), 1, "same (id, kind) replaces previous");
        assert_eq!(&store.roots()[0], &r1b);
    }

    #[test]
    fn add_keeps_same_key_id_across_kinds() {
        let mut store = TrustRootStore::empty();
        let (_, r_hub) = fresh_root("issuer_x", TrustRootKind::HubCheckpoint);
        let (_, r_ship) = fresh_root("issuer_x", TrustRootKind::Ship);
        store.add(r_hub);
        store.add(r_ship);
        assert_eq!(store.len(), 2, "same id is allowed across different kinds");
    }

    #[test]
    fn remove_strips_all_kinds_for_id() {
        let mut store = TrustRootStore::empty();
        let (_, r_hub) = fresh_root("issuer_x", TrustRootKind::HubCheckpoint);
        let (_, r_ship) = fresh_root("issuer_x", TrustRootKind::Ship);
        store.add(r_hub);
        store.add(r_ship);
        assert!(store.remove("issuer_x"));
        assert!(store.is_empty());
        assert!(!store.remove("issuer_x"), "second remove is a no-op");
    }

    #[test]
    fn encode_decode_roundtrip() {
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let pk = sk.verifying_key();
        let encoded = encode_ed25519_pubkey(&pk);
        assert!(encoded.starts_with("ed25519:"));
        let decoded = decode_ed25519_pubkey(&encoded).unwrap();
        assert_eq!(decoded.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn decode_accepts_bare_base64() {
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let pk = sk.verifying_key();
        let bare = URL_SAFE_NO_PAD.encode(pk.to_bytes());
        let decoded = decode_ed25519_pubkey(&bare).unwrap();
        assert_eq!(decoded.to_bytes(), pk.to_bytes());
    }
}
