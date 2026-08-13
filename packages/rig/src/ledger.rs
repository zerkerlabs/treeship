//! The ledger owns the signing key, the local artifact store, and the
//! chain head. Every attestation links to the previous one by artifact ID,
//! so the sequence of tool calls forms a tamper-evident hash chain.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ed25519_dalek::VerifyingKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use treeship_core::attestation::{sign, Ed25519Signer, Envelope, Signer, Verifier};
use treeship_core::keys;
use treeship_core::statements::{payload_type, ActionStatement};
use treeship_core::storage::{Record, Store as ArtifactStore};

use crate::error::AttestError;

/// A signed, stored attestation for one action.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Content-addressed ID (`art_...`). Recomputed at verify time; any
    /// tampering changes it.
    pub artifact_id: String,
    /// `sha256:<hex>` digest of the signed PAE bytes.
    pub digest: String,
    /// Parent artifact this one chains to, if any.
    pub parent_id: Option<String>,
}

/// Outcome of verifying a chain of attestations.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    /// Number of artifacts verified, newest to oldest.
    pub length: usize,
    /// Artifact IDs in verification order (newest first).
    pub artifact_ids: Vec<String>,
}

/// Signing + storage context shared by all attested tools of one agent.
///
/// Thread-safe: hold it in an `Arc` and hand clones of the `Arc` to every
/// [`crate::Attested`] wrapper. Calls are serialized through an internal
/// mutex so chain links never race.
pub struct TreeshipLedger {
    signer: Box<dyn Signer>,
    store: Option<ArtifactStore>,
    actor: String,
    /// Chain head: the artifact ID of the most recent attestation.
    head: Mutex<Option<String>>,
}

impl TreeshipLedger {
    /// In-memory ledger with a freshly generated Ed25519 key and no disk
    /// store. Receipts are signed and chained but not persisted — useful
    /// for tests and short-lived agents. For durable receipts use
    /// [`TreeshipLedger::open`] or [`TreeshipLedger::open_default`].
    pub fn ephemeral(actor: impl Into<String>) -> Result<Self, AttestError> {
        let signer = Ed25519Signer::generate("key_ephemeral")
            .map_err(|e| AttestError::Sign(e.to_string()))?;
        Ok(Self {
            signer: Box::new(signer),
            store: None,
            actor: actor.into(),
            head: Mutex::new(None),
        })
    }

    /// Opens (or creates) a ledger rooted at `base`, using `base/keys` for
    /// the encrypted keystore and `base/artifacts` for the receipt store.
    /// Generates a default key on first use.
    pub fn open(base: impl AsRef<Path>, actor: impl Into<String>) -> Result<Self, AttestError> {
        let base = base.as_ref();
        let key_store =
            keys::Store::open(base.join("keys")).map_err(|e| AttestError::Keys(e.to_string()))?;

        let signer = match key_store.default_signer() {
            Ok(s) => s,
            Err(_) => {
                // First run: create a default key, then load its signer.
                key_store
                    .generate(true)
                    .map_err(|e| AttestError::Keys(e.to_string()))?;
                key_store
                    .default_signer()
                    .map_err(|e| AttestError::Keys(e.to_string()))?
            }
        };

        let store = ArtifactStore::open(base.join("artifacts"))
            .map_err(|e| AttestError::Storage(e.to_string()))?;

        Ok(Self {
            signer,
            store: Some(store),
            actor: actor.into(),
            head: Mutex::new(None),
        })
    }

    /// Opens the ledger the same way the `treeship` CLI would, so receipts
    /// written by a Rig agent land in the store the operator actually uses
    /// and `treeship verify` finds them without extra flags.
    ///
    /// Resolution order, matching the CLI:
    ///   1. `$TREESHIP_HOME` — explicit override, used as a bare base dir
    ///   2. `$TREESHIP_CONFIG` — path to a `config.json`
    ///   3. `.treeship/config.json` found by walking up from the cwd
    ///      (project-local stores)
    ///   4. `$HOME/.treeship/config.json`
    ///
    /// When a config file is found, its `storage_dir` / `keys_dir` are
    /// honored, including relative paths (resolved against the config's own
    /// directory) and one level of `extends`. Falling back to `base/keys`
    /// and `base/artifacts` only when there is no config to read.
    ///
    /// Hardcoding `~/.treeship` here — the previous behavior — meant a Rig
    /// agent silently wrote into a different ship than the operator's CLI
    /// whenever a project-local store or `TREESHIP_CONFIG` was in play.
    pub fn open_default(actor: impl Into<String>) -> Result<Self, AttestError> {
        match resolve_store_dirs() {
            Some((keys_dir, artifacts_dir)) => Self::open_dirs(keys_dir, artifacts_dir, actor),
            None => Self::open(default_base(), actor),
        }
    }

    /// Opens a ledger against an explicit `config.json`, the crate-level
    /// equivalent of `treeship --config <path>`.
    pub fn open_config(
        config_path: impl AsRef<Path>,
        actor: impl Into<String>,
    ) -> Result<Self, AttestError> {
        let (keys_dir, artifacts_dir) =
            read_config_dirs(config_path.as_ref(), 0).ok_or_else(|| {
                AttestError::Keys(format!(
                    "could not read treeship config at {}",
                    config_path.as_ref().display()
                ))
            })?;
        Self::open_dirs(keys_dir, artifacts_dir, actor)
    }

    /// Opens a ledger from explicit key and artifact directories.
    pub fn open_dirs(
        keys_dir: impl AsRef<Path>,
        artifacts_dir: impl AsRef<Path>,
        actor: impl Into<String>,
    ) -> Result<Self, AttestError> {
        let key_store =
            keys::Store::open(keys_dir.as_ref()).map_err(|e| AttestError::Keys(e.to_string()))?;

        let signer = match key_store.default_signer() {
            Ok(s) => s,
            Err(_) => {
                key_store
                    .generate(true)
                    .map_err(|e| AttestError::Keys(e.to_string()))?;
                key_store
                    .default_signer()
                    .map_err(|e| AttestError::Keys(e.to_string()))?
            }
        };

        let store = ArtifactStore::open(artifacts_dir.as_ref())
            .map_err(|e| AttestError::Storage(e.to_string()))?;

        Ok(Self {
            signer,
            store: Some(store),
            actor: actor.into(),
            head: Mutex::new(None),
        })
    }

    /// The actor URI attached to every attestation (e.g. `agent://researcher`).
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// The current chain head, if any attestation has been made.
    pub fn head(&self) -> Option<String> {
        self.head.lock().unwrap().clone()
    }

    /// The signer's public key bytes (32 bytes, Ed25519) — hand these to a
    /// counterparty so they can verify your receipts independently.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signer.public_key_bytes()
    }

    /// Signs a `treeship/action/v1` statement, links it to the current
    /// chain head, persists it (when a store is attached), and advances
    /// the head.
    ///
    /// `meta` carries whatever evidence you want in the receipt. The
    /// [`crate::Attested`] wrapper puts `args_hash`, `output_hash`, and
    /// `outcome` here — hashes, never raw content.
    pub fn attest_action(
        &self,
        action: &str,
        meta: serde_json::Value,
    ) -> Result<Attestation, AttestError> {
        // Hold the head lock across sign+store so concurrent tool calls
        // produce a linear chain instead of two children of one parent.
        let mut head = self.head.lock().unwrap();

        let mut stmt = ActionStatement::new(self.actor.clone(), action);
        stmt.parent_id = head.clone();
        stmt.meta = Some(meta);

        let signed = sign(&payload_type("action"), &stmt, self.signer.as_ref())
            .map_err(|e| AttestError::Sign(e.to_string()))?;

        if let Some(store) = &self.store {
            let record = Record {
                artifact_id: signed.artifact_id.clone(),
                digest: signed.digest.clone(),
                payload_type: payload_type("action"),
                key_id: self.signer.key_id().to_string(),
                signed_at: stmt.timestamp.clone(),
                parent_id: stmt.parent_id.clone(),
                envelope: signed.envelope.clone(),
                hub_url: None,
            };
            store
                .write(&record)
                .map_err(|e| AttestError::Storage(e.to_string()))?;
        }

        let attestation = Attestation {
            artifact_id: signed.artifact_id.clone(),
            digest: signed.digest,
            parent_id: stmt.parent_id,
        };
        *head = Some(signed.artifact_id);
        Ok(attestation)
    }

    /// Verifies the chain ending at `artifact_id`: every envelope's
    /// signature checks out against this ledger's key, and every
    /// `parentId` resolves, back to the genesis attestation.
    ///
    /// Requires a disk store (receipts must be readable back).
    pub fn verify_chain(&self, artifact_id: &str) -> Result<ChainVerification, AttestError> {
        let store = self.store.as_ref().ok_or_else(|| AttestError::Verify {
            artifact_id: artifact_id.to_string(),
            reason: "ephemeral ledger has no artifact store to verify against".into(),
        })?;

        let verifier = self.verifier()?;
        let mut ids = Vec::new();
        let mut cursor = Some(artifact_id.to_string());

        while let Some(id) = cursor {
            let record = store.read(&id).map_err(|e| AttestError::Verify {
                artifact_id: id.clone(),
                reason: format!("read: {e}"),
            })?;

            verify_envelope(&verifier, &record.envelope, &id)?;

            // The stored parent pointer must match the signed payload's
            // parentId — otherwise the index was tampered with even though
            // the envelope itself verifies.
            let stmt: ActionStatement =
                record
                    .envelope
                    .unmarshal_statement()
                    .map_err(|e| AttestError::Verify {
                        artifact_id: id.clone(),
                        reason: format!("payload: {e}"),
                    })?;
            if stmt.parent_id != record.parent_id {
                return Err(AttestError::Verify {
                    artifact_id: id.clone(),
                    reason: "index parent_id does not match signed parentId".into(),
                });
            }

            ids.push(id);
            cursor = stmt.parent_id;
        }

        Ok(ChainVerification {
            length: ids.len(),
            artifact_ids: ids,
        })
    }

    fn verifier(&self) -> Result<Verifier, AttestError> {
        let bytes = self.signer.public_key_bytes();
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| AttestError::Keys("public key is not 32 bytes".into()))?;
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| AttestError::Keys(format!("verifying key: {e}")))?;
        let mut map = HashMap::new();
        map.insert(self.signer.key_id().to_string(), key);
        Ok(Verifier::new(map))
    }
}

fn verify_envelope(verifier: &Verifier, envelope: &Envelope, id: &str) -> Result<(), AttestError> {
    verifier
        .verify(envelope)
        .map_err(|e| AttestError::Verify {
            artifact_id: id.to_string(),
            reason: e.to_string(),
        })
        .map(|_| ())
}

fn default_base() -> PathBuf {
    if let Ok(dir) = std::env::var("TREESHIP_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".treeship")
}

/// Locate the config the CLI would use and read its store directories.
/// Returns `None` when there is no readable config, leaving the caller to
/// fall back to a bare base directory.
fn resolve_store_dirs() -> Option<(PathBuf, PathBuf)> {
    // 1. TREESHIP_HOME wins outright and is a base dir, not a config path.
    if std::env::var("TREESHIP_HOME").is_ok() {
        return None;
    }
    // 2. Explicit config path.
    if let Ok(p) = std::env::var("TREESHIP_CONFIG") {
        return read_config_dirs(Path::new(&p), 0);
    }
    // 3. Project-local: nearest .treeship/config.json walking up from cwd.
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = Some(cwd.as_path());
        while let Some(d) = dir {
            let candidate = d.join(".treeship").join("config.json");
            if candidate.is_file() {
                return read_config_dirs(&candidate, 0);
            }
            dir = d.parent();
        }
    }
    // 4. Global.
    let home = std::env::var("HOME").ok()?;
    let global = Path::new(&home).join(".treeship").join("config.json");
    if global.is_file() {
        return read_config_dirs(&global, 0);
    }
    None
}

/// Depth cap on `extends`. The CLI allows a deeper chain; two levels covers
/// the project-stub-extends-global shape and refuses to loop.
const EXTENDS_MAX_DEPTH: u8 = 2;

/// Read `storage_dir` / `keys_dir` out of a config, following `extends` and
/// resolving relative paths against the directory holding the config that
/// declared them -- the same rule the CLI applies.
fn read_config_dirs(config_path: &Path, depth: u8) -> Option<(PathBuf, PathBuf)> {
    if depth > EXTENDS_MAX_DEPTH {
        return None;
    }
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(config_path).ok()?).ok()?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));

    // Project stubs carry only {"extends": "...", "project": true}.
    if let Some(parent) = raw.get("extends").and_then(|v| v.as_str()) {
        let p = Path::new(parent);
        let resolved = if p.is_absolute() {
            p.to_path_buf()
        } else {
            base.join(p)
        };
        return read_config_dirs(&resolved, depth + 1);
    }

    let join = |key: &str, default: &str| -> PathBuf {
        let raw_val = raw.get(key).and_then(|v| v.as_str()).unwrap_or(default);
        let p = Path::new(raw_val);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            base.join(p)
        }
    };
    Some((join("keys_dir", "keys"), join("storage_dir", "artifacts")))
}

/// `sha256:<hex>` over a value's compact JSON encoding. Used for
/// `args_hash` / `output_hash` so receipts carry evidence without leaking
/// raw content.
pub fn sha256_json<T: serde::Serialize>(value: &T) -> Result<String, AttestError> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Convenience: the standard meta object the [`crate::Attested`] wrapper
/// records for a tool call.
pub fn tool_call_meta(
    tool: &str,
    args_hash: &str,
    output_hash: Option<&str>,
    outcome: &str,
) -> serde_json::Value {
    let mut meta = json!({
        "tool": tool,
        "args_hash": args_hash,
        "outcome": outcome,
    });
    if let Some(h) = output_hash {
        meta["output_hash"] = json!(h);
    }
    meta
}

#[cfg(test)]
mod config_resolution_tests {
    use super::read_config_dirs;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("rig-treeship-cfg-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, body: serde_json::Value) -> PathBuf {
        let p = dir.join("config.json");
        fs::write(&p, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
        p
    }

    /// A portable config -- the shape this crate itself writes -- must
    /// resolve against the config's directory, not the process cwd. This is
    /// the bug that made a relative store invisible to the CLI.
    #[test]
    fn relative_dirs_resolve_against_the_config_not_cwd() {
        let d = tmp("relative");
        let cfg = write(
            &d,
            serde_json::json!({
                "ship_id": "ship_x", "storage_dir": "artifacts", "keys_dir": "keys",
                "default_key_id": "key_a"
            }),
        );
        let (keys, artifacts) = read_config_dirs(&cfg, 0).expect("config reads");
        assert_eq!(keys, d.join("keys"));
        assert_eq!(artifacts, d.join("artifacts"));
    }

    #[test]
    fn absolute_dirs_are_used_verbatim() {
        let d = tmp("absolute");
        let cfg = write(
            &d,
            serde_json::json!({
                "ship_id": "ship_x",
                "storage_dir": "/opt/ship/artifacts", "keys_dir": "/opt/ship/keys",
                "default_key_id": "key_a"
            }),
        );
        let (keys, artifacts) = read_config_dirs(&cfg, 0).unwrap();
        assert_eq!(keys, PathBuf::from("/opt/ship/keys"));
        assert_eq!(artifacts, PathBuf::from("/opt/ship/artifacts"));
    }

    /// Project-local stubs `extends` a global config. An agent run from a
    /// project directory must sign into the ship that config points at.
    #[test]
    fn extends_follows_through_to_the_parent_store() {
        let global = tmp("extends-global");
        write(
            &global,
            serde_json::json!({
                "ship_id": "ship_parent", "storage_dir": "artifacts", "keys_dir": "keys",
                "default_key_id": "key_a"
            }),
        );
        let proj = tmp("extends-project");
        let stub = write(
            &proj,
            serde_json::json!({
                "extends": global.join("config.json").to_string_lossy(), "project": true
            }),
        );
        let (keys, artifacts) = read_config_dirs(&stub, 0).expect("stub resolves");
        assert_eq!(keys, global.join("keys"), "must use the parent's keystore");
        assert_eq!(artifacts, global.join("artifacts"));
    }

    /// An `extends` loop must terminate rather than recurse forever.
    #[test]
    fn extends_cycle_terminates() {
        let d = tmp("cycle");
        let p = d.join("config.json");
        fs::write(
            &p,
            serde_json::to_vec(&serde_json::json!({
                "extends": p.to_string_lossy()
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            read_config_dirs(&p, 0).is_none(),
            "a self-referencing config must not hang"
        );
    }

    /// Missing keys fall back to the conventional layout rather than erroring.
    #[test]
    fn missing_dir_fields_default_to_the_standard_layout() {
        let d = tmp("defaults");
        let cfg = write(
            &d,
            serde_json::json!({ "ship_id": "ship_x", "default_key_id": "key_a" }),
        );
        let (keys, artifacts) = read_config_dirs(&cfg, 0).unwrap();
        assert_eq!(keys, d.join("keys"));
        assert_eq!(artifacts, d.join("artifacts"));
    }
}
