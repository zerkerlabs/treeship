use std::path::Path;

use crate::{
    attestation::{sign, ArtifactId, Envelope, Signer, SignError},
    statements::{payload_type, ArtifactRef, BundleStatement},
    storage::{Record, Store, StorageError},
};

/// Error from bundle operations.
#[derive(Debug)]
pub enum BundleError {
    Storage(StorageError),
    Sign(SignError),
    Io(std::io::Error),
    Json(serde_json::Error),
    ArtifactNotFound(String),
    InvalidBundle(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e)          => write!(f, "bundle storage: {e}"),
            Self::Sign(e)             => write!(f, "bundle sign: {e}"),
            Self::Io(e)               => write!(f, "bundle io: {e}"),
            Self::Json(e)             => write!(f, "bundle json: {e}"),
            Self::ArtifactNotFound(id)=> write!(f, "artifact not found: {id}"),
            Self::InvalidBundle(msg)  => write!(f, "invalid bundle: {msg}"),
        }
    }
}

impl std::error::Error for BundleError {}
impl From<StorageError>       for BundleError { fn from(e: StorageError)       -> Self { Self::Storage(e) } }
impl From<SignError>          for BundleError { fn from(e: SignError)          -> Self { Self::Sign(e) } }
impl From<std::io::Error>    for BundleError { fn from(e: std::io::Error)    -> Self { Self::Io(e) } }
impl From<serde_json::Error> for BundleError { fn from(e: serde_json::Error) -> Self { Self::Json(e) } }

/// The result of creating a bundle.
#[derive(Debug)]
pub struct CreateResult {
    pub artifact_id: ArtifactId,
    pub digest:      String,
    pub record:      Record,
    pub statement:   BundleStatement,
}

/// A .treeship export file: the bundle envelope plus all referenced artifact envelopes.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ExportFile {
    /// Format version for forward compatibility.
    pub version: String,

    /// The signed bundle envelope.
    pub bundle: Envelope,

    /// All artifact envelopes referenced by the bundle, in chain order.
    pub artifacts: Vec<Envelope>,
}

const EXPORT_VERSION: &str = "treeship-export/v1";

/// Create a bundle from a list of artifact IDs.
///
/// Reads each artifact from storage, builds a `BundleStatement` referencing
/// them, signs it, and stores the bundle as a regular artifact.
pub fn create(
    artifact_ids: &[&str],
    tag:          Option<&str>,
    description:  Option<&str>,
    storage:      &Store,
    signer:       &dyn Signer,
) -> Result<CreateResult, BundleError> {
    if artifact_ids.is_empty() {
        return Err(BundleError::InvalidBundle("no artifact IDs provided".into()));
    }

    // Read each artifact and build the reference list.
    let mut refs = Vec::with_capacity(artifact_ids.len());
    let mut records = Vec::with_capacity(artifact_ids.len());

    for &id in artifact_ids {
        let rec = storage.read(id)
            .map_err(|_| BundleError::ArtifactNotFound(id.to_string()))?;
        refs.push(ArtifactRef {
            id:    rec.artifact_id.clone(),
            digest: rec.digest.clone(),
            type_: rec.payload_type.clone(),
        });
        records.push(rec);
    }

    let stmt = BundleStatement {
        type_:      crate::statements::TYPE_BUNDLE.into(),
        timestamp:  crate::statements::unix_to_rfc3339(now_secs()),
        tag:        tag.map(|s| s.to_string()),
        description: description.map(|s| s.to_string()),
        artifacts:  refs,
        policy_ref: None,
        meta:       None,
    };

    let pt     = payload_type("bundle");
    let result = sign(&pt, &stmt, signer)?;

    let record = Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    None,
        envelope:     result.envelope,
        hub_url:      None,
    };

    storage.write(&record)?;

    Ok(CreateResult {
        artifact_id: result.artifact_id,
        digest:      result.digest,
        record,
        statement:   stmt,
    })
}

/// Export a bundle to a .treeship file.
///
/// The export file contains the bundle envelope and all referenced artifact
/// envelopes. This is the portable format for sharing proof chains.
pub fn export(
    bundle_id: &str,
    out_path:  &Path,
    storage:   &Store,
) -> Result<(), BundleError> {
    let bundle_rec = storage.read(bundle_id)?;

    // Verify this is actually a bundle.
    let expected_pt = payload_type("bundle");
    if bundle_rec.payload_type != expected_pt {
        return Err(BundleError::InvalidBundle(format!(
            "artifact {} is {}, not a bundle",
            bundle_id, bundle_rec.payload_type
        )));
    }

    // Decode the bundle statement to get artifact references.
    let stmt: BundleStatement = bundle_rec.envelope.unmarshal_statement()
        .map_err(|e| BundleError::InvalidBundle(format!("cannot decode bundle: {e}")))?;

    // Collect all referenced artifact envelopes.
    let mut artifact_envelopes = Vec::with_capacity(stmt.artifacts.len());
    for art_ref in &stmt.artifacts {
        let rec = storage.read(&art_ref.id)
            .map_err(|_| BundleError::ArtifactNotFound(art_ref.id.clone()))?;
        artifact_envelopes.push(rec.envelope);
    }

    let export = ExportFile {
        version:   EXPORT_VERSION.into(),
        bundle:    bundle_rec.envelope,
        artifacts: artifact_envelopes,
    };

    let json = serde_json::to_vec_pretty(&export)?;
    std::fs::write(out_path, &json)?;

    Ok(())
}

/// Import a .treeship file into local storage.
///
/// Reads the export file, re-derives content-addressed IDs for each envelope,
/// and stores everything locally. Returns the bundle's artifact ID.
pub fn import(
    path:    &Path,
    storage: &Store,
) -> Result<ArtifactId, BundleError> {
    let bytes = std::fs::read(path)?;
    let export: ExportFile = serde_json::from_slice(&bytes)?;

    if export.version != EXPORT_VERSION {
        return Err(BundleError::InvalidBundle(format!(
            "unsupported export version: {} (expected {})",
            export.version, EXPORT_VERSION
        )));
    }

    // Import each artifact envelope.
    for env in &export.artifacts {
        let record = record_from_envelope(env)?;
        storage.write(&record)?;
    }

    // Import the bundle envelope.
    let bundle_record = record_from_envelope(&export.bundle)?;
    let bundle_id = bundle_record.artifact_id.clone();
    storage.write(&bundle_record)?;

    Ok(bundle_id)
}

/// Reconstruct a Record from a DSSE envelope by re-deriving the artifact ID.
fn record_from_envelope(envelope: &Envelope) -> Result<Record, BundleError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let payload_bytes = URL_SAFE_NO_PAD.decode(&envelope.payload)
        .map_err(|e| BundleError::InvalidBundle(format!("bad payload base64: {e}")))?;

    let pae_bytes = crate::attestation::pae(&envelope.payload_type, &payload_bytes);
    let artifact_id = crate::attestation::artifact_id_from_pae(&pae_bytes);
    let digest      = crate::attestation::digest_from_pae(&pae_bytes);

    // Extract timestamp from the payload if possible.
    let signed_at = serde_json::from_slice::<serde_json::Value>(&payload_bytes)
        .ok()
        .and_then(|v| v.get("timestamp").and_then(|t| t.as_str().map(|s| s.to_string())))
        .unwrap_or_default();

    // Extract parent_id from the payload if present.
    let parent_id = serde_json::from_slice::<serde_json::Value>(&payload_bytes)
        .ok()
        .and_then(|v| v.get("parentId").and_then(|t| t.as_str().map(|s| s.to_string())));

    let key_id = envelope.signatures.first()
        .map(|s| s.keyid.clone())
        .unwrap_or_default();

    Ok(Record {
        artifact_id,
        digest,
        payload_type: envelope.payload_type.clone(),
        key_id,
        signed_at,
        parent_id,
        envelope: envelope.clone(),
        hub_url: None,
    })
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Ed25519Signer;
    use crate::statements::{ActionStatement, ApprovalStatement};

    fn tmp_store() -> (Store, std::path::PathBuf) {
        let mut p = std::env::temp_dir();
        p.push(format!("treeship-bundle-test-{}", {
            use rand::RngCore;
            let mut b = [0u8; 4];
            rand::thread_rng().fill_bytes(&mut b);
            b.iter().fold(String::new(), |mut s, byte| {
                s.push_str(&format!("{:02x}", byte));
                s
            })
        }));
        let store = Store::open(&p).unwrap();
        (store, p)
    }

    fn rm(p: std::path::PathBuf) { let _ = std::fs::remove_dir_all(p); }

    fn sign_and_store(store: &Store, signer: &dyn Signer, pt: &str, stmt: &impl serde::Serialize) -> String {
        let result = sign(pt, stmt, signer).unwrap();
        store.write(&Record {
            artifact_id:  result.artifact_id.clone(),
            digest:       result.digest.clone(),
            payload_type: pt.to_string(),
            key_id:       signer.key_id().to_string(),
            signed_at:    String::new(),
            parent_id:    None,
            envelope:     result.envelope,
            hub_url:      None,
        }).unwrap();
        result.artifact_id
    }

    #[test]
    fn create_bundle() {
        let (store, dir) = tmp_store();
        let signer = Ed25519Signer::generate("key_test").unwrap();

        let a1 = sign_and_store(&store, &signer, &payload_type("action"),
            &ActionStatement::new("agent://a", "tool.call"));
        let a2 = sign_and_store(&store, &signer, &payload_type("approval"),
            &ApprovalStatement::new("human://b", "nonce_1"));

        let result = create(
            &[&a1, &a2],
            Some("test-bundle"),
            None,
            &store,
            &signer,
        ).unwrap();

        assert!(result.artifact_id.starts_with("art_"));
        assert_eq!(result.statement.artifacts.len(), 2);
        assert_eq!(result.statement.tag.as_deref(), Some("test-bundle"));

        // Bundle is stored
        assert!(store.exists(&result.artifact_id));
        rm(dir);
    }

    #[test]
    fn create_empty_fails() {
        let (store, dir) = tmp_store();
        let signer = Ed25519Signer::generate("key_test").unwrap();
        let err = create(&[], None, None, &store, &signer).unwrap_err();
        assert!(err.to_string().contains("no artifact IDs"));
        rm(dir);
    }

    #[test]
    fn create_missing_artifact_fails() {
        let (store, dir) = tmp_store();
        let signer = Ed25519Signer::generate("key_test").unwrap();
        let err = create(&["art_doesnotexist1234567890123456"], None, None, &store, &signer).unwrap_err();
        assert!(err.to_string().contains("not found"));
        rm(dir);
    }

    #[test]
    fn export_and_import_roundtrip() {
        let (store, dir) = tmp_store();
        let signer = Ed25519Signer::generate("key_test").unwrap();

        let a1 = sign_and_store(&store, &signer, &payload_type("action"),
            &ActionStatement::new("agent://a", "tool.call"));
        let a2 = sign_and_store(&store, &signer, &payload_type("action"),
            &ActionStatement::new("agent://b", "web.fetch"));

        let bundle = create(&[&a1, &a2], Some("roundtrip"), None, &store, &signer).unwrap();

        // Export
        let export_path = dir.join("test.treeship");
        export(&bundle.artifact_id, &export_path, &store).unwrap();
        assert!(export_path.exists());

        // Read and check the export file structure
        let bytes = std::fs::read(&export_path).unwrap();
        let ef: ExportFile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ef.version, EXPORT_VERSION);
        assert_eq!(ef.artifacts.len(), 2);

        // Import into a fresh store
        let (store2, dir2) = tmp_store();
        let imported_id = import(&export_path, &store2).unwrap();
        assert_eq!(imported_id, bundle.artifact_id);

        // All artifacts are now in the new store
        assert!(store2.exists(&a1));
        assert!(store2.exists(&a2));
        assert!(store2.exists(&bundle.artifact_id));

        rm(dir);
        rm(dir2);
    }

    #[test]
    fn export_non_bundle_fails() {
        let (store, dir) = tmp_store();
        let signer = Ed25519Signer::generate("key_test").unwrap();
        let a1 = sign_and_store(&store, &signer, &payload_type("action"),
            &ActionStatement::new("agent://a", "tool.call"));

        let export_path = dir.join("bad.treeship");
        let err = export(&a1, &export_path, &store).unwrap_err();
        assert!(err.to_string().contains("not a bundle"));
        rm(dir);
    }

    #[test]
    fn import_bad_version_fails() {
        let (store, dir) = tmp_store();
        let bad = ExportFile {
            version:   "bad/v99".into(),
            bundle:    Envelope {
                payload: String::new(),
                payload_type: String::new(),
                signatures: vec![],
            },
            artifacts: vec![],
        };
        let path = dir.join("bad.treeship");
        std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();

        let err = import(&path, &store).unwrap_err();
        assert!(err.to_string().contains("unsupported export version"));
        rm(dir);
    }
}
