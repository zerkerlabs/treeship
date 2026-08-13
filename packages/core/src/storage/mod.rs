use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

use crate::attestation::{parse_artifact_id, ArtifactId, Envelope};

/// The on-disk record for one stored artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub artifact_id: ArtifactId,
    pub digest: String, // "sha256:<hex>"
    pub payload_type: String,
    pub key_id: String,
    pub signed_at: String, // RFC 3339
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub envelope: Envelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_url: Option<String>,
    /// External witnesses to this artifact's existence, in the order they
    /// were obtained.
    ///
    /// Separate from `hub_url` because a URL records *that* something was
    /// pushed and not *when* -- and when is the whole value. A receipt's own
    /// timestamp is the signer's claim about itself; an anchor is somebody
    /// else's record that these bytes existed by a given moment, which is
    /// what makes a timeline hard to fabricate after the fact.
    ///
    /// `#[serde(default)]` so receipts written before this field parse
    /// unchanged: an old artifact has no anchors recorded, which is exactly
    /// what an empty list means.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<RecordAnchor>,
}

/// One external witness to an artifact, as observed locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordAnchor {
    /// Which mechanism witnessed it: "hub", "rekor", "ots", "tsa".
    pub mechanism: String,
    /// RFC 3339, from the *local* clock at the moment the witness responded.
    ///
    /// Honest caveat, and the reason this is not the end of the story: this
    /// is still our own clock. It records when we observed the witness, not
    /// when the witness says it saw us. It is trustworthy against an actor
    /// who fabricates a timeline afterwards -- you cannot obtain a Hub or
    /// Rekor response for bytes you have not written yet -- and not
    /// trustworthy against one who sets the system clock and anchors in real
    /// time. Closing that needs the witness's own signed time, which is
    /// `time-anchoring.md` slices 3-5.
    pub observed_at: String,
    /// Witness-side identifier where one exists: a Rekor log index, a Hub
    /// artifact URL. Lets a verifier go and check independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// A lightweight index entry — stored in index.json for fast listing
/// without reading every artifact file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub id: ArtifactId,
    pub payload_type: String,
    pub signed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Index {
    entries: Vec<IndexEntry>,
}

/// Errors from storage operations.
#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Json(serde_json::Error),
    EmptyId,
    /// The id is not a well-formed `art_<32 hex>`. Returned instead of
    /// touching the filesystem: an id reaches here from a Hub response, and
    /// one containing `../` used to resolve to a path outside the store.
    InvalidId(String),
    NotFound(ArtifactId),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "storage io: {}", e),
            Self::Json(e) => write!(f, "storage json: {}", e),
            Self::EmptyId => write!(f, "artifact_id must not be empty"),
            Self::InvalidId(e) => write!(f, "storage: {}", e),
            Self::NotFound(id) => write!(f, "artifact not found: {}", id),
        }
    }
}

impl std::error::Error for StorageError {}
impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Local artifact store. Thread-safe via internal RwLock.
///
/// Artifacts are stored as `<artifact_id>.json` files.
/// Content-addressed IDs mean same content → same filename → idempotent writes.
/// An `index.json` tracks all artifact IDs for O(1) listing.
pub struct Store {
    dir: PathBuf,
    index: Arc<RwLock<Index>>,
}

impl Store {
    /// Opens or creates an artifact store at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        let index = read_index(&dir)?;
        Ok(Self {
            dir,
            index: Arc::new(RwLock::new(index)),
        })
    }

    /// Writes an artifact record. Idempotent: writing the same artifact
    /// twice has no effect beyond overwriting with identical content.
    pub fn write(&self, record: &Record) -> Result<(), StorageError> {
        if record.artifact_id.is_empty() {
            return Err(StorageError::EmptyId);
        }

        let json = serde_json::to_vec_pretty(record)?;
        write_600(&self.artifact_path(&record.artifact_id)?, &json)?;

        let mut idx = self.index.write().unwrap();
        let entry = IndexEntry {
            id: record.artifact_id.clone(),
            payload_type: record.payload_type.clone(),
            signed_at: record.signed_at.clone(),
            parent_id: record.parent_id.clone(),
        };
        add_to_index(&mut idx, entry);
        write_600(
            &self.dir.join("index.json"),
            &serde_json::to_vec_pretty(&*idx)?,
        )?;

        Ok(())
    }

    /// Reads an artifact by ID.
    pub fn read(&self, id: &str) -> Result<Record, StorageError> {
        let path = self.artifact_path(id)?;
        if !path.exists() {
            return Err(StorageError::NotFound(id.to_string()));
        }
        let bytes = fs::read(&path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Returns true if an artifact with this ID is stored locally.
    pub fn exists(&self, id: &str) -> bool {
        // A malformed id cannot name a stored artifact, so it does not exist.
        // Deliberately not a filesystem probe on an unvalidated path.
        self.artifact_path(id).is_ok_and(|p| p.exists())
    }

    /// Lists index entries, most recent first.
    pub fn list(&self) -> Vec<IndexEntry> {
        let idx = self.index.read().unwrap();
        idx.entries.iter().rev().cloned().collect()
    }

    /// Lists index entries filtered to a specific payload type.
    pub fn list_by_type(&self, payload_type: &str) -> Vec<IndexEntry> {
        self.list()
            .into_iter()
            .filter(|e| e.payload_type == payload_type)
            .collect()
    }

    /// Updates the hub_url on a stored record after a successful dock push.
    pub fn set_hub_url(&self, id: &str, hub_url: &str) -> Result<(), StorageError> {
        let mut record = self.read(id)?;
        record.hub_url = Some(hub_url.to_string());
        self.write(&record)
    }

    /// Record that an external witness saw this artifact.
    ///
    /// Appends rather than replaces: two witnesses are strictly better
    /// evidence than one, and they fail differently -- a Hub anchor requires
    /// trusting the Hub, an OpenTimestamps anchor does not. Collapsing them
    /// would discard that difference.
    pub fn add_anchor(&self, id: &str, anchor: RecordAnchor) -> Result<(), StorageError> {
        let mut record = self.read(id)?;
        record.anchors.push(anchor);
        self.write(&record)
    }

    /// Returns the most recently stored artifact, if any.
    pub fn latest(&self) -> Option<IndexEntry> {
        self.index.read().unwrap().entries.last().cloned()
    }

    /// Resolve an artifact id to its on-disk path.
    ///
    /// Validates the id first. `join` on an attacker-influenced string is a
    /// path-traversal primitive: `../../x` resolved to a file outside the
    /// store, and `hub pull` writes whatever `artifact_id` the server sends
    /// back. `parse_artifact_id` already existed and enforces
    /// `art_<32 hex>` -- which cannot contain a separator or a dot -- it was
    /// simply never called on this path.
    fn artifact_path(&self, id: &str) -> Result<PathBuf, StorageError> {
        let id = parse_artifact_id(id).map_err(StorageError::InvalidId)?;
        Ok(self.dir.join(format!("{}.json", id)))
    }
}

fn read_index(dir: &Path) -> Result<Index, StorageError> {
    let path = dir.join("index.json");
    if !path.exists() {
        return Ok(Index::default());
    }
    let bytes = fs::read(&path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn add_to_index(idx: &mut Index, entry: IndexEntry) {
    // Deduplicate.
    if !idx.entries.iter().any(|e| e.id == entry.id) {
        idx.entries.push(entry);
    }
}

fn write_600(path: &Path, data: &[u8]) -> Result<(), StorageError> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    fn make_record(id: &str, pt: &str) -> Record {
        Record {
            artifact_id: id.to_string(),
            digest: format!("sha256:{}", "a".repeat(64)),
            payload_type: pt.to_string(),
            key_id: "key_test".into(),
            signed_at: "2026-03-26T10:00:00Z".into(),
            parent_id: None,
            envelope: Envelope {
                payload: URL_SAFE_NO_PAD.encode(b"{\"type\":\"test\"}"),
                payload_type: pt.to_string(),
                signatures: vec![crate::attestation::Signature {
                    keyid: "key_test".into(),
                    sig: URL_SAFE_NO_PAD.encode(b"fake_sig_64_bytes_padded_to_length_xxxxxxxxxx"),
                }],
            },
            hub_url: None,
            anchors: Vec::new(),
        }
    }

    fn tmp_store() -> (Store, PathBuf) {
        let mut p = std::env::temp_dir();
        p.push(format!("treeship-storage-test-{}", {
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

    fn rm(p: PathBuf) {
        let _ = fs::remove_dir_all(p);
    }

    #[test]
    fn write_and_read() {
        let (store, dir) = tmp_store();
        let id = "art_aabbccdd11223344aabbccdd11223344";
        let pt = "application/vnd.treeship.action.v1+json";
        store.write(&make_record(id, pt)).unwrap();

        let rec = store.read(id).unwrap();
        assert_eq!(rec.artifact_id, id);
        assert_eq!(rec.payload_type, pt);
        rm(dir);
    }

    #[test]
    fn exists() {
        let (store, dir) = tmp_store();
        let id = "art_aabbccdd11223344aabbccdd11223344";
        assert!(!store.exists(id));
        store
            .write(&make_record(id, "application/vnd.treeship.action.v1+json"))
            .unwrap();
        assert!(store.exists(id));
        rm(dir);
    }

    #[test]
    fn idempotent_write() {
        let (store, dir) = tmp_store();
        let id = "art_aabbccdd11223344aabbccdd11223344";
        let r = make_record(id, "application/vnd.treeship.action.v1+json");
        store.write(&r).unwrap();
        store.write(&r).unwrap();
        assert_eq!(store.list().len(), 1);
        rm(dir);
    }

    #[test]
    fn list_order() {
        let (store, dir) = tmp_store();
        let pt = "application/vnd.treeship.action.v1+json";
        store
            .write(&make_record("art_aabbccdd11223344aabbccdd11223344", pt))
            .unwrap();
        store
            .write(&make_record("art_bbccddee22334455bbccddee22334455", pt))
            .unwrap();

        let list = store.list();
        assert_eq!(list.len(), 2);
        // Most recent first — second write appears first.
        assert_eq!(list[0].id, "art_bbccddee22334455bbccddee22334455");
        rm(dir);
    }

    #[test]
    fn list_by_type() {
        let (store, dir) = tmp_store();
        store
            .write(&make_record(
                "art_aabbccdd11223344aabbccdd11223344",
                "application/vnd.treeship.action.v1+json",
            ))
            .unwrap();
        store
            .write(&make_record(
                "art_bbccddee22334455bbccddee22334455",
                "application/vnd.treeship.approval.v1+json",
            ))
            .unwrap();

        let actions = store.list_by_type("application/vnd.treeship.action.v1+json");
        assert_eq!(actions.len(), 1);
        rm(dir);
    }

    #[test]
    fn persist_across_opens() {
        let (store, dir) = tmp_store();
        let id = "art_aabbccdd11223344aabbccdd11223344";
        store
            .write(&make_record(id, "application/vnd.treeship.action.v1+json"))
            .unwrap();
        drop(store);

        let store2 = Store::open(&dir).unwrap();
        assert!(store2.exists(id));
        assert_eq!(store2.list().len(), 1);
        rm(dir);
    }

    #[test]
    fn not_found_error() {
        let (store, dir) = tmp_store();
        assert!(store.read("art_doesnotexist1234567890123456").is_err());
        rm(dir);
    }

    #[test]
    fn set_hub_url() {
        let (store, dir) = tmp_store();
        let id = "art_aabbccdd11223344aabbccdd11223344";
        store
            .write(&make_record(id, "application/vnd.treeship.action.v1+json"))
            .unwrap();
        store
            .set_hub_url(
                id,
                "https://treeship.dev/verify/art_aabbccdd11223344aabbccdd11223344",
            )
            .unwrap();
        let rec = store.read(id).unwrap();
        assert_eq!(
            rec.hub_url.as_deref(),
            Some("https://treeship.dev/verify/art_aabbccdd11223344aabbccdd11223344")
        );
        rm(dir);
    }
}

#[cfg(test)]
mod path_traversal_tests {
    use super::*;

    fn record_with_id(id: &str) -> Record {
        Record {
            artifact_id: id.to_string(),
            digest: "sha256:00".into(),
            payload_type: "application/vnd.in-toto+json".into(),
            key_id: "k".into(),
            signed_at: "2026-01-01T00:00:00Z".into(),
            parent_id: None,
            envelope: Envelope {
                payload: "e30".into(),
                payload_type: "application/vnd.in-toto+json".into(),
                signatures: vec![],
            },
            hub_url: None,
            anchors: Vec::new(),
        }
    }

    /// The vulnerability, as it actually behaved.
    ///
    /// `hub pull` writes the `artifact_id` the *server* returned, and
    /// `artifact_path` used to `join` it unvalidated. A malicious or
    /// compromised Hub could therefore write an attacker-chosen `.json` file
    /// anywhere the process could write. Before the fix this test's escaped
    /// file existed.
    #[test]
    fn write_cannot_escape_the_store_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let store_dir = tmp.path().join("a").join("b").join("store");
        let store = Store::open(&store_dir).unwrap();

        for id in [
            "../../escaped",
            "../../../etc/cron.d/x",
            "art_/../../escaped",
            "/tmp/absolute",
            "..",
        ] {
            let err = store.write(&record_with_id(id)).unwrap_err();
            assert!(
                matches!(err, StorageError::InvalidId(_)),
                "id {id:?} should be rejected as malformed, got {err:?}"
            );
        }

        let escaped = tmp.path().join("a").join("escaped.json");
        assert!(!escaped.exists(), "a file was written outside the store");
        assert!(!tmp.path().join("absolute.json").exists());
    }

    /// The check must not be so strict it rejects real ids -- a validator that
    /// blocks everything closes the hole and the feature together.
    #[test]
    fn well_formed_ids_still_write_and_read() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();

        let id = "art_0123456789abcdef0123456789abcdef";
        store.write(&record_with_id(id)).expect("write a valid id");
        assert!(store.exists(id));
        assert_eq!(store.read(id).unwrap().artifact_id, id);
    }

    /// `exists` took an unvalidated path to the filesystem. It now answers
    /// false rather than probing, which is also the honest answer: a malformed
    /// id cannot name a stored artifact.
    #[test]
    fn exists_reports_false_for_malformed_ids_without_probing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        assert!(!store.exists("../../../etc/passwd"));
        assert!(!store.exists(""));
        assert!(!store.exists("art_nothex0000000000000000000000zz"));
    }
}
