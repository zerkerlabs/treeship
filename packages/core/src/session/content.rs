//! The content layer: the bytes behind a digest.
//!
//! # Why this exists
//!
//! A step receipt commits to its output by digest, not by value. That is the
//! right default -- a receipt is built to be handed to someone who should not
//! have to be trusted with your data -- but on its own it leaves a reader
//! holding a commitment to something nobody can open. They can confirm the
//! agent received *some* bytes and that nobody altered the record of it. They
//! cannot see what the bytes were, and if the producer later produces some,
//! the reader has to take their word that these are the ones.
//!
//! The content layer closes that gap without weakening anything. Bytes live in
//! `content/<sha256 hex>` inside the package, named by their own digest, so:
//!
//!   - **Nothing new is signed.** A blob is bound to the trace because a
//!     signed statement already names its digest. The binding is the hash, not
//!     a position in a file or a second signature over the bytes.
//!   - **Attaching and dropping content changes no verdict.** Content can be
//!     added long after sealing and removed before sharing, and every
//!     signature, the Merkle root and the chain are untouched either way. That
//!     is what makes "share the steps that matter and hashes for the rest" an
//!     operation rather than a promise.
//!   - **A substituted blob cannot hide.** The file name is the digest of the
//!     contents, so swapping the bytes is caught by recomputing one hash --
//!     which [`read_blob`] does on every read, so no caller can forget to.
//!
//! Content that no signed statement names is not content, it is an attachment
//! someone added to a package. The verifier fails on it rather than warning:
//! a reader who sees bytes inside a trace will read them as part of it.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Directory inside the package holding one file per blob, each named by the
/// lowercase hex SHA-256 of its own contents.
pub const CONTENT_DIR: &str = "content";

/// How much of a blob is read at a time when hashing it, so verifying a
/// package does not depend on every blob fitting in memory.
const HASH_CHUNK: usize = 64 * 1024;

/// Where a digest was named inside a signed statement.
///
/// The reference is what makes a blob part of the trace, so it is worth
/// reporting precisely: a reader deciding whether to open some bytes wants to
/// know which step claimed them and in what role.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DigestRef {
    /// The artifact whose signed statement named this digest.
    pub artifact_id: String,
    /// Dotted path to the field inside the statement, e.g.
    /// `effect.output_hash` or `meta.output_digest`.
    pub field: String,
}

/// Errors from the content store. Distinct from [`super::package::PackageError`]
/// because the interesting case -- bytes that do not hash to their own name --
/// has no analogue there and must not be flattened into a generic IO error.
#[derive(Debug)]
pub enum ContentError {
    /// Not 64 hex characters, with or without a `sha256:` prefix.
    BadDigest(String),
    /// No blob stored under this digest.
    Missing(String),
    /// The stored bytes do not hash to the name they are filed under. Either
    /// the file was swapped or it was written by something that did not hash
    /// what it wrote; a reader must not be handed the bytes either way.
    DigestMismatch {
        expected: String,
        actual: String,
    },
    /// This digest appears in no signed statement in the package, so storing
    /// bytes for it would attach content the trace does not account for.
    Unreferenced(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ContentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadDigest(s) => write!(f, "not a sha-256 digest: {s}"),
            Self::Missing(d) => write!(f, "no content stored for {d}"),
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "content filed under sha256:{expected} hashes to sha256:{actual}: the bytes were substituted"
            ),
            Self::Unreferenced(d) => write!(
                f,
                "no signed statement in this package names sha256:{d}, so these bytes are not part of this trace"
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ContentError {}

impl From<std::io::Error> for ContentError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Reduce a digest as written in a statement to the bare lowercase hex this
/// module files blobs under, or `None` if it is not a SHA-256 digest.
///
/// Accepts `sha256:<hex>` and a bare `<hex>` in either case. Nothing else: the
/// returned string becomes a path component, and restricting it to 64 hex
/// characters is what makes that safe rather than a traversal waiting to be
/// found.
pub fn normalize_digest(s: &str) -> Option<String> {
    let hex = s.strip_prefix("sha256:").unwrap_or(s);
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

/// `sha256:<hex>` for `bytes`, in the form statements write.
pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// The path a blob with this digest occupies, or `None` for a digest that is
/// not well formed.
pub fn blob_path(pkg_dir: &Path, digest: &str) -> Option<PathBuf> {
    Some(pkg_dir.join(CONTENT_DIR).join(normalize_digest(digest)?))
}

/// Hash a file without reading it all into memory.
fn hash_file(path: &Path) -> Result<(String, u64), std::io::Error> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    let mut len = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        len += n as u64;
    }
    Ok((hex::encode(h.finalize()), len))
}

/// One stored blob: the digest it is filed under, its size, and whether the
/// bytes actually hash to that digest.
#[derive(Debug, Clone)]
pub struct StoredBlob {
    pub digest: String,
    pub bytes: u64,
    /// `None` when the bytes hash to their name. `Some(actual)` when they do
    /// not, which is a failure the caller must surface rather than skip.
    pub mismatch: Option<String>,
}

/// Every blob in the package's content directory, hashed. Empty when there is
/// no content directory, which is the normal state for a package whose
/// producer never opted into storing content.
///
/// Files whose names are not digests are reported through `strays` rather than
/// ignored: something put them there, and a content directory is not a place
/// for anything else.
pub fn list_blobs(pkg_dir: &Path) -> Result<(Vec<StoredBlob>, Vec<String>), ContentError> {
    let dir = pkg_dir.join(CONTENT_DIR);
    let mut blobs = Vec::new();
    let mut strays = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((blobs, strays)),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata()?;
        if !meta.is_file() {
            strays.push(name);
            continue;
        }
        let Some(digest) = normalize_digest(&name) else {
            strays.push(name);
            continue;
        };
        // A name that normalizes to something other than itself (uppercase,
        // or a `sha256:` prefix) is not the name this module writes, so it
        // would not be found by a lookup. Report it rather than accept it.
        if digest != name {
            strays.push(name);
            continue;
        }
        let (actual, bytes) = hash_file(&entry.path())?;
        blobs.push(StoredBlob {
            mismatch: (actual != digest).then_some(actual),
            digest,
            bytes,
        });
    }
    blobs.sort_by(|a, b| a.digest.cmp(&b.digest));
    strays.sort();
    Ok((blobs, strays))
}

/// The bytes stored for `digest`, after confirming they hash to it.
///
/// The check is here and not left to callers on purpose: handing back bytes
/// that do not match the digest they were asked for would turn the one
/// guarantee this layer offers into a convention.
pub fn read_blob(pkg_dir: &Path, digest: &str) -> Result<Vec<u8>, ContentError> {
    let want =
        normalize_digest(digest).ok_or_else(|| ContentError::BadDigest(digest.to_string()))?;
    let path = pkg_dir.join(CONTENT_DIR).join(&want);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ContentError::Missing(want))
        }
        Err(e) => return Err(e.into()),
    };
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != want {
        return Err(ContentError::DigestMismatch {
            expected: want,
            actual,
        });
    }
    Ok(bytes)
}

/// Store `bytes` under their own digest, which `referenced` must already name.
///
/// Returns the `sha256:<hex>` the bytes were filed under. Storing the same
/// bytes twice is a no-op rather than an error: the file name is a function of
/// the contents, so a second write cannot mean anything different from the
/// first.
pub fn write_blob(
    pkg_dir: &Path,
    bytes: &[u8],
    referenced: &BTreeSet<String>,
) -> Result<String, ContentError> {
    let hex_digest = hex::encode(Sha256::digest(bytes));
    if !referenced.contains(&hex_digest) {
        return Err(ContentError::Unreferenced(hex_digest));
    }
    let dir = pkg_dir.join(CONTENT_DIR);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(&hex_digest);
    // Written through a temp file in the same directory and renamed, so a
    // reader never sees a partial blob under a name that promises a hash.
    let tmp = dir.join(format!(".{hex_digest}.partial"));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(format!("sha256:{hex_digest}"))
}

/// Remove the blob stored for `digest`. `Ok(false)` when there was none.
///
/// Dropping content is a supported operation, not damage: the trace's
/// signatures, Merkle root and chain do not mention the bytes, only their
/// digest, so a package verifies exactly as well without them.
pub fn remove_blob(pkg_dir: &Path, digest: &str) -> Result<bool, ContentError> {
    let want =
        normalize_digest(digest).ok_or_else(|| ContentError::BadDigest(digest.to_string()))?;
    let path = pkg_dir.join(CONTENT_DIR).join(want);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Walk one signed statement for every SHA-256 digest it names, recording the
/// field each was found in.
///
/// Every digest in the statement counts, whatever the field is called. The
/// alternative -- a list of blessed field names -- fails quietly as statement
/// kinds grow: a new receipt kind names its output in a field the list has
/// never heard of, and content for it becomes unattachable for no reason a
/// reader could discover. What makes a blob legitimate is that *a signature
/// covers the digest*, and that is true of any field in a signed statement.
pub fn digests_in_statement(
    artifact_id: &str,
    stmt: &serde_json::Value,
    out: &mut BTreeMap<String, BTreeSet<DigestRef>>,
) {
    fn walk(
        artifact_id: &str,
        v: &serde_json::Value,
        path: &mut Vec<String>,
        out: &mut BTreeMap<String, BTreeSet<DigestRef>>,
    ) {
        match v {
            serde_json::Value::String(s) => {
                if let Some(d) = normalize_digest(s) {
                    out.entry(d).or_default().insert(DigestRef {
                        artifact_id: artifact_id.to_string(),
                        field: path.join("."),
                    });
                }
            }
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    path.push(i.to_string());
                    walk(artifact_id, item, path, out);
                    path.pop();
                }
            }
            serde_json::Value::Object(map) => {
                for (k, item) in map {
                    path.push(k.clone());
                    walk(artifact_id, item, path, out);
                    path.pop();
                }
            }
            _ => {}
        }
    }
    let mut path = Vec::new();
    walk(artifact_id, stmt, &mut path, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(ids: &[(&str, &str)]) -> BTreeSet<DigestRef> {
        ids.iter()
            .map(|(a, f)| DigestRef {
                artifact_id: a.to_string(),
                field: f.to_string(),
            })
            .collect()
    }

    const H: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn normalize_accepts_both_forms_and_rejects_everything_else() {
        assert_eq!(normalize_digest(H).as_deref(), Some(H));
        assert_eq!(normalize_digest(&format!("sha256:{H}")).as_deref(), Some(H));
        assert_eq!(normalize_digest(&H.to_uppercase()).as_deref(), Some(H));
        assert_eq!(normalize_digest(""), None);
        assert_eq!(normalize_digest("sha256:"), None);
        assert_eq!(normalize_digest(&H[..63]), None);
        assert_eq!(normalize_digest(&format!("{H}0")), None);
        // One non-hex character is enough, including the ones that would
        // matter in a path.
        assert_eq!(normalize_digest(&format!("{}/x", &H[..62])), None);
        assert_eq!(normalize_digest("../../etc/passwd"), None);
        assert_eq!(normalize_digest(&format!("{}zz", &H[..62])), None);
    }

    #[test]
    fn digest_of_empty_bytes_is_the_known_vector() {
        assert_eq!(digest_bytes(b""), format!("sha256:{H}"));
    }

    #[test]
    fn blob_path_refuses_a_digest_it_cannot_make_a_filename_from() {
        let dir = Path::new("/pkg");
        assert_eq!(
            blob_path(dir, &format!("sha256:{H}")),
            Some(dir.join("content").join(H))
        );
        assert_eq!(blob_path(dir, "../../escape"), None);
    }

    #[test]
    fn write_then_read_round_trips_and_rejects_unreferenced_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let bytes = b"forecast: 14C, clear".to_vec();
        let d = hex::encode(Sha256::digest(&bytes));

        // Nothing in the trace names these bytes, so they cannot be stored.
        let empty = BTreeSet::new();
        assert!(matches!(
            write_blob(tmp.path(), &bytes, &empty),
            Err(ContentError::Unreferenced(_))
        ));
        assert!(!tmp.path().join("content").join(&d).exists());

        let referenced: BTreeSet<String> = [d.clone()].into_iter().collect();
        let stored = write_blob(tmp.path(), &bytes, &referenced).unwrap();
        assert_eq!(stored, format!("sha256:{d}"));
        assert_eq!(read_blob(tmp.path(), &stored).unwrap(), bytes);
        assert_eq!(read_blob(tmp.path(), &d).unwrap(), bytes);

        // A second write of the same bytes is the same file.
        write_blob(tmp.path(), &bytes, &referenced).unwrap();
        let (blobs, strays) = list_blobs(tmp.path()).unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(strays.is_empty());
        assert_eq!(blobs[0].bytes, bytes.len() as u64);
        assert!(blobs[0].mismatch.is_none());
        // No partial file is left behind.
        assert!(!tmp
            .path()
            .join("content")
            .join(format!(".{d}.partial"))
            .exists());

        assert!(remove_blob(tmp.path(), &stored).unwrap());
        assert!(!remove_blob(tmp.path(), &stored).unwrap());
        assert!(matches!(
            read_blob(tmp.path(), &stored),
            Err(ContentError::Missing(_))
        ));
    }

    #[test]
    fn substituted_bytes_are_refused_on_read_and_reported_on_list() {
        let tmp = tempfile::tempdir().unwrap();
        let bytes = b"the real response".to_vec();
        let d = hex::encode(Sha256::digest(&bytes));
        let referenced: BTreeSet<String> = [d.clone()].into_iter().collect();
        write_blob(tmp.path(), &bytes, &referenced).unwrap();

        // Swap the contents, keeping the name that promises the old hash.
        std::fs::write(tmp.path().join("content").join(&d), b"a different response").unwrap();

        match read_blob(tmp.path(), &d) {
            Err(ContentError::DigestMismatch { expected, actual }) => {
                assert_eq!(expected, d);
                assert_ne!(actual, d);
            }
            other => panic!("expected a mismatch, got {other:?}"),
        }
        let (blobs, _) = list_blobs(tmp.path()).unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(blobs[0].mismatch.is_some());
    }

    #[test]
    fn list_reports_files_that_are_not_blobs_instead_of_ignoring_them() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("content");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("notes.txt"), b"hello").unwrap();
        std::fs::write(dir.join(H.to_uppercase()), b"").unwrap();
        std::fs::create_dir_all(dir.join("subdir")).unwrap();

        let (blobs, strays) = list_blobs(tmp.path()).unwrap();
        assert!(blobs.is_empty());
        assert_eq!(strays.len(), 3);
        assert!(strays.contains(&"notes.txt".to_string()));
        assert!(strays.contains(&"subdir".to_string()));
        assert!(strays.contains(&H.to_uppercase()));
    }

    #[test]
    fn no_content_directory_is_an_empty_list_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let (blobs, strays) = list_blobs(tmp.path()).unwrap();
        assert!(blobs.is_empty());
        assert!(strays.is_empty());
    }

    #[test]
    fn digests_are_collected_from_any_field_at_any_depth() {
        let a = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let b = "0000000000000000000000000000000000000000000000000000000000000001";
        let stmt = serde_json::json!({
            "type": "treeship/action/v2",
            "action": "http.get",
            "effect": { "output_hash": format!("sha256:{a}") },
            "meta": { "output_digest": b },
            "inputs": [ { "blob": format!("sha256:{a}") } ],
            "duration_ms": 144,
            "not_a_digest": "sha256:short",
        });
        let mut out = BTreeMap::new();
        digests_in_statement("art_1", &stmt, &mut out);

        assert_eq!(out.len(), 2);
        assert_eq!(
            out[a],
            refs(&[("art_1", "effect.output_hash"), ("art_1", "inputs.0.blob")])
        );
        assert_eq!(out[b], refs(&[("art_1", "meta.output_digest")]));
    }

    #[test]
    fn a_statement_with_no_digests_contributes_nothing() {
        let stmt = serde_json::json!({ "action": "session.start", "meta": { "n": 1 } });
        let mut out = BTreeMap::new();
        digests_in_statement("art_1", &stmt, &mut out);
        assert!(out.is_empty());
    }
}
