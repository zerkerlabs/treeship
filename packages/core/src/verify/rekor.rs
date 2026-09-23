//! Offline verification of a Rekor transparency-log entry stapled to an
//! artifact.
//!
//! # Why this exists (TS-2026-003)
//!
//! Before this module, a "rekor" anchor on a local record was a log index and
//! a time taken from the pushing machine's own clock. `verify` computed
//! anchoring coverage from that local time and never looked at Rekor, so an
//! operator who edited a record could satisfy `--max-unwitnessed-secs` with a
//! witness that never happened. (In practice the hub's Rekor submissions had
//! never succeeded either, so no such anchor was ever genuine.)
//!
//! An anchor now counts only if the full Rekor entry travels with the
//! artifact and verifies here, offline, against a pinned Rekor log key:
//!
//! 1. **Which log.** The entry's `logID` must be the SHA-256 of a trusted
//!    log key's DER encoding. Unknown logs are rejected, not trusted.
//! 2. **Rekor's promise.** The signed entry timestamp (SET) is Rekor's
//!    signature over `{body, integratedTime, logID, logIndex}`. This is what
//!    makes `integratedTime` Rekor's claim rather than ours.
//! 3. **Actual inclusion.** The RFC 6962 inclusion proof must lead from the
//!    entry's leaf hash to the root in a checkpoint that the same log key
//!    signed.
//! 4. **Binding.** The entry must be a `dsse` entry whose payload hash is the
//!    SHA-256 of *this* artifact's payload, and which lists one of *this*
//!    artifact's signatures together with a key that verifies it over PAE.
//!    Without this, a real Rekor entry for different bytes could be stapled
//!    onto any artifact.
//!
//! What this still does not prove: anchoring bounds *when a claim was made*,
//! never whether it is true. And a Rekor v1 `integratedTime` is Rekor's word;
//! the verdict names the log that vouched for it so a reader can weigh that.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdVerifyingKey};
use p256::ecdsa::{
    signature::Verifier as _, Signature as EcSignature, VerifyingKey as EcVerifyingKey,
};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attestation::{pae, Envelope};

/// Sigstore's public-good Rekor v1 production log key
/// (`https://rekor.sigstore.dev/api/v1/log/publicKey`). Built in the same way
/// Sigstore clients ship it in their trust root; a pinned
/// `transparency_log` trust root replaces it.
pub const SIGSTORE_PUBLIC_GOOD_REKOR_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----";

/// A transparency log a verifier is willing to believe.
#[derive(Debug, Clone)]
pub struct RekorLogKey {
    /// Shown in the verdict, e.g. "rekor.sigstore.dev (built-in)".
    pub label: String,
    /// hex(SHA-256(DER SubjectPublicKeyInfo)) -- Rekor's `logID`.
    pub log_id: String,
    key: EcVerifyingKey,
    der: Vec<u8>,
}

impl RekorLogKey {
    /// From a PEM `PUBLIC KEY` block (ECDSA P-256, as Rekor v1 uses).
    pub fn from_pem(label: impl Into<String>, pem: &str) -> Result<Self, String> {
        let der = pem_to_der(pem)?;
        Self::from_der(label, &der)
    }

    /// From DER SubjectPublicKeyInfo bytes.
    pub fn from_der(label: impl Into<String>, der: &[u8]) -> Result<Self, String> {
        let key = EcVerifyingKey::from_public_key_der(der)
            .map_err(|e| format!("not an ECDSA P-256 public key: {e}"))?;
        Ok(Self {
            label: label.into(),
            log_id: hex::encode(Sha256::digest(der)),
            key,
            der: der.to_vec(),
        })
    }

    /// The DER SubjectPublicKeyInfo this key was built from.
    pub fn spki_der(&self) -> &[u8] {
        &self.der
    }

    /// The built-in public-good log.
    pub fn sigstore_public_good() -> Self {
        Self::from_pem(
            "rekor.sigstore.dev (built-in)",
            SIGSTORE_PUBLIC_GOOD_REKOR_PEM,
        )
        .expect("built-in Rekor key parses")
    }
}

/// What a verified entry establishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedRekorAnchor {
    /// Rekor's own time for the entry, Unix seconds. Signed by the log.
    pub integrated_time: i64,
    /// Global log index.
    pub log_index: i64,
    pub log_id: String,
    /// Label of the trusted log key that vouched for it.
    pub log_label: String,
    /// The artifact signer key the entry binds, `ed25519:<base64url>`.
    pub signer: String,
    /// Always "rekor-v1-integrated-time" today; a TSA-backed source will say
    /// so here, which is how a later migration stays visible.
    pub time_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RekorVerifyError {
    Malformed(String),
    UnknownLog(String),
    BadSignedEntryTimestamp,
    BadInclusionProof(String),
    BadCheckpoint(String),
    NotBound(String),
}

impl std::fmt::Display for RekorVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "rekor entry is malformed: {m}"),
            Self::UnknownLog(id) => write!(
                f,
                "rekor entry is from a log that is not trusted here (logID {id})"
            ),
            Self::BadSignedEntryTimestamp => {
                write!(f, "rekor signed entry timestamp does not verify")
            }
            Self::BadInclusionProof(m) => write!(f, "rekor inclusion proof does not verify: {m}"),
            Self::BadCheckpoint(m) => write!(f, "rekor checkpoint does not verify: {m}"),
            Self::NotBound(m) => write!(f, "rekor entry is not for this artifact: {m}"),
        }
    }
}

impl std::error::Error for RekorVerifyError {}

#[derive(Deserialize)]
struct Entry {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logID")]
    log_id: String,
    #[serde(rename = "logIndex")]
    log_index: i64,
    verification: Verification,
}

#[derive(Deserialize)]
struct Verification {
    #[serde(rename = "signedEntryTimestamp")]
    signed_entry_timestamp: String,
    #[serde(rename = "inclusionProof")]
    inclusion_proof: InclusionProof,
}

#[derive(Deserialize)]
struct InclusionProof {
    #[serde(rename = "logIndex")]
    log_index: u64,
    #[serde(rename = "rootHash")]
    root_hash: String,
    #[serde(rename = "treeSize")]
    tree_size: u64,
    hashes: Vec<String>,
    checkpoint: String,
}

#[derive(Deserialize)]
struct Body {
    kind: String,
    #[serde(rename = "apiVersion")]
    api_version: String,
    spec: DsseSpec,
}

#[derive(Deserialize)]
struct DsseSpec {
    #[serde(rename = "payloadHash")]
    payload_hash: HashField,
    signatures: Vec<DsseSig>,
}

#[derive(Deserialize)]
struct HashField {
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
struct DsseSig {
    signature: String,
    verifier: String,
}

/// Verify a stapled Rekor entry for `envelope`, offline, against `logs`.
pub fn verify_rekor_entry(
    entry: &serde_json::Value,
    envelope: &Envelope,
    logs: &[RekorLogKey],
) -> Result<VerifiedRekorAnchor, RekorVerifyError> {
    let e: Entry = serde_json::from_value(entry.clone())
        .map_err(|err| RekorVerifyError::Malformed(err.to_string()))?;

    // 1. Which log.
    let log = logs
        .iter()
        .find(|l| l.log_id.eq_ignore_ascii_case(&e.log_id))
        .ok_or_else(|| RekorVerifyError::UnknownLog(e.log_id.clone()))?;

    // 2. Signed entry timestamp: ECDSA over the RFC 8785 canonical JSON of
    // these four fields. Keys sort as body < integratedTime < logID <
    // logIndex; all values are strings or integers, so canonicalization is
    // exactly this serialization.
    let set_payload = format!(
        "{{\"body\":{},\"integratedTime\":{},\"logID\":{},\"logIndex\":{}}}",
        serde_json::to_string(&e.body).expect("string serializes"),
        e.integrated_time,
        serde_json::to_string(&e.log_id).expect("string serializes"),
        e.log_index
    );
    let set_sig = STANDARD
        .decode(&e.verification.signed_entry_timestamp)
        .ok()
        .and_then(|b| EcSignature::from_der(&b).ok())
        .ok_or(RekorVerifyError::BadSignedEntryTimestamp)?;
    log.key
        .verify(set_payload.as_bytes(), &set_sig)
        .map_err(|_| RekorVerifyError::BadSignedEntryTimestamp)?;

    // 3. Inclusion: leaf -> root, and the root is in a checkpoint the log signed.
    let body_bytes = STANDARD
        .decode(&e.body)
        .map_err(|err| RekorVerifyError::Malformed(format!("body is not base64: {err}")))?;
    let ip = &e.verification.inclusion_proof;
    let root = decode_hash(&ip.root_hash).map_err(RekorVerifyError::BadInclusionProof)?;
    let proof: Vec<[u8; 32]> = ip
        .hashes
        .iter()
        .map(|h| decode_hash(h))
        .collect::<Result<_, _>>()
        .map_err(RekorVerifyError::BadInclusionProof)?;
    let leaf = leaf_hash(&body_bytes);
    let computed = root_from_inclusion_proof(ip.log_index, ip.tree_size, leaf, &proof)
        .map_err(RekorVerifyError::BadInclusionProof)?;
    if computed != root {
        return Err(RekorVerifyError::BadInclusionProof(
            "computed root does not match rootHash".into(),
        ));
    }
    let (cp_size, cp_root) = verify_checkpoint(&ip.checkpoint, log)?;
    if cp_size != ip.tree_size || cp_root != root {
        return Err(RekorVerifyError::BadCheckpoint(
            "checkpoint does not commit to the proof's tree".into(),
        ));
    }

    // 4. Binding to this artifact.
    let signer = verify_binding(&body_bytes, envelope)?;

    Ok(VerifiedRekorAnchor {
        integrated_time: e.integrated_time,
        log_index: e.log_index,
        log_id: log.log_id.clone(),
        log_label: log.label.clone(),
        signer,
        time_source: "rekor-v1-integrated-time".into(),
    })
}

fn verify_binding(body_bytes: &[u8], envelope: &Envelope) -> Result<String, RekorVerifyError> {
    let body: Body = serde_json::from_slice(body_bytes).map_err(|err| {
        RekorVerifyError::NotBound(format!("entry body is not a dsse entry: {err}"))
    })?;
    if body.kind != "dsse" || body.api_version != "0.0.1" {
        return Err(RekorVerifyError::NotBound(format!(
            "entry is {} {}, expected dsse 0.0.1",
            body.kind, body.api_version
        )));
    }
    let payload = envelope
        .payload_bytes()
        .map_err(|err| RekorVerifyError::NotBound(format!("artifact payload: {err}")))?;
    if body.spec.payload_hash.algorithm != "sha256"
        || !body
            .spec
            .payload_hash
            .value
            .eq_ignore_ascii_case(&hex::encode(Sha256::digest(&payload)))
    {
        return Err(RekorVerifyError::NotBound(
            "payload hash does not match this artifact".into(),
        ));
    }

    let signed = pae(&envelope.payload_type, &payload);
    let artifact_sigs: Vec<Vec<u8>> = envelope
        .signatures
        .iter()
        .filter_map(|s| Envelope::sig_bytes(s).ok())
        .collect();

    for s in &body.spec.signatures {
        let Ok(sig) = STANDARD.decode(&s.signature) else {
            continue;
        };
        if !artifact_sigs.iter().any(|a| a == &sig) {
            continue;
        }
        let Some(key) = STANDARD
            .decode(&s.verifier)
            .ok()
            .and_then(|pem| String::from_utf8(pem).ok())
            .and_then(|pem| pem_to_der(&pem).ok())
            .and_then(|der| ed25519_from_spki(&der))
        else {
            continue;
        };
        let Ok(sig) = EdSignature::from_slice(&sig) else {
            continue;
        };
        if key.verify_strict(&signed, &sig).is_ok() {
            return Ok(format!(
                "ed25519:{}",
                URL_SAFE_NO_PAD.encode(key.as_bytes())
            ));
        }
    }
    Err(RekorVerifyError::NotBound(
        "no signature in the entry is one of this artifact's signatures under a key that verifies it".into(),
    ))
}

/// Verify a C2SP signed note checkpoint and return (tree size, root hash).
fn verify_checkpoint(note: &str, log: &RekorLogKey) -> Result<(u64, [u8; 32]), RekorVerifyError> {
    let bad = |m: &str| RekorVerifyError::BadCheckpoint(m.to_string());
    let split = note
        .find("\n\n")
        .ok_or_else(|| bad("no blank line before signatures"))?;
    let text = &note[..split + 1];
    let mut lines = text.lines();
    let _origin = lines.next().ok_or_else(|| bad("missing origin"))?;
    let size: u64 = lines
        .next()
        .and_then(|l| l.parse().ok())
        .ok_or_else(|| bad("missing tree size"))?;
    let root_b64 = lines.next().ok_or_else(|| bad("missing root hash"))?;
    let root: [u8; 32] = STANDARD
        .decode(root_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("root hash is not 32 bytes of base64"))?;

    let hint = &hex::decode(&log.log_id).map_err(|_| bad("log id is not hex"))?[..4];
    for line in note[split + 2..].lines() {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            continue;
        };
        let Some((_name, sig_b64)) = rest.rsplit_once(' ') else {
            continue;
        };
        let Ok(raw) = STANDARD.decode(sig_b64) else {
            continue;
        };
        if raw.len() < 5 || &raw[..4] != hint {
            continue;
        }
        let Ok(sig) = EcSignature::from_der(&raw[4..]) else {
            continue;
        };
        if log.key.verify(text.as_bytes(), &sig).is_ok() {
            return Ok((size, root));
        }
    }
    Err(bad("no signature line verifies under the trusted log key"))
}

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// RFC 9162 section 2.1.3.2: recompute the root from an inclusion proof.
fn root_from_inclusion_proof(
    index: u64,
    size: u64,
    leaf: [u8; 32],
    proof: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    if index >= size {
        return Err(format!("leaf index {index} is outside tree size {size}"));
    }
    let (mut fnode, mut snode) = (index, size - 1);
    let mut r = leaf;
    for p in proof {
        if snode == 0 {
            return Err("proof is longer than the tree is deep".into());
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    if snode != 0 {
        return Err("proof is shorter than the tree is deep".into());
    }
    Ok(r)
}

fn decode_hash(h: &str) -> Result<[u8; 32], String> {
    hex::decode(h)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{h:?} is not a 32-byte hex hash"))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    if body.is_empty() {
        return Err("empty PEM".into());
    }
    STANDARD
        .decode(body)
        .map_err(|e| format!("PEM body is not base64: {e}"))
}

/// Ed25519 SubjectPublicKeyInfo is a fixed 12-byte prefix plus the key.
fn ed25519_from_spki(der: &[u8]) -> Option<EdVerifyingKey> {
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    if der.len() != 44 || der[..12] != PREFIX {
        return None;
    }
    EdVerifyingKey::from_bytes(der[12..].try_into().ok()?).ok()
}

/// Staging Rekor (`rekor.sigstage.dev/api/v1/log/publicKey`) and the
/// Treeship-shaped entry captured from it, for tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn staging_fixture_for_tests() -> (Envelope, serde_json::Value, RekorLogKey) {
    let (env, entry) = tests::fixture();
    (env, entry, tests::staging().remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGING_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9
nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg==
-----END PUBLIC KEY-----";

    /// A Treeship-shaped artifact anchored in Sigstore's staging Rekor by the
    /// fixed hub (`TestLiveStaging`), captured verbatim.
    pub(super) fn fixture() -> (Envelope, serde_json::Value) {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/rekor/staging-dsse.json"))
                .unwrap();
        let env: Envelope = serde_json::from_value(f["envelope"].clone()).unwrap();
        (env, f["entry"].clone())
    }

    pub(super) fn staging() -> Vec<RekorLogKey> {
        vec![RekorLogKey::from_pem("rekor.sigstage.dev (test)", STAGING_PEM).unwrap()]
    }

    #[test]
    fn real_staging_entry_verifies() {
        let (env, entry) = fixture();
        let v = verify_rekor_entry(&entry, &env, &staging()).unwrap();
        assert_eq!(v.integrated_time, entry["integratedTime"].as_i64().unwrap());
        assert_eq!(v.time_source, "rekor-v1-integrated-time");
        assert!(v.signer.starts_with("ed25519:"));
    }

    #[test]
    fn built_in_key_has_the_public_good_log_id() {
        assert_eq!(
            RekorLogKey::sigstore_public_good().log_id,
            "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
        );
    }

    #[test]
    fn untrusted_log_is_rejected() {
        let (env, entry) = fixture();
        let err =
            verify_rekor_entry(&entry, &env, &[RekorLogKey::sigstore_public_good()]).unwrap_err();
        assert!(matches!(err, RekorVerifyError::UnknownLog(_)));
    }

    /// The TS-2026-003 attack shape: move the claimed time. The SET covers
    /// integratedTime, so an edited time no longer verifies.
    #[test]
    fn edited_integrated_time_is_rejected() {
        let (env, mut entry) = fixture();
        let t = entry["integratedTime"].as_i64().unwrap();
        entry["integratedTime"] = serde_json::json!(t - 3600);
        assert_eq!(
            verify_rekor_entry(&entry, &env, &staging()).unwrap_err(),
            RekorVerifyError::BadSignedEntryTimestamp
        );
    }

    #[test]
    fn tampered_inclusion_proof_is_rejected() {
        let (env, mut entry) = fixture();
        let h = entry["verification"]["inclusionProof"]["hashes"][0]
            .as_str()
            .unwrap()
            .to_string();
        let flipped = format!("{}{}", if &h[..1] == "0" { "1" } else { "0" }, &h[1..]);
        entry["verification"]["inclusionProof"]["hashes"][0] = serde_json::json!(flipped);
        assert!(matches!(
            verify_rekor_entry(&entry, &env, &staging()).unwrap_err(),
            RekorVerifyError::BadInclusionProof(_)
        ));
    }

    /// A genuine entry stapled onto a different artifact must not bind.
    #[test]
    fn entry_for_other_bytes_is_rejected() {
        let (mut env, entry) = fixture();
        let mut payload = env.payload_bytes().unwrap();
        payload.push(b' ');
        env.payload = URL_SAFE_NO_PAD.encode(payload);
        assert!(matches!(
            verify_rekor_entry(&entry, &env, &staging()).unwrap_err(),
            RekorVerifyError::NotBound(_)
        ));
    }

    /// Same payload, different signature: the entry names a signature the
    /// artifact does not carry.
    #[test]
    fn entry_for_other_signature_is_rejected() {
        let (mut env, entry) = fixture();
        env.signatures[0].sig = URL_SAFE_NO_PAD.encode([7u8; 64]);
        assert!(matches!(
            verify_rekor_entry(&entry, &env, &staging()).unwrap_err(),
            RekorVerifyError::NotBound(_)
        ));
    }

    /// A real public-good production entry: log-side checks (SET, inclusion,
    /// checkpoint) must pass under the built-in key, and binding must fail
    /// because it is not a Treeship artifact.
    #[test]
    fn public_good_entry_passes_log_checks_and_fails_binding() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/rekor/public-good-dsse.json"
        ))
        .unwrap();
        let (env, _) = fixture();
        let err = verify_rekor_entry(&f["entry"], &env, &[RekorLogKey::sigstore_public_good()])
            .unwrap_err();
        assert!(matches!(err, RekorVerifyError::NotBound(_)), "got {err}");
    }

    /// Policy section 2: an artifact with zero signatures must not bind
    /// vacuously.
    #[test]
    fn artifact_with_no_signatures_is_rejected() {
        let (mut env, entry) = fixture();
        env.signatures.clear();
        assert!(matches!(
            verify_rekor_entry(&entry, &env, &staging()).unwrap_err(),
            RekorVerifyError::NotBound(_)
        ));
    }

    /// No trusted logs means nothing is trusted, not everything.
    #[test]
    fn empty_log_list_trusts_nothing() {
        let (env, entry) = fixture();
        assert!(matches!(
            verify_rekor_entry(&entry, &env, &[]).unwrap_err(),
            RekorVerifyError::UnknownLog(_)
        ));
    }

    /// An empty proof for a multi-leaf tree must not collapse to "leaf is
    /// root".
    #[test]
    fn empty_inclusion_proof_is_rejected_for_nontrivial_tree() {
        let (env, mut entry) = fixture();
        entry["verification"]["inclusionProof"]["hashes"] = serde_json::json!([]);
        assert!(matches!(
            verify_rekor_entry(&entry, &env, &staging()).unwrap_err(),
            RekorVerifyError::BadInclusionProof(_)
        ));
    }

    /// A checkpoint signed by a different key (here: the checkpoint's
    /// signature line removed) must not vouch for the root.
    #[test]
    fn unsigned_checkpoint_is_rejected() {
        let (env, mut entry) = fixture();
        let cp = entry["verification"]["inclusionProof"]["checkpoint"]
            .as_str()
            .unwrap()
            .to_string();
        let body_only = format!("{}\n", &cp[..cp.find("\n\n").unwrap() + 1]);
        entry["verification"]["inclusionProof"]["checkpoint"] = serde_json::json!(body_only);
        assert!(matches!(
            verify_rekor_entry(&entry, &env, &staging()).unwrap_err(),
            RekorVerifyError::BadCheckpoint(_)
        ));
    }

    #[test]
    fn inclusion_proof_math_matches_rfc9162_small_trees() {
        // Tree of 3 leaves: root = H(H(l0,l1), l2).
        let l: Vec<[u8; 32]> = (0u8..3).map(|i| leaf_hash(&[i])).collect();
        let n01 = node_hash(&l[0], &l[1]);
        let root = node_hash(&n01, &l[2]);
        assert_eq!(
            root_from_inclusion_proof(0, 3, l[0], &[l[1], l[2]]).unwrap(),
            root
        );
        assert_eq!(
            root_from_inclusion_proof(1, 3, l[1], &[l[0], l[2]]).unwrap(),
            root
        );
        assert_eq!(root_from_inclusion_proof(2, 3, l[2], &[n01]).unwrap(), root);
        assert!(root_from_inclusion_proof(3, 3, l[2], &[n01]).is_err());
    }
}
