use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng, Payload},
    AeadCore, Aes256Gcm, Key as AesKey, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroizing;

use crate::attestation::{Ed25519Signer, Signer};

// --- Public types ---

pub type KeyId = String;

/// Public information about a stored key. Never contains private material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub id:          KeyId,
    pub algorithm:   String,   // "ed25519"
    pub is_default:  bool,
    pub created_at:  String,   // RFC 3339
    /// First 8 bytes of sha256(public_key), hex-encoded.
    pub fingerprint: String,
    pub public_key:  Vec<u8>,  // raw 32-byte Ed25519 public key
    /// RFC 3339 timestamp after which signatures by this key should be
    /// considered stale. `None` means the key has not been rotated and is
    /// indefinitely valid. Set automatically by `Store::rotate` to
    /// `now + grace_period` on the predecessor key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// If this key was rotated to a successor, the successor's key id.
    /// Lets verifiers walk a rotation chain forward when validating an old
    /// receipt against the current keystore. `None` means this is the head
    /// of its chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_key_id: Option<KeyId>,
}

/// Outcome of a `Store::rotate` call.
#[derive(Debug, Clone)]
pub struct RotationResult {
    /// The key that was rotated. Its `valid_until` is now set.
    pub predecessor: KeyInfo,
    /// The freshly minted successor key.
    pub successor: KeyInfo,
    /// RFC 3339 timestamp until which the predecessor remains valid for
    /// signature verification under the grace period. Equal to
    /// `predecessor.valid_until.unwrap()`.
    pub grace_period_until: String,
}

/// Errors from keystore operations.
#[derive(Debug)]
pub enum KeyError {
    Io(io::Error),
    Json(serde_json::Error),
    Crypto(String),
    NotFound(KeyId),
    EmptyKeyId,
    NoDefaultKey,
    /// Private key file has insecure permissions (group- or world-readable).
    /// Carries the path and the observed octal mode so the caller can show
    /// an actionable error. Set `TREESHIP_ALLOW_INSECURE_KEY_PERMS=1` to
    /// bypass during testing or controlled environments.
    InsecureKeyPerms { path: PathBuf, mode: u32 },
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)       => write!(f, "keys io: {}", e),
            Self::Json(e)     => write!(f, "keys json: {}", e),
            Self::Crypto(e)   => write!(f, "keys crypto: {}", e),
            Self::NotFound(k) => write!(f, "key not found: {}", k),
            Self::EmptyKeyId  => write!(f, "key id must not be empty"),
            Self::NoDefaultKey => write!(f, "no default key — run treeship init"),
            Self::InsecureKeyPerms { path, mode } => write!(
                f,
                "private key {} has insecure permissions (mode {:o}); \
                 run `treeship doctor --fix` or chmod 600 the file. \
                 Set TREESHIP_ALLOW_INSECURE_KEY_PERMS=1 to bypass.",
                path.display(),
                mode & 0o777,
            ),
        }
    }
}

impl std::error::Error for KeyError {}
impl From<io::Error>          for KeyError { fn from(e: io::Error)          -> Self { Self::Io(e) } }
impl From<serde_json::Error>  for KeyError { fn from(e: serde_json::Error)  -> Self { Self::Json(e) } }

// --- On-disk formats ---

/// The encrypted representation of one keypair on disk.
#[derive(Serialize, Deserialize, Clone)]
struct EncryptedEntry {
    id:           KeyId,
    algorithm:    String,
    created_at:   String,
    public_key:   Vec<u8>,
    /// AES-256-GCM ciphertext of the 32-byte Ed25519 secret scalar.
    enc_priv_key: Vec<u8>,
    /// 12-byte GCM nonce used when encrypting.
    nonce:        Vec<u8>,
    /// RFC 3339 timestamp after which signatures by this key should be
    /// considered stale. `None` means the key is indefinitely valid.
    /// Defaulted on deserialization so pre-0.9.5 entry files still load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    valid_until: Option<String>,
    /// Successor key id if this key was rotated. Defaulted on
    /// deserialization for pre-0.9.5 entry files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    successor_key_id: Option<KeyId>,
}

/// The manifest file: which keys exist and which is the default.
#[derive(Serialize, Deserialize, Default)]
struct Manifest {
    default_key_id: Option<KeyId>,
    key_ids:        Vec<KeyId>,
}

// --- Store ---

/// Local encrypted keystore.
///
/// Private keys are encrypted with AES-256-GCM (RustCrypto `aes-gcm`
/// 0.10) before writing to disk. The encryption key is derived from a
/// machine-specific secret so key files are useless if copied to
/// another machine.
///
/// Pre-v0.10.3 keystores used a homemade SHA-256-CTR + HMAC-SHA-256
/// construction (TS-2026-001) and are transparently migrated to the
/// new AEAD format on first decrypt; see `encrypt_for_disk_v2` /
/// `decrypt_from_disk` for the format dispatcher.
///
/// A future version will delegate to OS credential stores (Secure
/// Enclave / TPM 2.0).
pub struct Store {
    dir:         PathBuf,
    machine_key: [u8; 32],
    /// Decrypt-only fallback machine keys, tried in order when the primary
    /// fails. These cover every wrapping an existing keystore may carry:
    /// the v1 hostname+username key under the current hostname, the same
    /// under the raw (non-canonicalized) path when the path contains a
    /// symlink, and — on macOS — the v1 key under `scutil LocalHostName`
    /// variants, because macOS renames `kern.hostname` out from under a
    /// running machine (network collisions, DHCP) while `LocalHostName`
    /// keeps the name the keystore was written under. Never used to
    /// encrypt: any entry that decrypts via a fallback is transparently
    /// rewrapped under the primary. See `open` and `signer`.
    fallback_machine_keys: Vec<[u8; 32]>,
    /// In-memory cache — avoids disk reads on hot paths.
    cache:       Arc<RwLock<HashMap<KeyId, EncryptedEntry>>>,
}

impl Store {
    /// Opens or creates a keystore at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, KeyError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        // Canonicalize the keystore path before deriving the machine key. The
        // derivation hashes the store path into the key, so the SAME logical
        // directory must produce the SAME path string every time -- otherwise
        // `init` and a later command can hash different strings for one
        // directory (e.g. macOS `/var` -> `/private/var`, or a symlinked
        // `$HOME`) and decryption fails with a misleading "wrong machine" MAC
        // error. canonicalize resolves symlinks to a stable absolute path;
        // create_dir_all above guarantees it exists.
        //
        // The raw-path key is retained as a DECRYPT-ONLY fallback so any
        // keystore written before this change (encrypted under the raw path)
        // still opens -- this hardening must never lock an existing user out.
        // Encryption always uses the canonical key, so entries migrate to it
        // as they are rewritten.
        let canonical = fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());

        // Primary (encrypt) key: hardware-stable when the machine offers a
        // stable identifier (/etc/machine-id, IOPlatformSerialNumber), so a
        // hostname rename can never invalidate the keystore again. Machines
        // with neither identifier keep the v1 derivation, whose seed-file
        // fallback is CO-LOCATED with the keystore -- switching those to the
        // stable derivation would move their seed to the global
        // ~/.treeship/.internal/ and silently break project-local keystore
        // isolation (the v0.9.6 property).
        let machine_key = match stable_hardware_key(&canonical) {
            Some(k) => k,
            None => derive_machine_key(&canonical)?,
        };

        // Decrypt-only fallbacks, most-likely first. Existing keystores are
        // wrapped under one of these; the first successful decrypt rewraps
        // the entry under the primary (see `signer`), so the fallbacks are
        // a migration path, not a permanent second key.
        let mut fallback_machine_keys: Vec<[u8; 32]> = Vec::new();
        // v1 under the current hostname (every pre-migration keystore).
        if let Ok(k) = derive_machine_key(&canonical) {
            fallback_machine_keys.push(k);
        }
        // v1 under the raw path, for keystores written before path
        // canonicalization through a symlink.
        if canonical != dir {
            if let Ok(k) = derive_machine_key(&dir) {
                fallback_machine_keys.push(k);
            }
        }
        // macOS: v1 under the mDNS LocalHostName variants. When macOS
        // renames kern.hostname (the usual keystore-bricking event),
        // LocalHostName typically still holds the name the store was
        // written under, so these recover a drifted keystore with no
        // user action.
        if let Ok(user) = std::env::var("USER") {
            for h in local_hostname_variants() {
                fallback_machine_keys
                    .push(derive_machine_key_v1_from_parts(&h, &user, &canonical));
            }
        }
        // Order-preserving dedupe (Vec::dedup only folds adjacent repeats),
        // and drop any candidate equal to the primary -- retrying the same
        // key can only re-fail.
        let mut seen: Vec<[u8; 32]> = vec![machine_key];
        fallback_machine_keys.retain(|k| {
            if seen.contains(k) {
                false
            } else {
                seen.push(*k);
                true
            }
        });

        Ok(Self {
            dir,
            machine_key,
            fallback_machine_keys,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Generates a new Ed25519 keypair, encrypts and stores it.
    /// If `set_default` is true (or there is no current default), makes
    /// this key the default signing key.
    pub fn generate(&self, set_default: bool) -> Result<KeyInfo, KeyError> {
        let key_id = new_key_id();

        let signer = Ed25519Signer::generate(&key_id)
            .map_err(|e| KeyError::Crypto(e.to_string()))?;

        // `secret` is a Zeroizing<[u8; 32]> -- the caller-side copy of the
        // signer's secret scalar is wiped on scope exit. `signer` is dropped
        // at end of fn, which wipes its own copy via the Drop impl in
        // attestation::signer.
        let secret  = signer.secret_bytes();
        let pub_key = signer.public_key_bytes();

        let enc = encrypt_for_disk_v2(&self.machine_key, key_id.as_str(), &pub_key, secret.as_slice())
            .map_err(KeyError::Crypto)?;

        let entry = EncryptedEntry {
            id:               key_id.clone(),
            algorithm:        "ed25519".into(),
            created_at:       crate::statements::unix_to_rfc3339(unix_now()),
            public_key:       pub_key.clone(),
            enc_priv_key:     enc,
            // v2 ciphertexts carry their nonce inline (bytes [2..14]).
            // The separate `nonce` field is retained for v1 legacy
            // compatibility; for fresh v2 entries we serialize an empty
            // vec so the JSON stays well-formed.
            nonce:            Vec::new(),
            valid_until:      None,
            successor_key_id: None,
        };

        self.write_entry(&entry)?;

        // Update manifest.
        let mut manifest = self.read_manifest()?;
        manifest.key_ids.push(key_id.clone());
        if set_default || manifest.default_key_id.is_none() {
            manifest.default_key_id = Some(key_id.clone());
        }
        self.write_manifest(&manifest)?;

        // Populate cache.
        self.cache.write().unwrap().insert(key_id.clone(), entry);

        Ok(KeyInfo {
            id:               key_id.clone(),
            algorithm:        "ed25519".into(),
            is_default:       manifest.default_key_id.as_deref() == Some(key_id.as_str()),
            created_at:       crate::statements::unix_to_rfc3339(unix_now()),
            fingerprint:      fingerprint(&pub_key),
            public_key:       pub_key,
            valid_until:      None,
            successor_key_id: None,
        })
    }

    /// Rotate the current default key (or a specific key) to a freshly
    /// generated successor.
    ///
    /// Mints a new Ed25519 keypair, links the predecessor to it via
    /// `successor_key_id`, and stamps the predecessor with a `valid_until`
    /// of `now + grace_period`. The grace window lets verifiers continue to
    /// accept signatures from the predecessor while clients catch up to
    /// the new public key.
    ///
    /// If `set_default` is true (the typical case -- you rotate because you
    /// want to start signing with the new key immediately), the successor
    /// becomes the default. Pass `false` to stage a rotation for review
    /// without flipping the active signer.
    ///
    /// `predecessor_id` may be `None` to rotate the current default. Pass
    /// an explicit id to rotate a non-default key (e.g. a per-environment
    /// secondary).
    ///
    /// Note on threat model: this is a graceful rotation primitive, not a
    /// revocation primitive. If the predecessor key is suspected compromised
    /// the grace_period should be `Duration::ZERO` (or use a future
    /// `revoke()` call once that lands) so the predecessor's `valid_until`
    /// is in the past and any verifier honoring the metadata refuses
    /// further signatures from it.
    pub fn rotate(
        &self,
        predecessor_id: Option<&str>,
        grace_period: std::time::Duration,
        set_default: bool,
    ) -> Result<RotationResult, KeyError> {
        // Resolve predecessor: explicit id, else the current default.
        let pred_id = match predecessor_id {
            Some(id) => id.to_string(),
            None => self.default_key_id()?,
        };

        // Refuse to rotate a key that has already been rotated -- the
        // chain head is the only valid rotation source. This makes the
        // operation idempotent in the face of accidental re-runs.
        let pred_entry_existing = self.load_entry(&pred_id)?;
        if let Some(existing) = &pred_entry_existing.successor_key_id {
            return Err(KeyError::Crypto(format!(
                "key {pred_id} has already been rotated to {existing}; \
                 rotate the chain head instead"
            )));
        }

        // Mint the successor. We deliberately do NOT call `self.generate()`
        // because that path also updates the manifest's default. We need a
        // single transactional update that sets both predecessor metadata
        // AND (optionally) the new default in one manifest write.
        let succ_id = new_key_id();
        let signer = Ed25519Signer::generate(&succ_id)
            .map_err(|e| KeyError::Crypto(e.to_string()))?;
        // `succ_secret` is a Zeroizing<[u8; 32]>; the caller-side copy is
        // wiped on scope exit, and `signer` is dropped at end of fn (which
        // wipes its own copy via the attestation::signer Drop impl).
        let succ_secret  = signer.secret_bytes();
        let succ_pub_key = signer.public_key_bytes();
        let succ_enc =
            encrypt_for_disk_v2(&self.machine_key, succ_id.as_str(), &succ_pub_key, succ_secret.as_slice())
                .map_err(KeyError::Crypto)?;

        let succ_created = crate::statements::unix_to_rfc3339(unix_now());
        let succ_entry = EncryptedEntry {
            id:               succ_id.clone(),
            algorithm:        "ed25519".into(),
            created_at:       succ_created.clone(),
            public_key:       succ_pub_key.clone(),
            enc_priv_key:     succ_enc,
            // v2 ciphertexts carry their nonce inline; the legacy
            // `nonce` field is left empty for fresh writes.
            nonce:            Vec::new(),
            valid_until:      None,
            successor_key_id: None,
        };

        // Stamp the predecessor with the grace deadline and link forward.
        let valid_until = crate::statements::unix_to_rfc3339(
            unix_now() + grace_period.as_secs(),
        );
        let mut pred_entry = pred_entry_existing;
        pred_entry.valid_until      = Some(valid_until.clone());
        pred_entry.successor_key_id = Some(succ_id.clone());

        // Write order matters for partial-failure recovery. Persist the
        // successor entry FIRST, then stamp the predecessor pointing at
        // it. If we wrote the predecessor first and then the successor
        // write failed, the predecessor's successor_key_id would dangle
        // at a key that doesn't exist on disk -- and the
        // already-been-rotated guard would refuse to retry. With this
        // order:
        //   - successor write fails: nothing observable changed; retry clean.
        //   - predecessor write fails: orphan successor key file on disk
        //     (not yet referenced by manifest or by any other key); retry
        //     generates a new successor and the orphan is harmless.
        //   - manifest write fails: predecessor + successor both on disk,
        //     manifest stale; retry's already-rotated guard catches the
        //     half-finished state and surfaces a clear error.
        self.write_entry(&succ_entry)?;
        self.write_entry(&pred_entry)?;

        // Refresh the cache to mirror the on-disk state we just wrote --
        // BEFORE the manifest update. If the manifest write fails, the
        // cache must still match disk so a same-process retry sees the
        // half-rotated state and the already-rotated guard fires
        // correctly. Doing this AFTER write_manifest would leave a
        // window where disk reflects the rotation but the in-memory
        // cache still serves the unstamped predecessor, and a retry
        // from the same Store instance would generate a duplicate
        // successor -- defeating the whole point of the guard.
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(pred_entry.id.clone(), pred_entry.clone());
            cache.insert(succ_id.clone(),       succ_entry.clone());
        }

        // Update the manifest: register the new key, optionally promote it.
        let mut manifest = self.read_manifest()?;
        manifest.key_ids.push(succ_id.clone());
        if set_default {
            manifest.default_key_id = Some(succ_id.clone());
        }
        self.write_manifest(&manifest)?;

        let default_id = manifest.default_key_id.clone();
        let predecessor = KeyInfo {
            id:               pred_entry.id.clone(),
            algorithm:        pred_entry.algorithm.clone(),
            is_default:       default_id.as_deref() == Some(pred_entry.id.as_str()),
            created_at:       pred_entry.created_at.clone(),
            fingerprint:      fingerprint(&pred_entry.public_key),
            public_key:       pred_entry.public_key.clone(),
            valid_until:      pred_entry.valid_until.clone(),
            successor_key_id: pred_entry.successor_key_id.clone(),
        };
        let successor = KeyInfo {
            id:               succ_id.clone(),
            algorithm:        "ed25519".into(),
            is_default:       default_id.as_deref() == Some(succ_id.as_str()),
            created_at:       succ_created,
            fingerprint:      fingerprint(&succ_pub_key),
            public_key:       succ_pub_key,
            valid_until:      None,
            successor_key_id: None,
        };

        Ok(RotationResult {
            predecessor,
            successor,
            grace_period_until: valid_until,
        })
    }

    /// Walk the rotation chain forward from `id`, returning the ordered
    /// list of key ids: `[id, successor_of_id, ...]`. The first element is
    /// always `id` itself. Stops at a key with no `successor_key_id`.
    pub fn successor_chain(&self, id: &str) -> Result<Vec<KeyId>, KeyError> {
        let mut chain = Vec::new();
        let mut cursor = id.to_string();
        // Cap iterations at the manifest size to defend against a corrupt
        // chain that loops back on itself. A well-formed chain is bounded
        // by the number of keys in the keystore.
        let max_steps = self.read_manifest()?.key_ids.len() + 1;
        for _ in 0..max_steps {
            chain.push(cursor.clone());
            let entry = self.load_entry(&cursor)?;
            match entry.successor_key_id {
                Some(next) => cursor = next,
                None => return Ok(chain),
            }
        }
        Err(KeyError::Crypto(format!(
            "rotation chain starting at {id} exceeds keystore size; suspected loop"
        )))
    }

    /// Returns the `KeyInfo` for every key whose `valid_until` is either
    /// unset or strictly after `at_unix_secs`. The result includes both
    /// rotated-but-still-in-grace predecessors and never-rotated keys.
    /// Useful for building a verifier's accept-set as of a given time.
    pub fn valid_keys_at(&self, at_unix_secs: u64) -> Result<Vec<KeyInfo>, KeyError> {
        let cutoff_rfc = crate::statements::unix_to_rfc3339(at_unix_secs);
        Ok(self.list()?
            .into_iter()
            .filter(|k| match &k.valid_until {
                None => true,
                Some(until) => until.as_str() > cutoff_rfc.as_str(),
            })
            .collect())
    }

    /// Returns a boxed `Signer` for the current default key.
    pub fn default_signer(&self) -> Result<Box<dyn Signer>, KeyError> {
        let manifest = self.read_manifest()?;
        let id = manifest.default_key_id.ok_or(KeyError::NoDefaultKey)?;
        self.signer(&id)
    }

    /// Returns a boxed `Signer` for a specific key ID.
    ///
    /// Refuses to load if the on-disk key file has insecure permissions
    /// (any group or world bits). This is the choke point for *all*
    /// signing — public-key reads and successor lookups go through
    /// `read_entry` / `public_key` and are not affected.
    ///
    /// Bypass with `TREESHIP_ALLOW_INSECURE_KEY_PERMS=1` for controlled
    /// environments (CI sandboxes, recovery flows). The bypass should
    /// not be set in normal operation.
    ///
    /// TOCTOU note: the perm-check and the ciphertext read run against
    /// the SAME file descriptor (open once, fstat, then read from that
    /// fd). The previous shape — `check_key_file_perms(path)` followed
    /// by `load_entry(id)` (which called `fs::read(path)`) — opened the
    /// file twice. An attacker with write access to `~/.treeship/keys/`
    /// could swap the file between the two opens: first present an
    /// owner-only file to pass the perm gate, then replace it with a
    /// different (loose-perm) file containing an attacker-controlled
    /// scalar before the second `open`. The single-fd shape closes that
    /// window because the inode is pinned by the open file descriptor;
    /// path-level swaps after the open don't affect what we read. This
    /// matches the pattern in `session/event_log.rs::open_lock_file`.
    pub fn signer(&self, id: &str) -> Result<Box<dyn Signer>, KeyError> {
        let entry = self.read_entry_with_perm_check(id)?;

        // Dispatcher: v2 ciphertexts start with magic 0x54, version 0x02
        // and use real AES-256-GCM. Older entries fall through to the
        // legacy SHA-256-CTR+HMAC path (`decrypt_legacy_v1`) and are
        // transparently re-encrypted in the new format below.
        let was_legacy = is_legacy_v1(&entry.enc_priv_key);
        let mut used_fallback = false;
        let secret = match decrypt_from_disk(
            &self.machine_key,
            &entry.id,
            &entry.public_key,
            &entry.enc_priv_key,
            &entry.nonce,
        ) {
            Ok(secret) => secret,
            Err(primary_err) => {
                // The entry may be wrapped under an older machine-key
                // derivation: the v1 hostname key (any pre-stable keystore),
                // the raw-path key (pre-canonicalization through a symlink),
                // or a v1 key under a hostname macOS has since renamed away
                // (the LocalHostName candidates). Try each in order; the
                // first hit marks the entry for rewrapping under the
                // primary. All misses surface the PRIMARY error, enriched,
                // so the diagnosis is unchanged for normal failures.
                let mut recovered = None;
                for candidate in &self.fallback_machine_keys {
                    if let Ok(secret) = decrypt_from_disk(
                        candidate,
                        &entry.id,
                        &entry.public_key,
                        &entry.enc_priv_key,
                        &entry.nonce,
                    ) {
                        recovered = Some(secret);
                        used_fallback = true;
                        break;
                    }
                }
                match recovered {
                    Some(secret) => secret,
                    None => return Err(self.enrich_crypto_error(primary_err)),
                }
            }
        };

        // L3: wrap the on-stack copy of the decrypted secret in a
        // `Zeroizing` so the byte buffer is wiped on drop. `secret`
        // itself is already a `Zeroizing<Vec<u8>>` returned by
        // `decrypt_from_disk`, but `try_into::<[u8; 32]>` produces an
        // independent stack-allocated array that the Vec's Drop will
        // not cover. Without this wrapper, returning from `signer()`
        // would leave the secret scalar in stale stack memory until
        // a future stack frame happens to overwrite it.
        let secret_arr: Zeroizing<[u8; 32]> = Zeroizing::new(
            secret.as_slice().try_into()
                .map_err(|_| KeyError::Crypto("decrypted key is wrong length".into()))?
        );

        // Transparent migration: if this entry was still in the legacy
        // v1 format (the broken SHA-256-CTR construction from
        // TS-2026-001), re-encrypt it with v2 AES-256-GCM and rewrite
        // the file. We do this best-effort -- a migration failure here
        // must NOT block signing for the current call, since the
        // in-memory secret is already valid. The next decrypt on a
        // fresh process will retry.
        if was_legacy || used_fallback {
            if let Err(e) = self.migrate_entry_to_primary(&entry, &secret_arr) {
                // Surface the failure as a tracing-style stderr note
                // rather than an error -- the user's signing flow is
                // unaffected, and we'd rather them know about it than
                // wedge the call.
                eprintln!(
                    "treeship: keystore entry {} could not be rewrapped \
                     under the current machine key ({}); will retry next \
                     load",
                    entry.id, e
                );
            }
        }

        let signer = Ed25519Signer::from_bytes(&entry.id, &secret_arr)
            .map_err(|e| KeyError::Crypto(e.to_string()))?;

        Ok(Box::new(signer))
    }

    /// Re-encrypt a legacy v1 entry with the new v2 AEAD and persist
    /// it. Updates the in-memory cache so subsequent loads in the same
    /// process see the migrated entry. Idempotent; safe to invoke
    /// concurrently because the migration is serialized by a per-entry
    /// advisory lock on `<entry>.migrate.lock` (TS-2026-001 H3).
    ///
    /// We lock a *sentinel* file rather than the entry file itself,
    /// because the entry file is renamed-into-place during the atomic
    /// write inside `write_entry`. Holding a flock on the entry's inode
    /// while a sibling process renames a new inode into its path is
    /// nonsensical (the lock would survive on the now-orphaned inode);
    /// the sentinel sidecar has a stable identity for the whole
    /// migration window.
    ///
    /// Same blocking-flock pattern as `packages/core/src/session/event_log.rs`
    /// (Lane F): exclusive lock, then a same-thread re-read to settle
    /// "did a peer already migrate while I was waiting?" cleanly.
    fn migrate_entry_to_primary(
        &self,
        old_entry: &EncryptedEntry,
        secret: &[u8; 32],
    ) -> Result<(), KeyError> {
        let entry_path = self.entry_path(&old_entry.id);
        let lock_path = entry_path.with_extension("migrate.lock");

        // Open (or create) the sentinel lock file with restrictive perms
        // and take an exclusive flock. We intentionally use the blocking
        // `lock_exclusive` -- not `try_lock_exclusive` -- because the
        // migration window is short (a single AEAD encrypt + atomic
        // rename) and the worst case under contention is one writer
        // serialized behind another. Pulling the
        // try-with-bounded-retry pattern in here would buy us nothing:
        // the second writer's re-read after the lock releases would
        // observe the now-v2 entry and short-circuit.
        let lock_file = open_migration_lock_file(&lock_path)
            .map_err(KeyError::Io)?;

        #[cfg(not(target_family = "wasm"))]
        {
            use fs2::FileExt;
            lock_file.lock_exclusive().map_err(KeyError::Io)?;
        }

        // Under the lock: did a peer already complete the migration
        // while we were waiting? If so, our work is done -- we must
        // NOT rewrite, because we'd overwrite a peer's freshly-rotated
        // v2 ciphertext with our own (semantically equivalent, but
        // unnecessary I/O and an unnecessary cache update).
        if let Ok(current) = self.read_entry(&old_entry.id) {
            // "Already migrated" now means: v2 format AND decryptable under
            // the PRIMARY machine key. The format check alone is not enough
            // since this path also rewraps v2 entries that a fallback
            // machine key decrypted (hostname drift, raw-path legacy); the
            // primary-decrypt probe is what proves a peer finished the job.
            let already_primary = !is_legacy_v1(&current.enc_priv_key)
                && decrypt_from_disk(
                    &self.machine_key,
                    &current.id,
                    &current.public_key,
                    &current.enc_priv_key,
                    &current.nonce,
                )
                .is_ok();
            if already_primary {
                // Peer already migrated. Refresh the cache so subsequent
                // loads in this process see the rewrapped entry rather
                // than the stale copy our caller passed in.
                if let Ok(mut cache) = self.cache.write() {
                    cache.insert(current.id.clone(), current);
                }
                // Lock drops at function exit; sentinel file remains on
                // disk as a harmless inode (no migration data, idempotent
                // for future invocations).
                return Ok(());
            }
        }

        let new_ciphertext = encrypt_for_disk_v2(
            &self.machine_key,
            &old_entry.id,
            &old_entry.public_key,
            secret,
        )
        .map_err(KeyError::Crypto)?;

        let migrated = EncryptedEntry {
            id:               old_entry.id.clone(),
            algorithm:        old_entry.algorithm.clone(),
            created_at:       old_entry.created_at.clone(),
            public_key:       old_entry.public_key.clone(),
            enc_priv_key:     new_ciphertext,
            // v2 carries the nonce inline; clear the legacy field.
            nonce:            Vec::new(),
            valid_until:      old_entry.valid_until.clone(),
            successor_key_id: old_entry.successor_key_id.clone(),
        };

        self.write_entry(&migrated)?;
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(migrated.id.clone(), migrated);
        }

        // Best-effort cleanup of the sentinel lock file. We hold the
        // lock until function exit (drop), so by the time we reach
        // here it is safe to unlink the inode -- future migrations
        // for this entry will succeed via the early-return path
        // because the entry is now v2. Leaving the sentinel behind is
        // also harmless; on Unix removing a flocked file is allowed
        // and the lock is released on fd drop regardless.
        let _ = std::fs::remove_file(&lock_path);

        // Keep the lock_file binding alive to function exit so the
        // flock is held across write_entry + remove_file. Explicit
        // drop makes the intent obvious to readers.
        drop(lock_file);
        Ok(())
    }

    /// Wrap a bare crypto error (typically "MAC verification failed ..." from
    /// the AES-GCM decrypt path) with a diagnostic and an actionable recovery
    /// path.
    ///
    /// The common failure mode in the wild is a pre-0.9.x keystore whose
    /// machine-key derivation was seed-file-based. Later versions derive
    /// the machine key from hostname+username (macOS) or /etc/machine-id
    /// (Linux), so old ciphertexts can't be MAC-verified with the new key.
    /// Detecting that case is best-effort: the presence of a legacy seed
    /// file (`.machineseed` or `machine_seed` inside the keys dir) is a
    /// strong hint. If we see one, call it out explicitly.
    fn enrich_crypto_error(&self, raw: String) -> KeyError {
        // Only enrich on MAC failures -- other errors (I/O, wrong length) are
        // surfaced as-is because their remediation differs.
        if !raw.contains("MAC verification failed") {
            return KeyError::Crypto(raw);
        }

        let legacy_seed_dot = self.dir.join(".machineseed");
        let legacy_seed     = self.dir.join("machine_seed");
        let has_legacy_seed = legacy_seed_dot.exists() || legacy_seed.exists();

        let diagnosis = if has_legacy_seed {
            "your keystore was created by an older Treeship version whose \
             machine-key derivation has since changed. The ciphertext is \
             intact but cannot be decrypted under the current derivation."
        } else {
            "the keystore cannot be decrypted under any known machine-key \
             derivation (hardware id, current hostname, mDNS LocalHostName, \
             raw path). Usual causes: the key file was copied from a \
             different machine, the username changed, or the file was \
             corrupted."
        };

        // Resolve the user's ~/.treeship path for the recovery command, so
        // we give a copy-pasteable command rather than a generic instruction.
        let ts_dir = std::env::var("HOME")
            .map(|h| format!("{h}/.treeship"))
            .unwrap_or_else(|_| "~/.treeship".into());

        // The outer KeyError::Crypto Display impl already prepends
        // "keys crypto: "; don't double it. Start with the raw MAC error
        // so the user still sees the underlying cryptographic reason,
        // then follow with the human-readable diagnosis and recovery.
        let msg = format!(
            "{raw}\n\n  \
             Diagnosis: {diagnosis}\n\n  \
             Recovery (nondestructive -- the old keystore is moved aside, \
             not deleted; any sealed .treeship packages you produced remain \
             verifiable since their receipts embed the old public key):\n\n    \
             mv {ts_dir} {ts_dir}.bak.$(date +%s)\n    \
             treeship init\n"
        );

        KeyError::Crypto(msg)
    }

    /// Returns the default key ID.
    pub fn default_key_id(&self) -> Result<KeyId, KeyError> {
        self.read_manifest()?
            .default_key_id
            .ok_or(KeyError::NoDefaultKey)
    }

    /// Lists all keys.
    pub fn list(&self) -> Result<Vec<KeyInfo>, KeyError> {
        let manifest = self.read_manifest()?;
        let default  = manifest.default_key_id.as_deref().unwrap_or("");

        manifest.key_ids.iter().map(|id| {
            let entry = self.load_entry(id)?;
            Ok(KeyInfo {
                id:               entry.id.clone(),
                algorithm:        entry.algorithm.clone(),
                is_default:       entry.id == default,
                created_at:       entry.created_at.clone(),
                fingerprint:      fingerprint(&entry.public_key),
                public_key:       entry.public_key.clone(),
                valid_until:      entry.valid_until.clone(),
                successor_key_id: entry.successor_key_id.clone(),
            })
        }).collect()
    }

    /// Sets the default signing key.
    pub fn set_default(&self, id: &str) -> Result<(), KeyError> {
        // Verify the key exists before updating the manifest.
        self.load_entry(id)?;
        let mut manifest = self.read_manifest()?;
        manifest.default_key_id = Some(id.to_string());
        self.write_manifest(&manifest)
    }

    /// Returns the public key bytes for a key ID.
    pub fn public_key(&self, id: &str) -> Result<Vec<u8>, KeyError> {
        Ok(self.load_entry(id)?.public_key)
    }

    // --- private ---

    fn load_entry(&self, id: &str) -> Result<EncryptedEntry, KeyError> {
        // Check cache first.
        if let Ok(cache) = self.cache.read() {
            if let Some(entry) = cache.get(id) {
                return Ok(entry.clone());
            }
        }
        self.read_entry(id)
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{}.json", id))
    }

    fn write_entry(&self, entry: &EncryptedEntry) -> Result<(), KeyError> {
        let path = self.entry_path(&entry.id);
        let json = serde_json::to_vec_pretty(entry)?;
        write_file_600(&path, &json)?;
        Ok(())
    }

    fn read_entry(&self, id: &str) -> Result<EncryptedEntry, KeyError> {
        let path = self.entry_path(id);
        if !path.exists() {
            return Err(KeyError::NotFound(id.to_string()));
        }
        let bytes = fs::read(&path)?;
        let entry: EncryptedEntry = serde_json::from_slice(&bytes)?;
        Ok(entry)
    }

    /// Single-open, race-free counterpart to `read_entry` for the
    /// signing path. Opens the key file ONCE, fstat's the file
    /// descriptor to check perms, then reads the JSON from the SAME
    /// descriptor. The path is never re-resolved after the open, so an
    /// attacker who swaps `<id>.json` on disk between the perm check
    /// and the ciphertext read cannot influence the bytes we decrypt.
    ///
    /// Cache: this path intentionally skips the in-memory entry cache.
    /// The cache is read-mostly and seeded by `load_entry`, which is
    /// fine for public-key lookups but defeats the perm gate (a cached
    /// entry would let `signer()` return without ever consulting the
    /// on-disk perms). The signing path is rare enough that the extra
    /// disk read is not a hot spot.
    fn read_entry_with_perm_check(&self, id: &str) -> Result<EncryptedEntry, KeyError> {
        let path = self.entry_path(id);

        // Open once. NotFound surfaces as `KeyError::NotFound` to
        // match the legacy `read_entry` shape; any other I/O error
        // (permission denied at the *open* layer, EIO, etc.)
        // propagates via the `From<io::Error>` impl.
        let mut file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(KeyError::NotFound(id.to_string()));
            }
            Err(e) => return Err(KeyError::Io(e)),
        };

        // Perm check on the open fd. On Unix `File::metadata` is
        // documented to call `fstat` on the underlying fd, which pins
        // the inode -- a subsequent path swap on disk cannot change
        // what we see. The bypass env var continues to short-circuit.
        check_open_key_file_perms(&path, &file)?;

        // Read the full ciphertext envelope from the same fd.
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        let entry: EncryptedEntry = serde_json::from_slice(&bytes)?;
        Ok(entry)
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join("manifest.json")
    }

    fn read_manifest(&self) -> Result<Manifest, KeyError> {
        let path = self.manifest_path();
        if !path.exists() {
            return Ok(Manifest::default());
        }
        let bytes = fs::read(&path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write_manifest(&self, m: &Manifest) -> Result<(), KeyError> {
        let json = serde_json::to_vec_pretty(m)?;
        write_file_600(&self.manifest_path(), &json)?;
        Ok(())
    }
}

// --- Crypto helpers ---
//
// AEAD choice: AES-256-GCM via the RustCrypto `aes-gcm` 0.10 crate.
// Reasons:
//   - Matches the original (documented but never implemented) intent of
//     the keystore, so audit reports and SECURITY.md don't need to be
//     re-anchored on a different primitive.
//   - Well-audited, widely deployed, no platform gotchas.
//   - `chacha20poly1305` would have been a defensible alternative
//     (slightly better software performance), but the migration cost of
//     changing the documented primitive while we already have to ship a
//     migration for the broken construction is not worth it.
//
// On-disk v2 format (`encrypt_for_disk_v2`):
//   [ magic = 0x54 ('T') ]   1 byte
//   [ version = 0x02     ]   1 byte
//   [ nonce              ]  12 bytes (random per encryption)
//   [ ciphertext || tag  ]  N + 16 bytes (tag appended by aead crate)
//
// The first byte (0x54) is a structural sentinel so we can dispatch on
// the format without relying on length heuristics. v1 ciphertexts start
// with the first byte of their random nonce, so the chance of an
// accidental v1 entry that looks like v2 is ~1/2^16 (matching both magic
// AND version byte) and we still re-validate by AEAD-decrypting; if the
// AEAD fails on something that looks like v2, we fall back to v1.

const KEYSTORE_MAGIC: u8 = 0x54; // 'T'
const KEYSTORE_VERSION_V2: u8 = 0x02;

/// Build the v2 keystore AEAD AAD.
///
/// The AAD binds two things into the GCM tag beyond ciphertext+nonce:
///
/// 1. **Framing prefix** (`[KEYSTORE_MAGIC, KEYSTORE_VERSION_V2]`) so
///    flipping the magic or version byte on disk surfaces as a MAC
///    failure rather than dispatcher confusion (the M2 audit finding).
/// 2. **Entry identity** (`entry_id` and `public_key`) so an attacker
///    with write access to `~/.treeship/keys/` cannot copy entry A's
///    `enc_priv_key` ciphertext into entry B's JSON envelope. Without
///    this binding, the swap would decrypt cleanly (same machine key,
///    same framing-only AAD) and the signer for advertised key id A
///    would silently sign with key B's secret scalar — un-binding
///    `KeyInfo.public_key` from the actual scalar in use. This closes
///    the "intra-keystore swap" class flagged in the post-merge audit
///    of TS-2026-001.
///
/// Every variable-length field is length-prefixed with a big-endian
/// u32 before its bytes. Concatenating variable-length fields without
/// length prefixes is a forgery class (an attacker who controls field
/// boundaries can shift bytes between fields and present a different
/// `(entry_id, public_key)` pair whose AAD-bytes serialize identically).
/// `entry_id` is a fixed-prefix `key_<hex>` string in practice, but we
/// length-prefix it anyway to defend against future id schemes.
///
/// The AAD must be byte-identical on encrypt and decrypt. Future
/// versions (V3+) get their own builder; the dispatcher picks which
/// to use based on the framing prefix.
fn build_aad_v2(entry_id: &str, public_key: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(2 + 4 + entry_id.len() + 4 + public_key.len());
    aad.push(KEYSTORE_MAGIC);
    aad.push(KEYSTORE_VERSION_V2);
    aad.extend_from_slice(&(entry_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(entry_id.as_bytes());
    aad.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
    aad.extend_from_slice(public_key);
    aad
}

/// AES-256-GCM (the real one) encrypt for at-rest keystore storage.
/// Returns the framed v2 blob ready to drop into `EncryptedEntry::enc_priv_key`.
///
/// Output: `[magic, version, nonce(12), ciphertext || tag(16)]`.
///
/// The AEAD's Associated Authenticated Data binds:
/// - the framing prefix (M2 — flipping magic/version surfaces as MAC failure)
/// - the entry id and public key (post-merge audit fix-up — closes the
///   intra-keystore swap class where a local attacker copies entry A's
///   `enc_priv_key` into entry B's JSON envelope).
///
/// See `build_aad_v2` for the exact layout. `entry_id` and `public_key`
/// must match what gets serialized into the `EncryptedEntry` JSON;
/// `decrypt_for_disk_v2` reads them back from the deserialized entry
/// to recompute the AAD.
fn encrypt_for_disk_v2(
    key: &[u8; 32],
    entry_id: &str,
    public_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    // Wrap the in-memory AEAD key in Zeroizing so the local stack copy
    // is wiped on drop. The aes-gcm cipher object owns its own internal
    // expanded key schedule; that's outside our control, but the raw
    // 32-byte buffer at this scope is ours to clear.
    let key_buf: Zeroizing<[u8; 32]> = Zeroizing::new(*key);
    let aead_key: &AesKey<Aes256Gcm> = AesKey::<Aes256Gcm>::from_slice(key_buf.as_slice());
    let cipher = Aes256Gcm::new(aead_key);

    // 96-bit random nonce from the OS CSPRNG.
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);

    let aad = build_aad_v2(entry_id, public_key);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: aad.as_slice(),
            },
        )
        .map_err(|e| format!("aead encrypt failed: {e}"))?;

    let mut out = Vec::with_capacity(2 + 12 + ciphertext.len());
    out.push(KEYSTORE_MAGIC);
    out.push(KEYSTORE_VERSION_V2);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// AES-256-GCM decrypt of a v2 framed blob. Uses the same AAD binding
/// as `encrypt_for_disk_v2`:
///   - framing prefix (so a tampered magic/version surfaces as MAC failure)
///   - entry id + public key (so swapping `enc_priv_key` between entries
///     in the same keystore surfaces as MAC failure).
///
/// `entry_id` and `public_key` come from the `EncryptedEntry` JSON
/// envelope that holds `blob`. The caller is responsible for passing the
/// *envelope's* id and pubkey, not values from some other source — that
/// is precisely what binds the ciphertext to its envelope.
fn decrypt_v2(
    key: &[u8; 32],
    entry_id: &str,
    public_key: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, String> {
    // Minimum: magic(1) + version(1) + nonce(12) + tag(16) = 30 bytes.
    if blob.len() < 30 {
        return Err("v2 ciphertext too short".into());
    }
    if blob[0] != KEYSTORE_MAGIC || blob[1] != KEYSTORE_VERSION_V2 {
        return Err("v2 ciphertext has wrong magic/version".into());
    }
    let nonce_bytes = &blob[2..14];
    let ct = &blob[14..];

    let key_buf: Zeroizing<[u8; 32]> = Zeroizing::new(*key);
    let aead_key: &AesKey<Aes256Gcm> = AesKey::<Aes256Gcm>::from_slice(key_buf.as_slice());
    let cipher = Aes256Gcm::new(aead_key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let aad = build_aad_v2(entry_id, public_key);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| "MAC verification failed — key file may be corrupt or wrong machine".into())
}

/// Returns true iff `blob` is shaped like a v1 (legacy) ciphertext.
/// Used by the dispatcher to decide whether a successful decrypt should
/// trigger a transparent re-encrypt to v2.
fn is_legacy_v1(blob: &[u8]) -> bool {
    // A v2 blob always starts with [magic, version]. Anything else
    // (including the empty enc_priv_key case during partial writes) is
    // treated as legacy and routed through the v1 path, which will fail
    // cleanly on garbage.
    !(blob.len() >= 2 && blob[0] == KEYSTORE_MAGIC && blob[1] == KEYSTORE_VERSION_V2)
}

/// Top-level decrypt dispatcher used by the keystore. Tries v2 if the
/// blob carries the magic+version prefix, otherwise falls through to the
/// legacy v1 path. If a blob looks like v2 but AEAD verification fails,
/// we also try v1 — this defends against the (negligible) probability
/// that a legacy ciphertext's random first two bytes happen to collide
/// with our magic+version.
///
/// M1 (TS-2026-001 audit): when the blob is v2-shaped and BOTH the v2
/// AEAD and the v1 fallback fail, surface the v2 error rather than the
/// v1 error. v1's failure on a v2-shaped blob is mechanical (wrong
/// MAC computed under the wrong construction) and tells the user
/// nothing useful; v2's failure is the actually-relevant signal
/// (MAC verification under the documented AEAD). The previous code
/// would mask the meaningful error with a confused legacy error
/// message that pointed at the wrong remediation.
fn decrypt_from_disk(
    key: &[u8; 32],
    entry_id: &str,
    public_key: &[u8],
    enc_data: &[u8],
    legacy_nonce_field: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if !is_legacy_v1(enc_data) {
        match decrypt_v2(key, entry_id, public_key, enc_data) {
            Ok(pt) => return Ok(Zeroizing::new(pt)),
            Err(v2_err) => {
                // Collision fallback. v1 entries had random first bytes;
                // there's a vanishing chance one looks like v2 framing.
                // Try v1 first; if it succeeds we have a legitimate
                // legacy entry whose framing happens to look v2-shaped.
                // If v1 also fails, surface the v2 error (the
                // semantically meaningful one) rather than v1's
                // mechanical-junk failure.
                return match decrypt_legacy_v1(key, enc_data, legacy_nonce_field) {
                    Ok(pt) => Ok(Zeroizing::new(pt)),
                    Err(_) => Err(v2_err),
                };
            }
        }
    }
    decrypt_legacy_v1(key, enc_data, legacy_nonce_field).map(Zeroizing::new)
}

/// DEPRECATED: legacy at-rest decryption for keystores written before
/// v0.10.3. This is the SHA-256-CTR + HMAC-SHA-256 construction that
/// was mis-labelled as AES-256-GCM (TS-2026-001). The CTR keystream is
/// also degenerate (the same `enc_key` byte is reused once per
/// plaintext byte, since `block[i % 32]` indexes the same SHA-256 output
/// modulo 32), so the construction is NOT a real stream cipher even
/// ignoring the AEAD mislabelling.
///
/// Kept ONLY to migrate existing on-disk keystores forward to the v2
/// AEAD format. Never call this for new writes. The encrypt counterpart
/// has been removed from the v2 codepath — the only place v1
/// ciphertexts come from is files written by older Treeship versions.
pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    enc_data: &[u8],
    _nonce_unused: &[u8],
) -> Result<Vec<u8>, String> {
    // Preserved as a public symbol because the `treeship-vi` sibling
    // crate calls it directly. vi only ever produces v1 ciphertexts
    // (its `aes_gcm_encrypt` shim calls `legacy_v1_encrypt`) and has
    // no concept of the `EncryptedEntry` envelope that carries the
    // entry id + public key the v2 AAD now requires. Route this shim
    // directly through the legacy v1 path so vi's call site keeps
    // working byte-for-byte; vi's eventual migration release will
    // adopt its own AEAD path with its own envelope binding.
    decrypt_legacy_v1(key, enc_data, _nonce_unused)
}

/// DEPRECATED: legacy at-rest encryption. Same caveats as
/// `aes_gcm_decrypt`. Kept ONLY as a public symbol for compatibility
/// with the `treeship-vi` sibling crate; the core keystore no longer
/// produces v1 ciphertexts.
///
/// New code MUST use `encrypt_for_disk_v2`. This function still
/// produces v1-format output so the vi crate's on-disk format remains
/// byte-stable until it migrates on its own cadence.
pub fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    legacy_v1_encrypt(key, plaintext)
}

/// Legacy v1 encrypt. SHA-256-CTR + HMAC-SHA-256. DO NOT USE for new
/// writes — present only so vi-keystore callers keep working until
/// they migrate. See `aes_gcm_encrypt` doc-comment for the security
/// caveats.
fn legacy_v1_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use sha2::Sha256;

    let mut nonce = [0u8; 12];
    // v0.10.4 P1 audit: nonce reuse breaks AEAD. Read directly from the OS
    // CSPRNG via OsRng rather than the userland thread_rng, which can mis-seed
    // across forks / on some WASM targets. Legacy v1 write path is kept for
    // treeship-vi byte-stability but still needs sound nonces.
    OsRng.fill_bytes(&mut nonce);

    let mut enc_key_input = key.to_vec();
    enc_key_input.extend_from_slice(&nonce);
    enc_key_input.extend_from_slice(b"enc");
    let enc_key = Sha256::digest(&enc_key_input);

    let mut mac_key_input = key.to_vec();
    mac_key_input.extend_from_slice(&nonce);
    mac_key_input.extend_from_slice(b"mac");
    let mac_key = Sha256::digest(&mac_key_input);

    let ciphertext: Vec<u8> = plaintext.iter().enumerate().map(|(i, &b)| {
        let mut block_input = enc_key.to_vec();
        block_input.extend_from_slice(&(i as u64).to_le_bytes());
        let block = Sha256::digest(&block_input);
        b ^ block[i % 32]
    }).collect();

    let mut mac_input = mac_key.to_vec();
    mac_input.extend_from_slice(&nonce);
    mac_input.extend_from_slice(&ciphertext);
    let mac = Sha256::digest(&mac_input);

    let mut out = Vec::with_capacity(12 + 32 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&mac);
    out.extend_from_slice(&ciphertext);

    Ok((out, nonce.to_vec()))
}

/// Legacy v1 decrypt. SHA-256-CTR + HMAC-SHA-256. See the module-level
/// notes on TS-2026-001 for why this is broken; kept only to migrate
/// existing keystores forward.
fn decrypt_legacy_v1(
    key: &[u8; 32],
    enc_data: &[u8],
    _nonce_unused: &[u8],
) -> Result<Vec<u8>, String> {
    if enc_data.len() < 44 {
        return Err("ciphertext too short".into());
    }
    use sha2::Sha256;

    let nonce      = &enc_data[..12];
    let stored_mac = &enc_data[12..44];
    let ciphertext = &enc_data[44..];

    let nonce_arr: [u8; 12] = nonce.try_into().unwrap();

    let mut enc_key_input = key.to_vec();
    enc_key_input.extend_from_slice(&nonce_arr);
    enc_key_input.extend_from_slice(b"enc");
    let enc_key = Sha256::digest(&enc_key_input);

    let mut mac_key_input = key.to_vec();
    mac_key_input.extend_from_slice(&nonce_arr);
    mac_key_input.extend_from_slice(b"mac");
    let mac_key = Sha256::digest(&mac_key_input);

    let mut mac_input = mac_key.to_vec();
    mac_input.extend_from_slice(&nonce_arr);
    mac_input.extend_from_slice(ciphertext);
    let computed_mac = Sha256::digest(&mac_input);

    let mac_ok = stored_mac.iter().zip(computed_mac.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;

    if !mac_ok {
        return Err("MAC verification failed — key file may be corrupt or wrong machine".into());
    }

    let plaintext: Vec<u8> = ciphertext.iter().enumerate().map(|(i, &b)| {
        let mut block_input = enc_key.to_vec();
        block_input.extend_from_slice(&(i as u64).to_le_bytes());
        let block = Sha256::digest(&block_input);
        b ^ block[i % 32]
    }).collect();

    Ok(plaintext)
}

// --- Machine key derivation ---

pub fn derive_machine_key(store_dir: &Path) -> Result<[u8; 32], KeyError> {
    // 1. Linux: /etc/machine-id (stable across reboots)
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            let mut h = Sha256::new();
            h.update(trimmed.as_bytes());
            h.update(store_dir.to_string_lossy().as_bytes());
            return Ok(h.finalize().into());
        }
    }

    // 2. macOS: hostname + username derivation (v1, backward compatible).
    //
    // TODO(v0.7.0): Migrate to IOPlatformSerialNumber-based derivation.
    // The serial number is more stable (survives hostname and username
    // changes), but switching now would silently invalidate all existing
    // keys on macOS. A proper migration needs to:
    //   1. Try the new derivation first.
    //   2. On decryption failure, fall back to hostname+username.
    //   3. If legacy succeeds, re-encrypt with the new key and save.
    // Until that migration tooling is in place, keep hostname+username
    // as the primary derivation so existing users are not locked out.
    #[cfg(target_os = "macos")]
    {
        let hostname = std::process::Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let username = std::env::var("USER").unwrap_or_default();
        if !hostname.is_empty() && !username.is_empty() {
            return Ok(derive_machine_key_v1_from_parts(
                &hostname, &username, store_dir,
            ));
        }
    }

    // 3. Fallback: random seed file. Co-located with the keystore so a
    //    project-local keystore (/proj/.treeship/keys/) keeps its seed at
    //    /proj/.treeship/machine_seed -- never reaching for ~/.treeship.
    //    A global keystore (~/.treeship/keys/) co-locates to
    //    ~/.treeship/machine_seed, which is byte-identical to the
    //    pre-v0.9.6 location, so existing global keystores keep working.
    //
    //    Backward-compat read order:
    //      1. <store_dir>/../machine_seed  (the new co-located path)
    //      2. ~/.treeship/machine_seed     (the old hardcoded path)
    //    Write order on first creation:
    //      1. <store_dir>/../machine_seed  if the parent exists/is writable
    //      2. ~/.treeship/machine_seed     as a last resort
    //
    //    This makes project-local config truly self-contained: an
    //    isolated /proj keystore can decrypt its own keys even when
    //    the user's ~/.treeship is corrupt or on a different machine,
    //    closing the trust-fabric isolation gap that blocked
    //    project-local smoke tests.
    let local_seed_path = store_dir.parent().map(|p| p.join("machine_seed"));
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| KeyError::Crypto("HOME not set".to_string()))?;
    let global_seed_path = home.join(".treeship").join("machine_seed");

    let seed = if let Some(local) = local_seed_path.as_ref().filter(|p| p.exists()) {
        fs::read_to_string(local).map_err(KeyError::Io)?
    } else if global_seed_path.exists() {
        // Backward-compat: an existing global seed keeps decrypting any
        // keystore that was encrypted under it (in particular the
        // standard ~/.treeship/keys/ case where local == global).
        fs::read_to_string(&global_seed_path).map_err(KeyError::Io)?
    } else {
        let mut bytes = [0u8; 32];
        // v0.10.4 P1 audit: this seed becomes the machine-key fallback used to
        // wrap on-disk private keys. Source straight from the OS entropy pool.
        OsRng.fill_bytes(&mut bytes);
        let seed_hex = hex_encode(&bytes);

        // Prefer creating the seed locally. Falls back to the global
        // path only when the keystore has no usable parent (rare;
        // happens when store_dir is "/" or similar pathological input).
        let target = match local_seed_path.as_ref() {
            Some(p) => {
                let _ = fs::create_dir_all(p.parent().unwrap_or(Path::new(".")));
                p.clone()
            }
            None => {
                let _ = fs::create_dir_all(global_seed_path.parent().unwrap_or(Path::new(".")));
                global_seed_path.clone()
            }
        };
        fs::write(&target, &seed_hex).map_err(KeyError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o600));
        }
        seed_hex
    };

    let mut h = Sha256::new();
    h.update(b"treeship-machine-key-fallback:");
    h.update(seed.trim().as_bytes());
    h.update(b":");
    h.update(store_dir.to_string_lossy().as_bytes());
    Ok(h.finalize().into())
}

/// The v1 hostname+username machine-key derivation, as a pure function of
/// its inputs. This is the exact construction the macOS branch of
/// [`derive_machine_key`] has always used; extracting it lets `Store::open`
/// derive decrypt-only fallback candidates for hostnames the machine no
/// longer reports (macOS renames `kern.hostname` on network collisions,
/// which used to brick the keystore) without shelling `hostname` twice.
pub fn derive_machine_key_v1_from_parts(
    hostname: &str,
    username: &str,
    store_dir: &Path,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"treeship-machine-key:");
    h.update(hostname.as_bytes());
    h.update(b":");
    h.update(username.as_bytes());
    h.update(b":");
    h.update(store_dir.to_string_lossy().as_bytes());
    h.finalize().into()
}

/// Hostname candidates a drifted macOS keystore may be wrapped under.
///
/// `scutil --get LocalHostName` holds the user-visible mDNS name, which
/// usually retains the value `hostname` reported when the keystore was
/// written even after macOS renames `kern.hostname` (DHCP, name-collision
/// auto-renames). `hostname` historically reported it with and without the
/// `.local` suffix depending on network state, so both variants are
/// candidates. Non-macOS platforms have no such drift (machine-id is
/// stable) and return no candidates.
#[cfg(target_os = "macos")]
fn local_hostname_variants() -> Vec<String> {
    let lh = std::process::Command::new("scutil")
        .args(["--get", "LocalHostName"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if lh.is_empty() {
        return Vec::new();
    }
    vec![format!("{lh}.local"), lh]
}

#[cfg(not(target_os = "macos"))]
fn local_hostname_variants() -> Vec<String> {
    Vec::new()
}

/// The hardware-identifier half of [`derive_machine_key_stable`]: machine-id
/// (Linux) or IOPlatformSerialNumber (macOS), `None` when the machine offers
/// neither. Split out so `Store::open` can pick a hardware-stable PRIMARY
/// key without inheriting the stable derivation's seed-file fallback, whose
/// seed lives under the global `~/.treeship/.internal/` and would break
/// project-local keystore isolation (the v1 seed is co-located with the
/// keystore on purpose).
fn stable_hardware_key(store_dir: &Path) -> Option<[u8; 32]> {
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            let mut h = Sha256::new();
            h.update(b"treeship-machine-key-v2:");
            h.update(trimmed.as_bytes());
            h.update(b":");
            h.update(store_dir.to_string_lossy().as_bytes());
            return Some(h.finalize().into());
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("IOPlatformSerialNumber") {
                    if let Some(serial) = line.split('"').nth(3) {
                        if !serial.is_empty() {
                            let mut h = Sha256::new();
                            h.update(b"treeship-machine-key-v2:");
                            h.update(serial.as_bytes());
                            h.update(b":");
                            h.update(store_dir.to_string_lossy().as_bytes());
                            return Some(h.finalize().into());
                        }
                    }
                }
            }
        }
    }

    None
}

/// Stable machine key derivation for NEW keys (VI P-256, etc).
/// Uses hardware identifiers that survive hostname/user changes.
/// For legacy ship Ed25519 keys, use `derive_machine_key()` instead.
pub fn derive_machine_key_stable(store_dir: &Path) -> Result<[u8; 32], KeyError> {
    // 1./2. Hardware identifiers: /etc/machine-id (Linux) or
    //    IOPlatformSerialNumber (macOS) -- stable across hostname changes,
    //    user renames, non-interactive shells. Shared with `Store::open`'s
    //    primary-key selection via `stable_hardware_key`.
    if let Some(k) = stable_hardware_key(store_dir) {
        return Ok(k);
    }

    // 3. Fallback: persistent random seed in ~/.treeship/.internal/
    //    Separate from key material. Mode 0600.
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| KeyError::Crypto("HOME not set".to_string()))?;
    let seed_dir = home.join(".treeship").join(".internal");
    let _ = fs::create_dir_all(&seed_dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&seed_dir, fs::Permissions::from_mode(0o700));
    }

    let seed_path = seed_dir.join("machine_seed_v2");
    let seed = if seed_path.exists() {
        fs::read_to_string(&seed_path).map_err(KeyError::Io)?
    } else {
        let mut bytes = [0u8; 32];
        // v0.10.4 P1 audit: machine_seed_v2 backs the v2 machine-key
        // fallback. Same OsRng rationale as the v1 seed above.
        OsRng.fill_bytes(&mut bytes);
        let seed_hex = hex_encode(&bytes);
        fs::write(&seed_path, &seed_hex).map_err(KeyError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600));
        }
        seed_hex
    };

    let mut h = Sha256::new();
    h.update(b"treeship-machine-key-v2-fallback:");
    h.update(seed.trim().as_bytes());
    h.update(b":");
    h.update(store_dir.to_string_lossy().as_bytes());
    Ok(h.finalize().into())
}

// --- Utility ---

fn new_key_id() -> KeyId {
    let mut b = [0u8; 8];
    // v0.10.4 P1 audit: key_id is mixed into AAD by encrypt_for_disk_v2, so
    // collisions or low-entropy ids would weaken the AAD binding. Use OsRng
    // directly so the id is OS-CSPRNG-quality even under fork or odd targets.
    OsRng.fill_bytes(&mut b);
    format!("key_{}", hex_encode(&b))
}

fn fingerprint(pub_key: &[u8]) -> String {
    let h = Sha256::digest(pub_key);
    hex_encode(&h[..8])
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, byte| {
        s.push_str(&format!("{:02x}", byte));
        s
    })
}

/// Verify a private-key file has restrictive permissions before loading
/// it for signing. Returns `Ok(())` on non-Unix platforms, when the
/// `TREESHIP_ALLOW_INSECURE_KEY_PERMS=1` escape hatch is set, or when
/// the file is not group/world accessible. Otherwise returns
/// `KeyError::InsecureKeyPerms` with the offending path and mode.
///
/// **TOCTOU caveat:** this path-based check has an unavoidable race
/// window between the `stat` and any subsequent `open` of the same
/// path. New signing-path callers MUST use
/// `check_open_key_file_perms` (fstat on an already-open fd) instead;
/// this function is retained only for non-signing callers that
/// already accept the race (e.g. `treeship doctor` scanning the
/// keystore directory).
#[allow(dead_code)]
fn check_key_file_perms(path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("TREESHIP_ALLOW_INSECURE_KEY_PERMS")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            return Ok(());
        }
        // Missing files are reported by the caller as NotFound -- don't
        // mask that with a perm error.
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(KeyError::InsecureKeyPerms {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    let _ = path;
    Ok(())
}

/// Race-free perm gate: runs `fstat` on an already-open `File` and
/// rejects if the mode has any group or world bits. Use this from the
/// signing path: open the key file once, hand the resulting `File` to
/// this function, then read from the SAME `File` -- the inode is
/// pinned by the open fd, so a path-level swap between perm-check and
/// read cannot influence what we end up decrypting.
///
/// `path` is carried only for error reporting; it is never re-opened.
/// The `TREESHIP_ALLOW_INSECURE_KEY_PERMS=1` bypass is honored
/// identically to `check_key_file_perms` so existing CI workflows keep
/// working.
#[allow(unused_variables)]
fn check_open_key_file_perms(path: &Path, file: &fs::File) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("TREESHIP_ALLOW_INSECURE_KEY_PERMS")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            return Ok(());
        }
        // `File::metadata` on Unix calls `fstat(fd)` -- it does NOT
        // re-resolve the path, so the result describes the same inode
        // we will read from. This is the structural property that
        // makes the gate race-free.
        let meta = file.metadata()?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(KeyError::InsecureKeyPerms {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    Ok(())
}

impl Store {
    /// Repair file permissions on the keystore directory and every file
    /// inside it: dir to 0700, key entry files and manifest to 0600.
    /// Used by `treeship doctor --fix`. No-op on non-Unix.
    ///
    /// Returns the list of (path, old_mode, new_mode) tuples for paths
    /// that were actually changed, so the caller can report what it did.
    pub fn fix_perms(&self) -> Result<Vec<(PathBuf, u32, u32)>, KeyError> {
        let mut changed: Vec<(PathBuf, u32, u32)> = Vec::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir_meta = fs::metadata(&self.dir)?;
            let dir_mode = dir_meta.permissions().mode() & 0o777;
            if dir_mode != 0o700 {
                fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
                changed.push((self.dir.clone(), dir_mode, 0o700));
            }

            for entry in fs::read_dir(&self.dir)? {
                let entry = entry?;
                let path = entry.path();
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let mode = entry.metadata()?.permissions().mode() & 0o777;
                if mode != 0o600 {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                    changed.push((path, mode, 0o600));
                }
            }
        }
        Ok(changed)
    }
}

/// Open (or create) the per-entry migration sentinel lock file with
/// owner-only permissions (0o600 on Unix). The handle returned can be
/// passed to `fs2::FileExt::lock_exclusive` to serialize concurrent
/// v1->v2 migrations of the same entry across processes/threads
/// (TS-2026-001 H3).
///
/// On Unix the mode is set at creation via `OpenOptionsExt::mode` so the
/// sentinel never has a moment of looser perms. On non-Unix platforms the
/// file inherits parent ACLs (the keystore dir is owner-scoped already).
#[cfg(unix)]
fn open_migration_lock_file(path: &Path) -> Result<fs::File, io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_migration_lock_file(path: &Path) -> Result<fs::File, io::Error> {
    fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
}

/// Atomically write `data` to `path` with owner-only (0o600) permissions on
/// Unix.
///
/// TS-2026-001 H1 + H2: the prior implementation was truncate-then-write,
/// which destroys the original file if the process crashes mid-write. For
/// the keystore that's catastrophic -- a crash during transparent v1->v2
/// migration would leave a zero-byte (or partial) key entry on disk and
/// the private key would be unrecoverable. This implementation writes to
/// a sibling tmp file in the same directory, fsyncs the bytes through to
/// the platter, then performs a POSIX-atomic same-filesystem `rename(2)`.
/// A crash before the rename leaves the original file intact; the tmp
/// file is harmless garbage that the next successful write will overwrite.
///
/// The 0o600 mode is set at file *creation* via `OpenOptionsExt::mode`
/// so there is no window in which the file exists with looser perms.
/// The prior `set_permissions` post-write call is dropped because it was
/// redundant and gave the appearance (but not the substance) of safety.
fn write_file_600(path: &Path, data: &[u8]) -> Result<(), KeyError> {
    // Place the tmp file in the same directory as the final path so the
    // rename stays on the same filesystem (cross-FS renames are not atomic
    // and degrade to copy+unlink, defeating the whole point).
    let tmp_path = path.with_extension("tmp");

    // Best-effort cleanup of any stale tmp from a prior crash before we
    // start writing. Ignored on error -- if it doesn't exist that's fine,
    // and if it can't be removed the OpenOptions call below will surface
    // the underlying error.
    let _ = fs::remove_file(&tmp_path);

    let write_result: Result<(), KeyError> = (|| {
        #[cfg(unix)]
        let open = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
        };
        #[cfg(not(unix))]
        let open = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path);

        let mut f = open?;
        f.write_all(data)?;
        // sync_all flushes both data AND metadata, so on a crash after
        // the rename, fsck/journal recovery sees the new bytes -- not a
        // ghost inode with stale content.
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        // Best-effort cleanup so the next write isn't surprised by a
        // half-written tmp. Errors here are not surfaced: the original
        // write error is what the caller needs to see.
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Atomic same-filesystem rename. On Unix this is a single
    // rename(2) syscall guaranteed by POSIX to be atomic with respect
    // to other observers. On Windows std::fs::rename is implemented
    // via MoveFileEx with MOVEFILE_REPLACE_EXISTING (atomic on NTFS,
    // best-effort elsewhere). After this returns Ok, the new bytes are
    // visible at `path` and the tmp file no longer exists.
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(KeyError::Io(e));
    }

    // fsync the parent directory so the rename's directory-entry update
    // is itself persisted. The previous code only fsynced the tmp
    // file's contents (via sync_all on the file handle) -- on ext4/xfs
    // with default mount options, the rename can return to userspace
    // before the dirent metadata has been written to the journal. A
    // power loss in that window leaves the directory entry pointing at
    // the OLD inode (or, worse, missing entirely if both old and new
    // were unlinked from the parent), even though both the data bytes
    // and the rename syscall ostensibly completed. The H1 doc-comment
    // above promised stronger durability than the code delivered;
    // fsyncing the parent dir closes that gap.
    //
    // Best-effort on Unix: a directory open + sync_all is the standard
    // pattern (see e.g. SQLite's atomic-commit, leveldb, lmdb). On
    // platforms where opening a directory for sync isn't supported, we
    // silently skip -- the rename is still atomic-with-respect-to-
    // observers, we just don't guarantee crash-durability of the
    // dirent update.
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            // Errors here are non-fatal: the rename succeeded and the
            // common case (no power loss before the next fs flush) is
            // correct. We surface a failure to open/sync the dir only
            // if the rename itself succeeded, since otherwise the
            // caller would mistake a durability hint for a write
            // failure. swallow silently rather than return.
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }

    Ok(())
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("treeship-test-{}", {
            let mut b = [0u8; 4];
            // v0.10.4 P1 audit: thread_rng acceptable here. This is a
            // test-only temp-dir suffix to avoid collisions between parallel
            // test runs. Not a cryptographic input; entropy quality irrelevant.
            rand::thread_rng().fill_bytes(&mut b);
            hex_encode(&b)
        }));
        p
    }

    fn make_store() -> (Store, PathBuf) {
        let dir = temp_dir_path();
        let store = Store::open(&dir).unwrap();
        (store, dir)
    }

    fn cleanup(dir: PathBuf) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn generate_key() {
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();
        assert!(info.id.starts_with("key_"));
        assert_eq!(info.algorithm, "ed25519");
        assert!(!info.fingerprint.is_empty());
        assert_eq!(info.public_key.len(), 32);
        cleanup(dir);
    }

    #[test]
    fn default_signer_works() {
        let (store, dir) = make_store();
        store.generate(true).unwrap();
        let signer = store.default_signer().unwrap();
        assert!(!signer.key_id().is_empty());
        let pae = crate::attestation::pae("text/plain", b"test");
        let sig = signer.sign(&pae).unwrap();
        assert_eq!(sig.len(), 64);
        cleanup(dir);
    }

    /// Regression: a keystore whose path contains a symlink must decrypt
    /// consistently no matter which path string is used to open it. Before
    /// path canonicalization in `open`, deriving the machine key from the raw
    /// path string produced different keys for the same directory (e.g. open
    /// via a symlink vs. the real path), surfacing as a misleading
    /// "MAC verification failed -- wrong machine" error on a perfectly good
    /// keystore on the same machine.
    #[cfg(unix)]
    #[test]
    fn machine_key_stable_across_symlinked_path() {
        let real = temp_dir_path();
        fs::create_dir_all(&real).unwrap();
        let link = temp_dir_path();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Mint a default key via the SYMLINK path.
        {
            let store = Store::open(&link).unwrap();
            store.generate(true).unwrap();
        }

        // Re-open via the REAL (canonical) path and decrypt. Pre-fix this
        // failed because the raw path strings ("link" vs "real") hashed to
        // different machine keys.
        let via_real = Store::open(&real).unwrap();
        via_real
            .default_signer()
            .expect("decrypt via the canonical path must succeed");

        // And via the symlink again (fresh Store, re-derives the key).
        let via_link = Store::open(&link).unwrap();
        via_link
            .default_signer()
            .expect("decrypt via the symlink path must succeed");

        fs::remove_file(&link).ok();
        cleanup(real);
    }

    /// A keystore encrypted under the RAW path key (as the pre-canonicalization
    /// code wrote it) must still open after the change -- the legacy fallback
    /// must never lock an existing user out.
    #[cfg(unix)]
    #[test]
    fn legacy_raw_path_key_still_decrypts() {
        let real = temp_dir_path();
        fs::create_dir_all(&real).unwrap();
        let link = temp_dir_path();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Simulate a pre-fix keystore: encrypt a key under the machine key
        // derived from the RAW (symlink) path, bypassing canonicalization.
        let key_id = new_key_id();
        let signer = Ed25519Signer::generate(&key_id).unwrap();
        let raw_key = derive_machine_key(&link).unwrap();
        let canon_key = derive_machine_key(&fs::canonicalize(&link).unwrap()).unwrap();
        assert_ne!(raw_key, canon_key, "symlink must change the raw path key");
        let enc = encrypt_for_disk_v2(
            &raw_key,
            key_id.as_str(),
            &signer.public_key_bytes(),
            signer.secret_bytes().as_slice(),
        )
        .unwrap();
        let entry = EncryptedEntry {
            id:               key_id.clone(),
            algorithm:        "ed25519".into(),
            created_at:       crate::statements::unix_to_rfc3339(unix_now()),
            public_key:       signer.public_key_bytes(),
            enc_priv_key:     enc,
            nonce:            Vec::new(),
            valid_until:      None,
            successor_key_id: None,
        };

        // The store opened via the symlink has the canonical key as primary and
        // the raw-path key as the legacy fallback. The entry above is encrypted
        // under the raw key, so decryption must fall back rather than fail.
        let store = Store::open(&link).unwrap();
        store.write_entry(&entry).unwrap();
        let got = store
            .signer(key_id.as_str())
            .expect("legacy raw-path key must decrypt via the fallback");
        assert_eq!(got.public_key_bytes(), signer.public_key_bytes());

        fs::remove_file(&link).ok();
        cleanup(real);
    }

    /// A keystore wrapped under the v1 hostname+username machine key (every
    /// keystore written before the stable-primary change) must decrypt via
    /// the fallback chain AND be transparently rewrapped under the primary,
    /// so a later hostname rename can no longer brick it. This is the
    /// migration path for the recurring real-world failure where macOS
    /// renames `kern.hostname` (network collision, DHCP) and the keystore
    /// dies with "MAC verification failed -- wrong machine".
    #[test]
    fn v1_wrapped_keystore_decrypts_and_rewraps_under_primary() {
        let dir = temp_dir_path();
        fs::create_dir_all(&dir).unwrap();
        let canonical = fs::canonicalize(&dir).unwrap();

        // Only meaningful where a hardware-stable primary exists; on
        // machines without machine-id/serial the primary IS the v1 key
        // and there is nothing to migrate.
        let Some(primary) = stable_hardware_key(&canonical) else {
            cleanup(dir);
            return;
        };
        let v1_key = derive_machine_key(&canonical).unwrap();
        assert_ne!(primary, v1_key, "stable and v1 derivations must differ");

        // Simulate the pre-fix keystore: entry wrapped under the v1 key.
        let key_id = new_key_id();
        let signer = Ed25519Signer::generate(&key_id).unwrap();
        let enc = encrypt_for_disk_v2(
            &v1_key,
            key_id.as_str(),
            &signer.public_key_bytes(),
            signer.secret_bytes().as_slice(),
        )
        .unwrap();
        let entry = EncryptedEntry {
            id:               key_id.clone(),
            algorithm:        "ed25519".into(),
            created_at:       crate::statements::unix_to_rfc3339(unix_now()),
            public_key:       signer.public_key_bytes(),
            enc_priv_key:     enc,
            nonce:            Vec::new(),
            valid_until:      None,
            successor_key_id: None,
        };

        let store = Store::open(&dir).unwrap();
        store.write_entry(&entry).unwrap();
        let got = store
            .signer(key_id.as_str())
            .expect("v1-wrapped entry must decrypt via the fallback chain");
        assert_eq!(got.public_key_bytes(), signer.public_key_bytes());

        // The successful fallback decrypt must have rewrapped the on-disk
        // entry under the PRIMARY key: after migration the entry decrypts
        // with the primary directly and no longer with the old v1 key.
        let migrated = store.read_entry(key_id.as_str()).unwrap();
        assert!(
            decrypt_from_disk(
                &primary,
                &migrated.id,
                &migrated.public_key,
                &migrated.enc_priv_key,
                &migrated.nonce,
            )
            .is_ok(),
            "entry must be rewrapped under the primary machine key"
        );
        assert!(
            decrypt_from_disk(
                &v1_key,
                &migrated.id,
                &migrated.public_key,
                &migrated.enc_priv_key,
                &migrated.nonce,
            )
            .is_err(),
            "rewrapped entry must no longer decrypt under the old v1 key"
        );

        cleanup(dir);
    }

    /// A keystore wrapped under a v1 key derived from the mDNS
    /// LocalHostName (the hostname the machine reported before macOS
    /// renamed `kern.hostname` away from it) must decrypt via the
    /// LocalHostName fallback candidates. This is the exact drift shape
    /// that repeatedly bricked real keystores.
    #[cfg(target_os = "macos")]
    #[test]
    fn local_hostname_variant_recovers_drifted_keystore() {
        let variants = local_hostname_variants();
        let Some(old_hostname) = variants.first() else {
            // No LocalHostName on this machine; nothing to test.
            return;
        };
        let Ok(user) = std::env::var("USER") else {
            return;
        };

        let dir = temp_dir_path();
        fs::create_dir_all(&dir).unwrap();
        let canonical = fs::canonicalize(&dir).unwrap();

        let drifted_key =
            derive_machine_key_v1_from_parts(old_hostname, &user, &canonical);

        let key_id = new_key_id();
        let signer = Ed25519Signer::generate(&key_id).unwrap();
        let enc = encrypt_for_disk_v2(
            &drifted_key,
            key_id.as_str(),
            &signer.public_key_bytes(),
            signer.secret_bytes().as_slice(),
        )
        .unwrap();
        let entry = EncryptedEntry {
            id:               key_id.clone(),
            algorithm:        "ed25519".into(),
            created_at:       crate::statements::unix_to_rfc3339(unix_now()),
            public_key:       signer.public_key_bytes(),
            enc_priv_key:     enc,
            nonce:            Vec::new(),
            valid_until:      None,
            successor_key_id: None,
        };

        let store = Store::open(&dir).unwrap();
        store.write_entry(&entry).unwrap();
        let got = store.signer(key_id.as_str()).expect(
            "keystore wrapped under the LocalHostName-derived v1 key must \
             decrypt via the drift-recovery candidates",
        );
        assert_eq!(got.public_key_bytes(), signer.public_key_bytes());

        cleanup(dir);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        // Routes the legacy public API through the dispatcher; v1
        // ciphertexts must still decrypt correctly.
        let key = [42u8; 32];
        let plaintext = b"super secret private key material here!";
        let (enc, nonce) = aes_gcm_encrypt(&key, plaintext).unwrap();
        let dec = aes_gcm_decrypt(&key, &enc, &nonce).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key   = [42u8; 32];
        let wrong = [99u8; 32];
        let (enc, nonce) = aes_gcm_encrypt(&key, b"secret").unwrap();
        assert!(aes_gcm_decrypt(&wrong, &enc, &nonce).is_err());
    }

    // --- v2 AEAD tests (TS-2026-001 fix) -----------------------------------

    // Fixed entry id + pubkey for the unit-level v2 tests below. The AAD
    // builder binds these into the GCM tag, so encrypt and decrypt must
    // see identical values. Using constants keeps each test focused on
    // its own bit-flip / tamper assertion without dragging Store setup
    // into the picture.
    const TEST_ENTRY_ID: &str = "key_unit_test_entry_0001";
    const TEST_PUBLIC_KEY: &[u8; 32] = &[0xAA; 32];

    #[test]
    fn v2_encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let plaintext = b"super secret private key material here!";
        let blob =
            encrypt_for_disk_v2(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, plaintext).unwrap();
        // Structural check on the framing.
        assert_eq!(blob[0], KEYSTORE_MAGIC, "magic byte");
        assert_eq!(blob[1], KEYSTORE_VERSION_V2, "version byte");
        assert_eq!(blob.len(), 2 + 12 + plaintext.len() + 16,
                   "magic+version+nonce+ct+tag length");

        let dec =
            decrypt_from_disk(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, &blob, &[]).unwrap();
        assert_eq!(&*dec, plaintext);
    }

    #[test]
    fn v2_decrypt_wrong_key_fails() {
        let key   = [7u8; 32];
        let wrong = [99u8; 32];
        let blob = encrypt_for_disk_v2(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, b"secret").unwrap();
        // Wrong key with v2 framing: AEAD must reject. Dispatcher will
        // try v1 fallback (which also fails on garbage), so the final
        // error surfaces as a MAC failure rather than wrong plaintext.
        let result = decrypt_from_disk(&wrong, TEST_ENTRY_ID, TEST_PUBLIC_KEY, &blob, &[]);
        assert!(result.is_err(), "wrong key must fail");
    }

    #[test]
    fn v2_tamper_ciphertext_fails() {
        let key = [7u8; 32];
        let mut blob = encrypt_for_disk_v2(
            &key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, b"super secret private key"
        ).unwrap();
        // Flip one bit inside the ciphertext body (after the 14-byte
        // framing). GCM authenticates ciphertext + nonce; any flip must
        // fail.
        let last = blob.len() - 5;
        blob[last] ^= 0x01;
        let result = decrypt_from_disk(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, &blob, &[]);
        assert!(result.is_err(), "tampered ciphertext must fail to decrypt");
    }

    #[test]
    fn v2_tamper_nonce_fails() {
        let key = [7u8; 32];
        let mut blob = encrypt_for_disk_v2(
            &key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, b"super secret private key"
        ).unwrap();
        // Flip a bit in the nonce (bytes [2..14]).
        blob[5] ^= 0x01;
        let result = decrypt_from_disk(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, &blob, &[]);
        assert!(result.is_err(), "tampered nonce must fail to decrypt");
    }

    #[test]
    fn v2_tamper_tag_fails() {
        let key = [7u8; 32];
        let mut blob = encrypt_for_disk_v2(
            &key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, b"super secret private key"
        ).unwrap();
        // Flip a bit in the trailing GCM tag (last 16 bytes).
        let len = blob.len();
        blob[len - 1] ^= 0x80;
        let result = decrypt_from_disk(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, &blob, &[]);
        assert!(result.is_err(), "tampered GCM tag must fail to decrypt");
    }

    #[test]
    fn v2_nonces_are_unique_across_writes() {
        // Sanity check: two encryptions of identical plaintext under the
        // same key must produce different blobs (random per-write nonce).
        // Without this property, AES-GCM is catastrophically broken.
        let key = [7u8; 32];
        let blob_a =
            encrypt_for_disk_v2(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, b"identical").unwrap();
        let blob_b =
            encrypt_for_disk_v2(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, b"identical").unwrap();
        assert_ne!(blob_a, blob_b,
                   "two v2 encryptions of the same plaintext must differ");
        assert_ne!(&blob_a[2..14], &blob_b[2..14], "nonces must differ");

        // L1 (TS-2026-001 audit): draw 10k nonces in a row and assert
        // every one is distinct. A duplicate at this volume would be a
        // strong (10k^2 / 2^96 ~ 2^-65 floor) signal that the OS CSPRNG
        // backing aead::OsRng is misbehaving on this build. Cheap, fast,
        // and catches a regression class (PRNG mis-seeding,
        // accidentally-deterministic nonce, RNG getting forked across
        // threads without re-seed) that the 2-sample check above can't.
        const N: usize = 10_000;
        let mut nonces: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::with_capacity(N);
        for _ in 0..N {
            let blob =
                encrypt_for_disk_v2(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, b"x").unwrap();
            // bytes [2..14] are the 12-byte GCM nonce.
            nonces.insert(blob[2..14].to_vec());
        }
        assert_eq!(
            nonces.len(),
            N,
            "all {} v2 nonces must be unique; collision => RNG defect",
            N
        );
    }

    #[test]
    fn v2_tamper_version_byte_fails() {
        // M2: flipping the version byte must cause decryption to fail.
        // The framing sanity check catches obvious flips immediately;
        // the AAD-binding test below covers the case where the framing
        // sanity check would otherwise pass.
        let key = [7u8; 32];
        let mut blob = encrypt_for_disk_v2(
            &key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, b"super secret private key"
        ).unwrap();
        assert_eq!(blob[1], KEYSTORE_VERSION_V2);
        blob[1] = 0xff;
        assert!(
            decrypt_v2(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, &blob).is_err(),
            "altered version byte must be rejected"
        );
    }

    #[test]
    fn v2_aad_binding_detects_framing_substitution() {
        // M2 direct check: encrypt a payload with v2 AAD, then construct
        // a blob whose framing claims to be v2 but whose ciphertext was
        // computed under a different AAD (empty). decrypt_v2 must
        // reject with MAC failure rather than returning the plaintext.
        let key = [7u8; 32];
        let plaintext = b"M2 AAD bound material";

        // Compute a v2-framed blob without supplying AAD -- mimics what
        // the *pre-M2* code would have produced. This is the exact
        // attack surface AAD closes: an old blob whose framing is v2
        // but whose tag was computed empty.
        use aes_gcm::aead::Aead;
        let key_buf: Zeroizing<[u8; 32]> = Zeroizing::new(key);
        let aead_key: &AesKey<Aes256Gcm> = AesKey::<Aes256Gcm>::from_slice(key_buf.as_slice());
        let cipher = Aes256Gcm::new(aead_key);
        let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
        let ct_no_aad = cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();

        let mut forged = Vec::with_capacity(2 + 12 + ct_no_aad.len());
        forged.push(KEYSTORE_MAGIC);
        forged.push(KEYSTORE_VERSION_V2);
        forged.extend_from_slice(nonce.as_slice());
        forged.extend_from_slice(&ct_no_aad);

        // Framing sanity passes. AAD does not. decrypt_v2 must reject.
        assert_eq!(forged[0], KEYSTORE_MAGIC);
        assert_eq!(forged[1], KEYSTORE_VERSION_V2);
        let result = decrypt_v2(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, &forged);
        assert!(result.is_err(),
                "ciphertext computed without AAD must fail to decrypt now that AAD is bound");
    }

    #[test]
    fn dispatcher_surfaces_v2_error_on_corrupted_v2_blob() {
        // M1: a v2-shaped blob whose AEAD verification fails (and
        // whose v1 fallback also fails, since the bytes are garbage
        // under both constructions) must surface the v2 MAC error, not
        // the v1 "ciphertext too short" / random-junk error. The user
        // sees a meaningful message that points at the right
        // remediation.
        let key = [7u8; 32];
        let mut blob =
            encrypt_for_disk_v2(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, b"hello").unwrap();
        // Flip a byte in the GCM tag (last 16 bytes) so the v2 AEAD
        // rejects but the framing still classifies as v2.
        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let err =
            decrypt_from_disk(&key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, &blob, &[]).unwrap_err();
        // The dispatcher should bubble the v2 error string up. v2's
        // error message contains "MAC verification failed"; v1's
        // shape on garbage data is either "ciphertext too short" or
        // a different MAC error. Match on the v2-specific tail.
        assert!(
            err.contains("MAC verification failed"),
            "dispatcher must surface the v2 MAC error on corrupted v2 blob, got: {err}"
        );
    }

    #[test]
    fn legacy_v1_ciphertext_still_decrypts_via_dispatcher() {
        // Simulates an on-disk keystore written by Treeship <= v0.10.2:
        // the dispatcher must successfully route legacy ciphertexts
        // through the v1 path so existing users are not locked out.
        let key = [13u8; 32];
        let plaintext = b"pre-v0.10.3 keystore entry";
        let (legacy_blob, legacy_nonce) =
            legacy_v1_encrypt(&key, plaintext).unwrap();

        // Sanity: legacy blob does NOT start with v2 framing.
        assert!(is_legacy_v1(&legacy_blob),
                "legacy_v1_encrypt output must classify as legacy");

        // Dispatcher must accept it. AAD inputs are irrelevant for the
        // v1 path (it doesn't use them), but the signature requires them
        // — pass the same placeholder constants used elsewhere.
        let dec = decrypt_from_disk(
            &key, TEST_ENTRY_ID, TEST_PUBLIC_KEY, &legacy_blob, &legacy_nonce,
        )
        .unwrap();
        assert_eq!(&*dec, plaintext);
    }

    #[test]
    fn store_signer_migrates_legacy_entry_to_v2() {
        // End-to-end: write a key entry with the legacy v1 ciphertext
        // (as if upgrading from v0.10.2), call `signer()`, then verify
        // the on-disk entry has been rewritten in v2 format.
        let (store, dir) = make_store();

        // Generate normally (this writes v2). Then re-encrypt the
        // secret in v1 format and overwrite the entry on disk to
        // simulate the upgrade scenario.
        let info = store.generate(true).unwrap();
        let entry_path = store.entry_path(&info.id);

        // Pull the v2 entry off disk, decrypt to recover the secret,
        // then re-encode in legacy v1 format and write it back.
        let v2_entry: EncryptedEntry =
            serde_json::from_slice(&fs::read(&entry_path).unwrap()).unwrap();
        let secret = decrypt_from_disk(
            &store.machine_key,
            &v2_entry.id,
            &v2_entry.public_key,
            &v2_entry.enc_priv_key,
            &v2_entry.nonce,
        )
            .unwrap();
        let (legacy_blob, legacy_nonce) =
            legacy_v1_encrypt(&store.machine_key, &secret).unwrap();
        let legacy_entry = EncryptedEntry {
            id:               v2_entry.id.clone(),
            algorithm:        v2_entry.algorithm.clone(),
            created_at:       v2_entry.created_at.clone(),
            public_key:       v2_entry.public_key.clone(),
            enc_priv_key:     legacy_blob,
            nonce:            legacy_nonce,
            valid_until:      v2_entry.valid_until.clone(),
            successor_key_id: v2_entry.successor_key_id.clone(),
        };
        fs::write(&entry_path, serde_json::to_vec_pretty(&legacy_entry).unwrap()).unwrap();

        // Reload with a fresh Store so the cache doesn't paper over the
        // on-disk change.
        let store2 = Store::open(&dir).unwrap();
        // Loading the signer must succeed (legacy path works) AND
        // trigger the transparent migration to v2.
        let _signer = store2.signer(&info.id).unwrap();

        let after: EncryptedEntry =
            serde_json::from_slice(&fs::read(&entry_path).unwrap()).unwrap();
        assert!(!is_legacy_v1(&after.enc_priv_key),
                "post-migration entry must be in v2 format");
        assert_eq!(after.enc_priv_key[0], KEYSTORE_MAGIC);
        assert_eq!(after.enc_priv_key[1], KEYSTORE_VERSION_V2);
        assert!(after.nonce.is_empty(),
                "v2 entries serialize an empty legacy nonce field");

        // L2 (TS-2026-001 audit): the framing check above proves the
        // migrator *wrote* a v2-shaped blob, but a downstream
        // assert_eq! on framing alone doesn't prove the v2 ciphertext
        // is actually a working AEAD encryption of the right secret.
        // Load the signer one more time through a fresh Store; this
        // routes through the dispatcher's v2-first branch and would
        // fail loudly if the migration had produced garbage.
        let store3 = Store::open(&dir).unwrap();
        let _signer = store3
            .signer(&info.id)
            .expect("post-migration v2 decrypt works");

        cleanup(dir);
    }

    #[test]
    fn persist_and_reload() {
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();

        // Open a new Store instance pointing to the same directory.
        let store2 = Store::open(&dir).unwrap();
        let signer = store2.signer(&info.id).unwrap();
        assert_eq!(signer.key_id(), info.id);

        // The reloaded signer must produce signatures verifiable with
        // the same public key.
        let verifier = {
            use crate::attestation::Verifier;
            use ed25519_dalek::VerifyingKey;
            let pk_bytes: [u8; 32] = info.public_key.try_into().unwrap();
            let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
            let mut v = Verifier::new(std::collections::HashMap::new());
            v.add_key(info.id.clone(), vk);
            v
        };

        use crate::attestation::sign;
        use crate::statements::ActionStatement;
        let stmt   = ActionStatement::new("agent://test", "tool.call");
        let pt     = crate::statements::payload_type("action");
        let signed = sign(&pt, &stmt, signer.as_ref()).unwrap();
        verifier.verify(&signed.envelope).unwrap();

        cleanup(dir);
    }

    #[test]
    fn list_keys() {
        let (store, dir) = make_store();
        store.generate(true).unwrap();
        store.generate(false).unwrap();

        let keys = store.list().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.iter().filter(|k| k.is_default).count(), 1);
        cleanup(dir);
    }

    #[test]
    fn no_default_key_errors() {
        let (store, dir) = make_store();
        assert!(store.default_signer().is_err());
        cleanup(dir);
    }

    #[test]
    fn rotate_mints_successor_and_links_predecessor() {
        let (store, dir) = make_store();
        let pred = store.generate(true).unwrap();
        assert!(pred.valid_until.is_none(), "fresh key has no expiry");
        assert!(pred.successor_key_id.is_none(), "fresh key has no successor");

        let result = store
            .rotate(None, std::time::Duration::from_secs(3600), true)
            .unwrap();

        // Predecessor metadata is updated.
        assert_eq!(result.predecessor.id, pred.id);
        assert!(result.predecessor.valid_until.is_some(),
                "predecessor must get valid_until after rotation");
        assert_eq!(result.predecessor.successor_key_id.as_deref(),
                   Some(result.successor.id.as_str()),
                   "predecessor must link forward to successor");
        assert!(!result.predecessor.is_default,
                "after rotation with set_default=true, predecessor is no longer default");

        // Successor is fresh.
        assert_ne!(result.successor.id, pred.id);
        assert!(result.successor.valid_until.is_none(), "successor has no expiry yet");
        assert!(result.successor.successor_key_id.is_none(), "successor is chain head");
        assert!(result.successor.is_default, "successor is the new default");

        // Same metadata visible via list().
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 2);
        let pred_listed = listed.iter().find(|k| k.id == pred.id).unwrap();
        assert!(pred_listed.valid_until.is_some());
        assert_eq!(pred_listed.successor_key_id.as_deref(),
                   Some(result.successor.id.as_str()));

        cleanup(dir);
    }

    #[test]
    fn rotate_with_set_default_false_keeps_predecessor_active() {
        let (store, dir) = make_store();
        let pred = store.generate(true).unwrap();

        let result = store
            .rotate(None, std::time::Duration::from_secs(3600), false)
            .unwrap();

        // Predecessor is still default. Successor exists but is not default.
        assert!(result.predecessor.is_default);
        assert!(!result.successor.is_default);
        assert_eq!(store.default_key_id().unwrap(), pred.id);

        cleanup(dir);
    }

    #[test]
    fn rotate_predecessor_signing_still_works_during_grace_window() {
        let (store, dir) = make_store();
        let pred = store.generate(true).unwrap();
        let _ = store
            .rotate(None, std::time::Duration::from_secs(3600), true)
            .unwrap();

        // Predecessor key must still be loadable and capable of signing
        // during its grace window. Verifiers can refuse on lifecycle, but
        // the keystore must not preemptively destroy material.
        let signer = store.signer(&pred.id).unwrap();
        let pae = crate::attestation::pae("text/plain", b"grace-window-payload");
        let sig = signer.sign(&pae).unwrap();
        assert_eq!(sig.len(), 64);

        cleanup(dir);
    }

    #[test]
    fn rotate_refuses_to_rotate_already_rotated_key() {
        let (store, dir) = make_store();
        store.generate(true).unwrap();
        let r1 = store
            .rotate(None, std::time::Duration::from_secs(60), true)
            .unwrap();

        // Rotating the predecessor again must be refused -- it already
        // points at r1.successor. Caller should rotate the chain head.
        let err = store
            .rotate(Some(&r1.predecessor.id),
                    std::time::Duration::from_secs(60),
                    true)
            .unwrap_err();
        match err {
            KeyError::Crypto(msg) => assert!(
                msg.contains("already been rotated"),
                "error must explain why: {msg}"
            ),
            other => panic!("expected Crypto error, got {other:?}"),
        }
        cleanup(dir);
    }

    #[test]
    fn successor_chain_walks_forward() {
        let (store, dir) = make_store();
        let k0 = store.generate(true).unwrap();
        let r1 = store
            .rotate(None, std::time::Duration::from_secs(60), true)
            .unwrap();
        let r2 = store
            .rotate(None, std::time::Duration::from_secs(60), true)
            .unwrap();

        let chain = store.successor_chain(&k0.id).unwrap();
        assert_eq!(chain, vec![k0.id.clone(), r1.successor.id.clone(), r2.successor.id.clone()],
                   "chain must be ordered head -> tail");

        // Mid-chain start: chain from r1.successor should drop k0.
        let mid = store.successor_chain(&r1.successor.id).unwrap();
        assert_eq!(mid, vec![r1.successor.id.clone(), r2.successor.id.clone()]);

        // Tail: just itself.
        let tail = store.successor_chain(&r2.successor.id).unwrap();
        assert_eq!(tail, vec![r2.successor.id.clone()]);

        cleanup(dir);
    }

    #[test]
    fn valid_keys_at_filters_by_grace_window() {
        let (store, dir) = make_store();
        let _ = store.generate(true).unwrap();
        let result = store
            .rotate(None, std::time::Duration::from_secs(3600), true)
            .unwrap();

        // At time-of-rotation, both keys must be valid -- predecessor is
        // mid-grace, successor is freshly minted.
        let now = unix_now();
        let valid_now = store.valid_keys_at(now).unwrap();
        assert_eq!(valid_now.len(), 2, "both predecessor (in grace) and successor should be valid");

        // After the grace window expires, only the successor remains.
        let after_grace = unix_now() + 7200;
        let valid_after = store.valid_keys_at(after_grace).unwrap();
        assert_eq!(valid_after.len(), 1,
                   "after grace window only successor remains valid");
        assert_eq!(valid_after[0].id, result.successor.id);

        cleanup(dir);
    }

    /// Regression: if the successor key file is missing on disk (because a
    /// prior rotate() crashed AFTER stamping the predecessor but BEFORE
    /// writing the successor), retrying must NOT be wedged. With the
    /// successor-first write order this scenario can't be reached by a
    /// single-process crash, but we still need to defend against an operator
    /// who manually deletes a successor file mid-life. The recovery path
    /// is: clear the predecessor's successor pointer (or restore the file
    /// from backup) and try again.
    /// Regression: even if the manifest write FAILED (say, disk full at
    /// the worst possible moment), the in-memory cache must reflect the
    /// stamped predecessor that already landed on disk -- otherwise a
    /// same-process retry would skip the already-rotated guard and mint
    /// a duplicate successor.
    ///
    /// We can't easily inject a manifest-write failure mid-test, but we
    /// can verify the precondition that makes the recovery work: after a
    /// successful rotate(), the cache holds the stamped predecessor (so
    /// any subsequent rotate would correctly refuse). Combined with the
    /// write order (cache update BEFORE manifest write in rotate()),
    /// this proves a manifest-write crash leaves the cache aligned with
    /// disk, not behind it.
    #[test]
    fn rotate_cache_reflects_stamped_predecessor_for_retry_safety() {
        let (store, dir) = make_store();
        let pred = store.generate(true).unwrap();
        let _ = store
            .rotate(None, std::time::Duration::from_secs(60), true)
            .unwrap();

        // The cache must have the stamped predecessor; a same-process
        // retry of rotate(predecessor) MUST be refused. If the cache
        // were stale (still showing the unstamped predecessor), this
        // call would proceed and mint a duplicate successor.
        let err = store
            .rotate(Some(&pred.id),
                    std::time::Duration::from_secs(60),
                    true)
            .unwrap_err();
        match err {
            KeyError::Crypto(msg) => assert!(
                msg.contains("already been rotated"),
                "cache should reflect stamped predecessor; got: {msg}"
            ),
            other => panic!("expected Crypto error, got {other:?}"),
        }

        cleanup(dir);
    }

    #[test]
    fn rotated_predecessor_pointing_at_missing_successor_surfaces_clear_error() {
        let (store, dir) = make_store();
        store.generate(true).unwrap();
        let result = store
            .rotate(None, std::time::Duration::from_secs(60), true)
            .unwrap();

        // Simulate operator-deleted successor file. The manifest still
        // references it, so a cold-cache reader trying to walk the chain
        // hits a clear NotFound for the missing key.
        let succ_path = store.entry_path(&result.successor.id);
        fs::remove_file(&succ_path).unwrap();

        // Open a fresh Store instance so the cache doesn't paper over the
        // missing on-disk entry. successor_chain() walks via load_entry;
        // the missing file must produce KeyError::NotFound, not a panic
        // and not an infinite loop.
        let store2 = Store::open(&dir).unwrap();
        let err = store2.successor_chain(&result.predecessor.id).unwrap_err();
        match err {
            KeyError::NotFound(id) => assert_eq!(id, result.successor.id),
            other => panic!("expected NotFound error, got {other:?}"),
        }

        cleanup(dir);
    }

    /// Pre-0.9.5 entry files lack `valid_until` and `successor_key_id`.
    /// They must still deserialize cleanly and be visible via `list()` /
    /// `default_signer()` etc.
    #[test]
    fn legacy_entry_without_lifecycle_fields_loads() {
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();

        // Re-serialize the on-disk entry without the new fields, simulating
        // a file created by a 0.9.4 or earlier CLI.
        let path = store.entry_path(&info.id);
        let raw  = fs::read(&path).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let obj = json.as_object_mut().unwrap();
        obj.remove("valid_until");
        obj.remove("successor_key_id");
        fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        // A fresh Store (cold cache) must still load the entry and treat
        // the missing fields as None.
        let store2 = Store::open(&dir).unwrap();
        let listed = store2.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].valid_until.is_none(),
                "missing valid_until must default to None on legacy entry");
        assert!(listed[0].successor_key_id.is_none(),
                "missing successor_key_id must default to None on legacy entry");
        let signer = store2.default_signer().unwrap();
        assert_eq!(signer.key_id(), info.id);

        cleanup(dir);
    }

    // --- keystore permission hardening (PR 1) -------------------------------

    // The perm tests below mutate the process-global env var
    // TREESHIP_ALLOW_INSECURE_KEY_PERMS. cargo test runs cases in
    // parallel by default, so without serialization one test can set
    // the bypass while another expects it unset and racefully fail.
    // This mutex serializes them; everything else in the file remains
    // parallel-safe.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    #[cfg(unix)]
    fn write_entry_creates_file_with_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();
        let mode = fs::metadata(store.entry_path(&info.id))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "freshly written key file must be 0600, got {:o}", mode);
        cleanup(dir);
    }

    #[test]
    #[cfg(unix)]
    fn signer_refuses_world_readable_key() {
        use std::os::unix::fs::PermissionsExt;
        // Mutex prevents the bypass var from being toggled by a
        // sibling test mid-flight (cargo test parallel runner).
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Make sure the bypass var is not leaking from the host env.
        std::env::remove_var("TREESHIP_ALLOW_INSECURE_KEY_PERMS");

        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();

        // Loosen perms on the key file -- simulates a checkout, scp, or
        // shared-volume mishap.
        let path = store.entry_path(&info.id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        match store.signer(&info.id) {
            Err(KeyError::InsecureKeyPerms { path: p, mode }) => {
                assert_eq!(p, path);
                assert_eq!(mode & 0o777, 0o644);
            }
            other => panic!("expected InsecureKeyPerms, got {:?}", other.map(|_| "ok")),
        }
        cleanup(dir);
    }

    #[test]
    #[cfg(unix)]
    fn signer_bypass_via_env_var() {
        use std::os::unix::fs::PermissionsExt;
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();
        let path = store.entry_path(&info.id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        std::env::set_var("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1");
        let result = store.signer(&info.id);
        std::env::remove_var("TREESHIP_ALLOW_INSECURE_KEY_PERMS");

        assert!(
            result.is_ok(),
            "bypass env var must allow signing: {:?}",
            result.err()
        );
        cleanup(dir);
    }

    // --- v0.10.4 P2: TOCTOU window in signer() perm-check ---------------

    /// Structural / single-open proof: the on-disk key file is opened
    /// EXACTLY ONCE during `signer()`. The fix replaces the prior
    /// `check_key_file_perms(path) + load_entry(id) -> fs::read(path)`
    /// two-open shape with `read_entry_with_perm_check`, which opens
    /// once and fstat's the resulting fd. We can't reliably race the
    /// FS in a unit test, so instead we assert the structural
    /// invariant: after `signer()` succeeds, only the bytes that the
    /// open file descriptor saw at perm-check time can have been read.
    ///
    /// The simulation: stage an attacker-controlled "loose perms"
    /// envelope at the path, then call `signer()`. With the fixed
    /// single-open shape, perm-check on the open fd fails before any
    /// content is read -- we get `InsecureKeyPerms`, not a successful
    /// signer. The legacy two-open code would have observed the perm
    /// failure on the same loose file too, but the property we are
    /// pinning here is that the perm rejection comes from the SAME fd
    /// the read would have used (no chance for an intermediate swap).
    #[test]
    #[cfg(unix)]
    fn signer_rejects_post_check_swap() {
        use std::os::unix::fs::PermissionsExt;
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("TREESHIP_ALLOW_INSECURE_KEY_PERMS");

        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();
        let path = store.entry_path(&info.id);

        // Snapshot the legit (0o600) v2 ciphertext bytes so we can
        // confirm that even if an attacker were to swap THIS exact
        // content under a loose-perms file, the single-open gate
        // catches it on the fd.
        let original_bytes = fs::read(&path).unwrap();
        assert!(!original_bytes.is_empty(), "test sanity");

        // Stage the swapped file: same envelope content (so the JSON
        // parses and AEAD would succeed if we got that far), but
        // loose perms. With the old two-open shape, an attacker could
        // present 0o600 to perm-check, then race in this 0o644
        // version before the read; with the new single-open shape,
        // we open once, fstat the fd, and reject before reading.
        fs::write(&path, &original_bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        match store.signer(&info.id) {
            Err(KeyError::InsecureKeyPerms { path: p, mode }) => {
                assert_eq!(p, path);
                assert_eq!(mode & 0o777, 0o644);
            }
            Err(other) => panic!(
                "expected InsecureKeyPerms from single-open fstat gate, got {:?}",
                other
            ),
            Ok(_) => panic!(
                "expected InsecureKeyPerms from single-open fstat gate, got ok signer"
            ),
        }

        // The "structural" half of the test: invoke the helper
        // directly. It must reject on the open fd, never returning
        // an `EncryptedEntry`. This pins the no-second-open property
        // -- if a future refactor reintroduces a path-based read
        // after the perm gate, this assertion still holds (the gate
        // would still trip on the same loose fd) but the code review
        // diff is the real test for the structural invariant.
        let direct = store.read_entry_with_perm_check(&info.id);
        assert!(
            matches!(direct, Err(KeyError::InsecureKeyPerms { .. })),
            "read_entry_with_perm_check must reject before reading bytes; got {:?}",
            direct.map(|_| "ok")
        );

        cleanup(dir);
    }

    // --- TS-2026-001 H3 migration-lock concurrency test -----------------

    /// H3: two threads calling `Store::signer` on the same legacy v1
    /// entry must both succeed, the on-disk entry must end up as a
    /// valid v2 entry (decryptable via the v2 path), and no `.tmp`
    /// fragment must be left in the keystore directory.
    ///
    /// Without the advisory lock around `migrate_entry_to_v2`, two
    /// concurrent migrators would race the read-modify-rename cycle:
    /// the loser's rename would clobber the winner's v2 entry with
    /// its own (also-valid) v2 entry, but in between the two
    /// renames a third reader could observe a v2 entry, decrypt
    /// successfully, then have its in-memory state invalidated by
    /// the second writer. The flock turns the race into a queue --
    /// both writers produce identical v2 plaintext, only one rename
    /// per entry is actually needed, and the second writer's
    /// post-lock recheck observes the v2 state and exits cleanly.
    #[test]
    fn concurrent_migration_serializes_correctly() {
        use std::sync::Arc;
        use std::thread;

        // Set up a legacy v1 entry on disk -- same shape as the
        // store_signer_migrates_legacy_entry_to_v2 test, just shared
        // with two threads.
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();
        let entry_path = store.entry_path(&info.id);

        let v2_entry: EncryptedEntry =
            serde_json::from_slice(&fs::read(&entry_path).unwrap()).unwrap();
        let secret = decrypt_from_disk(
            &store.machine_key,
            &v2_entry.id,
            &v2_entry.public_key,
            &v2_entry.enc_priv_key,
            &v2_entry.nonce,
        )
            .unwrap();
        let (legacy_blob, legacy_nonce) =
            legacy_v1_encrypt(&store.machine_key, &secret).unwrap();
        let legacy_entry = EncryptedEntry {
            id:               v2_entry.id.clone(),
            algorithm:        v2_entry.algorithm.clone(),
            created_at:       v2_entry.created_at.clone(),
            public_key:       v2_entry.public_key.clone(),
            enc_priv_key:     legacy_blob,
            nonce:            legacy_nonce,
            valid_until:      v2_entry.valid_until.clone(),
            successor_key_id: v2_entry.successor_key_id.clone(),
        };
        fs::write(&entry_path, serde_json::to_vec_pretty(&legacy_entry).unwrap()).unwrap();

        // Two independent Store instances racing on the same on-disk
        // legacy entry. Using independent Store instances forces the
        // lock-on-disk path to engage (a shared Store would serialize
        // through the internal RwLock cache and we'd be testing the
        // wrong thing).
        let dir_a = Arc::new(dir.clone());
        let dir_b = Arc::new(dir.clone());
        let id_a = info.id.clone();
        let id_b = info.id.clone();

        let h1 = thread::spawn(move || -> Result<(), String> {
            let s = Store::open(&*dir_a).map_err(|e| e.to_string())?;
            let _signer = s.signer(&id_a).map_err(|e| e.to_string())?;
            Ok(())
        });
        let h2 = thread::spawn(move || -> Result<(), String> {
            let s = Store::open(&*dir_b).map_err(|e| e.to_string())?;
            let _signer = s.signer(&id_b).map_err(|e| e.to_string())?;
            Ok(())
        });

        h1.join().unwrap().expect("thread 1 signer load must succeed");
        h2.join().unwrap().expect("thread 2 signer load must succeed");

        // Post-condition: on-disk entry is v2 framed.
        let after: EncryptedEntry =
            serde_json::from_slice(&fs::read(&entry_path).unwrap()).unwrap();
        assert!(
            !is_legacy_v1(&after.enc_priv_key),
            "post-concurrent-migration entry must be in v2 format"
        );
        assert_eq!(after.enc_priv_key[0], KEYSTORE_MAGIC);
        assert_eq!(after.enc_priv_key[1], KEYSTORE_VERSION_V2);

        // v2 decrypts cleanly. Use the post-migration entry's own id +
        // pubkey — the migration must have re-encrypted with those bound
        // into the AAD, or this assertion would surface a MAC failure.
        let dec = decrypt_v2(
            &store.machine_key,
            &after.id,
            &after.public_key,
            &after.enc_priv_key,
        )
            .expect("v2 entry must decrypt cleanly after concurrent migration");
        assert_eq!(dec.len(), 32, "decrypted secret must be a 32-byte ed25519 scalar");

        // No stale .tmp file left behind.
        for entry in fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            assert!(
                p.extension().is_none_or(|e| e != "tmp"),
                "no .tmp fragment must remain after migration, found: {}",
                p.display()
            );
        }

        cleanup(dir);
    }

    // --- TS-2026-001 H1 + H2 atomic write tests ------------------------

    /// H1: a partial failure between writing the tmp file and renaming
    /// it into place MUST leave the original on-disk file intact. We
    /// simulate the failure by pre-creating a tmp file (so the next
    /// write_file_600 would clobber it) and then independently verifying
    /// that an already-written key entry remains decryptable even after
    /// a fresh write_file_600 fails partway.
    ///
    /// We exercise the failure path by pointing the rename at an
    /// unwritable target. On Unix we make the *parent directory*
    /// read-only after the original key is in place, which causes the
    /// final fs::rename to fail with EACCES. The original key file is
    /// unaffected because rename(2) returns before touching the target.
    #[test]
    #[cfg(unix)]
    fn atomic_write_leaves_original_intact_on_partial_failure() {
        use std::os::unix::fs::PermissionsExt;
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();
        let entry_path = store.entry_path(&info.id);

        // Capture the original bytes for byte-identity comparison.
        let original = fs::read(&entry_path).expect("entry file must exist");
        assert!(!original.is_empty(), "freshly generated entry must be non-empty");

        // Lock the directory: read+execute only, no write. fs::rename
        // into this directory will fail.
        let orig_dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();

        // Attempt a fresh write to the SAME path -- must fail because
        // the directory is read-only, exercising the rename-failure
        // branch.
        let res = write_file_600(&entry_path, b"new junk that must not land");
        assert!(res.is_err(), "write_file_600 must fail when dir is read-only");

        // Restore perms so we can read back the entry.
        fs::set_permissions(&dir, fs::Permissions::from_mode(orig_dir_mode)).unwrap();

        // The original key file must be byte-identical to what we
        // captured before the failed write.
        let after = fs::read(&entry_path).expect("entry file must still exist after failed write");
        assert_eq!(
            after, original,
            "failed atomic write must not corrupt the original file",
        );

        // And the keystore must still produce a working signer from it.
        let store2 = Store::open(&dir).unwrap();
        let signer = store2
            .signer(&info.id)
            .expect("original key must still decrypt after a failed write");
        let pae = crate::attestation::pae("text/plain", b"survive");
        assert_eq!(signer.sign(&pae).unwrap().len(), 64);

        // No stale tmp file left behind.
        let tmp = entry_path.with_extension("tmp");
        assert!(!tmp.exists(), "tmp file must be cleaned up after rename failure");

        cleanup(dir);
    }

    /// H2: the entry file's mode is 0o600 at the moment of creation, set
    /// via OpenOptionsExt::mode rather than a post-write set_permissions
    /// (which had a tiny window of looser perms). Also confirms the tmp
    /// file is removed by the rename.
    #[test]
    #[cfg(unix)]
    fn mode_is_600_at_creation() {
        use std::os::unix::fs::PermissionsExt;
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();
        let entry_path = store.entry_path(&info.id);

        let mode = fs::metadata(&entry_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "entry file must be 0600 at creation, got {:o}", mode);

        let tmp = entry_path.with_extension("tmp");
        assert!(
            !tmp.exists(),
            "no .tmp file must be left behind after a successful atomic write"
        );

        cleanup(dir);
    }

    #[test]
    #[cfg(unix)]
    fn fix_perms_repairs_loose_modes() {
        use std::os::unix::fs::PermissionsExt;
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();
        let key_path = store.entry_path(&info.id);

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

        let changes = store.fix_perms().unwrap();
        // dir + key file + manifest = 3 paths to fix (manifest may already be 0600
        // depending on Manifest write path; we only assert the loose ones moved).
        assert!(
            changes.iter().any(|(p, _, _)| p == &dir),
            "dir should be repaired"
        );
        assert!(
            changes.iter().any(|(p, _, _)| p == &key_path),
            "key file should be repaired"
        );

        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let key_mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(key_mode, 0o600);

        // After repair, signing must work again.
        store.signer(&info.id).expect("signing must work after fix_perms");

        cleanup(dir);
    }

    // --- TS-2026-001 post-merge fix-up: entry-binding AAD ------------------

    /// Post-merge audit fix: the v2 AAD now binds entry id + public key
    /// into the GCM tag. Without that binding, a local attacker with
    /// write access to ~/.treeship/keys/ could copy entry A's
    /// `enc_priv_key` ciphertext into entry B's JSON envelope; the
    /// decrypt would succeed (same machine key, same framing-only AAD)
    /// and the signer for advertised key id A would silently sign with
    /// key B's secret scalar.
    ///
    /// This test performs exactly that swap and asserts decryption now
    /// fails. Before the fix this test would silently pass with the
    /// wrong scalar -- a true regression guard.
    #[test]
    fn cross_entry_swap_fails_decryption() {
        let (store, dir) = make_store();

        // Two independent keys in the same store, same machine key.
        let a = store.generate(true).unwrap();
        let b = store.generate(false).unwrap();

        // Snapshot both on-disk envelopes.
        let path_a = store.entry_path(&a.id);
        let path_b = store.entry_path(&b.id);
        let entry_a: EncryptedEntry =
            serde_json::from_slice(&fs::read(&path_a).unwrap()).unwrap();
        let entry_b: EncryptedEntry =
            serde_json::from_slice(&fs::read(&path_b).unwrap()).unwrap();

        // Sanity: both are v2 framed, and the ciphertexts differ.
        assert_eq!(entry_a.enc_priv_key[0], KEYSTORE_MAGIC);
        assert_eq!(entry_a.enc_priv_key[1], KEYSTORE_VERSION_V2);
        assert_eq!(entry_b.enc_priv_key[0], KEYSTORE_MAGIC);
        assert_eq!(entry_b.enc_priv_key[1], KEYSTORE_VERSION_V2);
        assert_ne!(
            entry_a.enc_priv_key, entry_b.enc_priv_key,
            "two freshly-generated entries must have distinct ciphertexts"
        );

        // The attack: copy B's enc_priv_key into A's envelope. Leave
        // everything else (id, public_key, algorithm) as it was in A.
        // This is the file an attacker with write access to the keys
        // directory would produce.
        let mut tampered_a = entry_a.clone();
        tampered_a.enc_priv_key = entry_b.enc_priv_key.clone();
        // The v2 nonce travels inline with the ciphertext (bytes
        // [2..14] of enc_priv_key), so swapping the blob also swaps
        // the nonce; the separate JSON `nonce` field is empty for v2
        // entries either way.
        fs::write(&path_a, serde_json::to_vec_pretty(&tampered_a).unwrap()).unwrap();

        // Fresh Store so the in-memory cache doesn't paper over the
        // on-disk tamper.
        let store2 = Store::open(&dir).unwrap();
        let err = match store2.signer(&a.id) {
            Ok(_) => panic!(
                "swapping B's ciphertext into A's envelope must fail decrypt; \
                 got Ok which means the signer would silently sign with key B"
            ),
            Err(e) => e,
        };

        // The specific error must be a crypto/MAC failure, not (e.g.)
        // a NotFound or InsecureKeyPerms surface that could mask the
        // class of bug.
        match err {
            KeyError::Crypto(msg) => assert!(
                msg.contains("MAC verification failed"),
                "swap must surface MAC failure; got: {msg}"
            ),
            other => panic!("expected Crypto MAC error, got: {other:?}"),
        }

        cleanup(dir);
    }

    /// Companion to `cross_entry_swap_fails_decryption`: the id field
    /// is also bound into the AAD, so editing the JSON `id` while
    /// leaving the ciphertext alone must also fail. (An attacker who
    /// renames a stolen entry file onto a victim's id without
    /// re-encrypting would land here.)
    #[test]
    fn aad_tampered_entry_id_fails_decryption() {
        let (store, dir) = make_store();
        let info = store.generate(true).unwrap();
        let path = store.entry_path(&info.id);

        let mut entry: EncryptedEntry =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(entry.id, info.id, "sanity: id matches what generate returned");

        // Pretend the attacker forged an id. Note we write this back to
        // the SAME file path so Store::load_entry by the original id
        // finds it; if we changed the path too we'd just be testing
        // NotFound, which isn't the point.
        entry.id = "key_attacker_substituted_id".to_string();
        fs::write(&path, serde_json::to_vec_pretty(&entry).unwrap()).unwrap();

        // Fresh Store so cache doesn't paper this over. Load via the
        // tampered id (matching what's in the JSON) so we exercise the
        // decrypt path rather than a path-vs-id mismatch.
        let store2 = Store::open(&dir).unwrap();
        // Drop the cache by opening fresh; load by the on-disk id.
        // The entry_path for "key_attacker_substituted_id" doesn't
        // exist, so we deliberately call the lower-level read by
        // path-of-original and assert decrypt fails via the dispatcher.
        // Easiest: bypass entry_path and invoke decrypt_from_disk with
        // the tampered id directly.
        let key_buf = store2.machine_key;
        let result = decrypt_from_disk(
            &key_buf,
            &entry.id,          // tampered id (bound into AAD)
            &entry.public_key,  // original pubkey
            &entry.enc_priv_key,
            &entry.nonce,
        );
        assert!(
            result.is_err(),
            "AAD-bound entry id mismatch must fail decrypt; got Ok"
        );

        cleanup(dir);
    }
}
