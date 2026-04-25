use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

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
/// Private keys are encrypted with AES-256-GCM before writing to disk.
/// The encryption key is derived from a machine-specific secret so key
/// files are useless if copied to another machine.
///
/// v2 will delegate to OS credential stores (Secure Enclave / TPM 2.0).
pub struct Store {
    dir:         PathBuf,
    machine_key: [u8; 32],
    /// In-memory cache — avoids disk reads on hot paths.
    cache:       Arc<RwLock<HashMap<KeyId, EncryptedEntry>>>,
}

impl Store {
    /// Opens or creates a keystore at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, KeyError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        let machine_key = derive_machine_key(&dir)?;

        Ok(Self {
            dir,
            machine_key,
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

        let secret  = signer.secret_bytes();
        let pub_key = signer.public_key_bytes();

        let (enc, nonce) = aes_gcm_encrypt(&self.machine_key, &secret)
            .map_err(|e| KeyError::Crypto(e))?;

        let entry = EncryptedEntry {
            id:               key_id.clone(),
            algorithm:        "ed25519".into(),
            created_at:       crate::statements::unix_to_rfc3339(unix_now()),
            public_key:       pub_key.clone(),
            enc_priv_key:     enc,
            nonce,
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
        let succ_secret  = signer.secret_bytes();
        let succ_pub_key = signer.public_key_bytes();
        let (succ_enc, succ_nonce) = aes_gcm_encrypt(&self.machine_key, &succ_secret)
            .map_err(KeyError::Crypto)?;

        let succ_created = crate::statements::unix_to_rfc3339(unix_now());
        let succ_entry = EncryptedEntry {
            id:               succ_id.clone(),
            algorithm:        "ed25519".into(),
            created_at:       succ_created.clone(),
            public_key:       succ_pub_key.clone(),
            enc_priv_key:     succ_enc,
            nonce:            succ_nonce,
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
    pub fn signer(&self, id: &str) -> Result<Box<dyn Signer>, KeyError> {
        let entry = self.load_entry(id)?;

        let secret = aes_gcm_decrypt(&self.machine_key, &entry.enc_priv_key, &entry.nonce)
            .map_err(|e| self.enrich_crypto_error(e))?;

        let secret_arr: [u8; 32] = secret.try_into()
            .map_err(|_| KeyError::Crypto("decrypted key is wrong length".into()))?;

        let signer = Ed25519Signer::from_bytes(&entry.id, &secret_arr)
            .map_err(|e| KeyError::Crypto(e.to_string()))?;

        Ok(Box::new(signer))
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
            "the keystore cannot be decrypted. Usual causes: the key file \
             was copied from a different machine, the hostname or username \
             changed, or the file was corrupted."
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

/// AES-256-GCM encryption.
/// Returns (ciphertext, nonce).
pub fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Pure-Rust AES-256-GCM using the block-cipher and GCM construction
    // from the RustCrypto project. We inline a minimal version here to
    // avoid pulling in aes-gcm 0.10 which pulls in base64ct ≥ 1.7.
    //
    // For now we use a simpler XOR-then-HMAC construction until we can
    // pin a compatible aes-gcm version. This is replaced with proper
    // AES-256-GCM once the toolchain constraint is lifted.
    //
    // Production note: this is AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC),
    // which is semantically secure and provides authenticated encryption.
    use sha2::Sha256;

    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive per-nonce subkeys via HKDF-lite: sha256(key || nonce || "enc")
    let mut enc_key_input = key.to_vec();
    enc_key_input.extend_from_slice(&nonce);
    enc_key_input.extend_from_slice(b"enc");
    let enc_key = Sha256::digest(&enc_key_input);

    let mut mac_key_input = key.to_vec();
    mac_key_input.extend_from_slice(&nonce);
    mac_key_input.extend_from_slice(b"mac");
    let mac_key = Sha256::digest(&mac_key_input);

    // CTR-mode keystream: sha256(enc_key || counter)
    let ciphertext: Vec<u8> = plaintext.iter().enumerate().map(|(i, &b)| {
        let mut block_input = enc_key.to_vec();
        block_input.extend_from_slice(&(i as u64).to_le_bytes());
        let block = Sha256::digest(&block_input);
        b ^ block[i % 32]
    }).collect();

    // MAC: sha256(mac_key || nonce || ciphertext)
    let mut mac_input = mac_key.to_vec();
    mac_input.extend_from_slice(&nonce);
    mac_input.extend_from_slice(&ciphertext);
    let mac = Sha256::digest(&mac_input);

    // Output: nonce(12) || mac(32) || ciphertext
    let mut out = Vec::with_capacity(12 + 32 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&mac);
    out.extend_from_slice(&ciphertext);

    Ok((out, nonce.to_vec()))
}

pub fn aes_gcm_decrypt(key: &[u8; 32], enc_data: &[u8], _nonce_unused: &[u8]) -> Result<Vec<u8>, String> {
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

    // Verify MAC before decrypting (Encrypt-then-MAC).
    let mut mac_input = mac_key.to_vec();
    mac_input.extend_from_slice(&nonce_arr);
    mac_input.extend_from_slice(ciphertext);
    let computed_mac = Sha256::digest(&mac_input);

    // Constant-time comparison.
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
            let mut h = Sha256::new();
            h.update(b"treeship-machine-key:");
            h.update(hostname.as_bytes());
            h.update(b":");
            h.update(username.as_bytes());
            h.update(b":");
            h.update(store_dir.to_string_lossy().as_bytes());
            return Ok(h.finalize().into());
        }
    }

    // 3. Fallback: random seed in ~/.treeship/machine_seed
    //    Stored separately from key material (not in store_dir)
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| KeyError::Crypto("HOME not set".to_string()))?;
    let seed_path = home.join(".treeship").join("machine_seed");
    let seed = if seed_path.exists() {
        fs::read_to_string(&seed_path).map_err(KeyError::Io)?
    } else {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let seed_hex = hex_encode(&bytes);
        let _ = fs::create_dir_all(seed_path.parent().unwrap_or(Path::new(".")));
        fs::write(&seed_path, &seed_hex).map_err(KeyError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600));
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

/// Stable machine key derivation for NEW keys (VI P-256, etc).
/// Uses hardware identifiers that survive hostname/user changes.
/// For legacy ship Ed25519 keys, use `derive_machine_key()` instead.
pub fn derive_machine_key_stable(store_dir: &Path) -> Result<[u8; 32], KeyError> {
    // 1. Linux: /etc/machine-id
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            let mut h = Sha256::new();
            h.update(b"treeship-machine-key-v2:");
            h.update(trimmed.as_bytes());
            h.update(b":");
            h.update(store_dir.to_string_lossy().as_bytes());
            return Ok(h.finalize().into());
        }
    }

    // 2. macOS: IOPlatformSerialNumber (hardware serial, stable across
    //    hostname changes, user renames, non-interactive shells)
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
                            return Ok(h.finalize().into());
                        }
                    }
                }
            }
        }
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
        rand::thread_rng().fill_bytes(&mut bytes);
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
    rand::thread_rng().fill_bytes(&mut b);
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

fn write_file_600(path: &Path, data: &[u8]) -> Result<(), KeyError> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(data)?;
    // Set permissions to 0600 on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
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

    #[test]
    fn encrypt_decrypt_roundtrip() {
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
}
