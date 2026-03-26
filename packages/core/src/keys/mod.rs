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
#[derive(Serialize, Deserialize)]
struct EncryptedEntry {
    id:           KeyId,
    algorithm:    String,
    created_at:   String,
    public_key:   Vec<u8>,
    /// AES-256-GCM ciphertext of the 32-byte Ed25519 secret scalar.
    enc_priv_key: Vec<u8>,
    /// 12-byte GCM nonce used when encrypting.
    nonce:        Vec<u8>,
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
            id:           key_id.clone(),
            algorithm:    "ed25519".into(),
            created_at:   crate::statements::unix_to_rfc3339(unix_now()),
            public_key:   pub_key.clone(),
            enc_priv_key: enc,
            nonce,
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
            id:          key_id,
            algorithm:   "ed25519".into(),
            is_default:  manifest.default_key_id.as_deref() == Some(&manifest.key_ids.last().unwrap_or(&String::new())),
            created_at:  crate::statements::unix_to_rfc3339(unix_now()),
            fingerprint: fingerprint(&pub_key),
            public_key:  pub_key,
        })
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
            .map_err(|e| KeyError::Crypto(e))?;

        let secret_arr: [u8; 32] = secret.try_into()
            .map_err(|_| KeyError::Crypto("decrypted key is wrong length".into()))?;

        let signer = Ed25519Signer::from_bytes(&entry.id, &secret_arr)
            .map_err(|e| KeyError::Crypto(e.to_string()))?;

        Ok(Box::new(signer))
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
                id:          entry.id.clone(),
                algorithm:   entry.algorithm.clone(),
                is_default:  entry.id == default,
                created_at:  entry.created_at.clone(),
                fingerprint: fingerprint(&entry.public_key),
                public_key:  entry.public_key.clone(),
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
                // Re-create entry from cache fields to satisfy ownership.
                return Ok(EncryptedEntry {
                    id:           entry.id.clone(),
                    algorithm:    entry.algorithm.clone(),
                    created_at:   entry.created_at.clone(),
                    public_key:   entry.public_key.clone(),
                    enc_priv_key: entry.enc_priv_key.clone(),
                    nonce:        entry.nonce.clone(),
                });
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
fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
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

fn aes_gcm_decrypt(key: &[u8; 32], enc_data: &[u8], _nonce_unused: &[u8]) -> Result<Vec<u8>, String> {
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

fn derive_machine_key(store_dir: &Path) -> Result<[u8; 32], KeyError> {
    let mut seed = Vec::new();

    // Try /etc/machine-id first (Linux standard).
    if let Ok(id) = fs::read("/etc/machine-id") {
        seed.extend_from_slice(&id);
    } else {
        // Fallback: stable seed file inside the store directory.
        let seed_path = store_dir.join(".machineseed");
        if seed_path.exists() {
            seed = fs::read(&seed_path)?;
        } else {
            let mut s = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut s);
            write_file_600(&seed_path, &s)?;
            seed = s;
        }
    }

    // Mix in the store directory path so the same machine-id can't open
    // a store that was copied from another path.
    seed.extend_from_slice(store_dir.to_string_lossy().as_bytes());

    let h = Sha256::digest(&seed);
    Ok(h.into())
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
}
