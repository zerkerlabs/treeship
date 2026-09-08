//! The agent's P-256 key at rest: `<keys_dir>/vi/<kid>.json`, the private
//! scalar sealed by the ship keystore's machine key (AES-256-GCM, the same
//! construction that protects the Ed25519 keys), so a copied file is useless
//! on another machine.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::keys::Store as KeyStore;

use super::jws::{b64u, b64u_decode, AgentKey, Jwk};
use super::ViError;

const SEAL_CONTEXT_PREFIX: &str = "vi:p256:v1:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAgentKey {
    pub kid: String,
    pub created_at: String,
    pub public_jwk: Jwk,
    /// base64url of the sealed 32-byte scalar.
    pub sealed_d: String,
    #[serde(default)]
    pub label: Option<String>,
}

pub fn vi_keys_dir(keys_dir: &Path) -> PathBuf {
    keys_dir.join("vi")
}

fn key_path(keys_dir: &Path, kid: &str) -> PathBuf {
    vi_keys_dir(keys_dir).join(format!("{kid}.json"))
}

/// Seal and write `key`. Refuses to overwrite an existing kid.
pub fn save_agent_key(
    keys_dir: &Path,
    store: &KeyStore,
    key: &AgentKey,
    label: Option<&str>,
    created_at: &str,
) -> Result<PathBuf, ViError> {
    let dir = vi_keys_dir(keys_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| ViError::Key(format!("create {}: {e}", dir.display())))?;
    let path = key_path(keys_dir, &key.kid);
    if path.exists() {
        return Err(ViError::Key(format!(
            "key {} already exists at {}",
            key.kid,
            path.display()
        )));
    }
    let secret = key.secret_bytes();
    let sealed = store
        .encrypt_secret(&format!("{SEAL_CONTEXT_PREFIX}{}", key.kid), &secret)
        .map_err(|e| ViError::Key(format!("seal: {e}")))?;
    let rec = StoredAgentKey {
        kid: key.kid.clone(),
        created_at: created_at.into(),
        public_jwk: key.public_jwk(),
        sealed_d: b64u(&sealed),
        label: label.map(str::to_string),
    };
    let json = serde_json::to_string_pretty(&rec).map_err(|e| ViError::Key(e.to_string()))?;
    std::fs::write(&path, json)
        .map_err(|e| ViError::Key(format!("write {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

pub fn load_agent_key(keys_dir: &Path, store: &KeyStore, kid: &str) -> Result<AgentKey, ViError> {
    let rec = read_stored(keys_dir, kid)?;
    let sealed = b64u_decode(&rec.sealed_d)?;
    let d = store
        .decrypt_secret(&format!("{SEAL_CONTEXT_PREFIX}{kid}"), &sealed)
        .map_err(|e| ViError::Key(format!("unseal {kid}: {e}")))?;
    let key = AgentKey::from_secret(&d, kid)?;
    if key.public_jwk().x != rec.public_jwk.x || key.public_jwk().y != rec.public_jwk.y {
        return Err(ViError::Key(format!(
            "stored public key for {kid} does not match its scalar"
        )));
    }
    Ok(key)
}

pub fn read_stored(keys_dir: &Path, kid: &str) -> Result<StoredAgentKey, ViError> {
    let path = key_path(keys_dir, kid);
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| ViError::Key(format!("no VI key {kid} ({}): {e}", path.display())))?;
    serde_json::from_str(&raw).map_err(|e| ViError::Key(format!("parse {}: {e}", path.display())))
}

/// Every stored key, oldest first.
pub fn list_agent_keys(keys_dir: &Path) -> Result<Vec<StoredAgentKey>, ViError> {
    let dir = vi_keys_dir(keys_dir);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut out: Vec<StoredAgentKey> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect();
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(out)
}

/// The single key when there is exactly one, else an error naming the
/// choice the caller has to make.
pub fn default_agent_key(keys_dir: &Path) -> Result<StoredAgentKey, ViError> {
    let all = list_agent_keys(keys_dir)?;
    match all.len() {
        0 => Err(ViError::Key("no VI key; run: treeship vi keygen".into())),
        1 => Ok(all.into_iter().next().expect("one")),
        n => Err(ViError::Key(format!("{n} VI keys; pass --key <kid>"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_round_trip_and_no_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let ks_dir = tmp.path().join("keys");
        let store = KeyStore::open(&ks_dir).unwrap();
        let key = AgentKey::generate();
        let p =
            save_agent_key(&ks_dir, &store, &key, Some("test"), "2026-09-08T00:00:00Z").unwrap();
        assert!(p.exists());
        let back = load_agent_key(&ks_dir, &store, &key.kid).unwrap();
        assert_eq!(back.public_jwk(), key.public_jwk());
        assert!(save_agent_key(&ks_dir, &store, &key, None, "x").is_err());
        assert_eq!(list_agent_keys(&ks_dir).unwrap().len(), 1);
        assert_eq!(default_agent_key(&ks_dir).unwrap().kid, key.kid);
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(
            !raw.contains(&b64u(&key.secret_bytes())),
            "scalar must not be stored in the clear"
        );
    }
}
