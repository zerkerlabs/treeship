//! P-256 key management for Verifiable Intent credentials.
//!
//! Generates, saves, and loads ECDSA P-256 keypairs used for agent key
//! binding (`cnf`) in L2 mandates and for signing L3 credentials.

use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// A VI keypair: P-256 signing key with a stable key identifier.
pub struct ViKeypair {
    /// Stable key identifier (hex-encoded thumbprint of the public key)
    pub kid: String,
    /// P-256 signing (private) key
    pub signing_key: SigningKey,
    /// P-256 verifying (public) key
    pub verifying_key: VerifyingKey,
}

/// Serializable form used for persistence.
#[derive(Serialize, Deserialize)]
struct StoredKey {
    kid: String,
    /// Hex-encoded private scalar (encrypted when encrypted=true)
    private_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_hex: Option<String>,
    #[serde(default)]
    encrypted: bool,
}

const KEY_FILENAME: &str = "vi_key.json";

impl ViKeypair {
    /// Generate a fresh P-256 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let kid = Self::compute_kid(&verifying_key);
        Self {
            kid,
            signing_key,
            verifying_key,
        }
    }

    /// Load a keypair from `dir/vi_key.json`. Decrypts if encrypted.
    pub fn load(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let path = dir.join(KEY_FILENAME);
        let data = fs::read_to_string(&path)?;
        let stored: StoredKey = serde_json::from_str(&data)?;

        let bytes = if stored.encrypted {
            let machine_key = treeship_core::keys::derive_machine_key(dir)
                .map_err(|e| format!("failed to derive machine key: {}", e))?;
            let enc_bytes = hex::decode(&stored.private_hex)?;
            let nonce = stored.nonce_hex
                .as_deref()
                .map(hex::decode)
                .transpose()?
                .unwrap_or_default();
            treeship_core::keys::aes_gcm_decrypt(&machine_key, &enc_bytes, &nonce)
                .map_err(|e| format!("decryption failed: {}", e))?
        } else {
            // Legacy plaintext format
            hex::decode(&stored.private_hex)?
        };
        let signing_key = SigningKey::from_slice(&bytes)?;
        let verifying_key = *signing_key.verifying_key();
        let kid = Self::compute_kid(&verifying_key);
        // Verify stored kid matches
        if kid != stored.kid {
            return Err("stored kid does not match derived kid".into());
        }
        Ok(Self {
            kid,
            signing_key,
            verifying_key,
        })
    }

    /// Save the keypair to `dir/vi_key.json` with mode 0600.
    /// Private key is encrypted at rest using the same machine-derived key
    /// as the Ed25519 ship keystore.
    pub fn save(&self, dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        fs::create_dir_all(dir)?;
        let path = dir.join(KEY_FILENAME);

        // Encrypt the private key using the machine-derived key
        let machine_key = treeship_core::keys::derive_machine_key(dir)
            .map_err(|e| format!("failed to derive machine key: {}", e))?;
        let plaintext = self.signing_key.to_bytes();
        let (enc_bytes, nonce) = treeship_core::keys::aes_gcm_encrypt(&machine_key, plaintext.as_slice())
            .map_err(|e| format!("encryption failed: {}", e))?;

        let stored = StoredKey {
            kid: self.kid.clone(),
            private_hex: hex::encode(&enc_bytes),
            nonce_hex: Some(hex::encode(&nonce)),
            encrypted: true,
        };
        let json = serde_json::to_string_pretty(&stored)?;
        fs::write(&path, &json)?;

        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(path)
    }

    /// Export the public key as a JWK suitable for L2 `cnf` binding.
    pub fn public_jwk(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Encode the public key as SEC1 uncompressed point
        let point = self.verifying_key.to_encoded_point(false);
        let x_bytes = point.x().ok_or("missing x coordinate")?;
        let y_bytes = point.y().ok_or("missing y coordinate")?;

        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x_bytes.as_slice()),
            "y": URL_SAFE_NO_PAD.encode(y_bytes.as_slice()),
            "kid": self.kid,
        });
        Ok(jwk)
    }

    /// Compute a key identifier from the public key (SHA-256 of the
    /// SEC1 compressed encoding, hex-encoded).
    fn compute_kid(vk: &VerifyingKey) -> String {
        let compressed = vk.to_encoded_point(true);
        let hash = Sha256::digest(compressed.as_bytes());
        hex::encode(&hash[..16]) // first 16 bytes for a compact kid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn generate_and_roundtrip() {
        let kp = ViKeypair::generate();
        assert!(!kp.kid.is_empty());

        let dir = std::env::temp_dir().join("treeship_vi_key_test");
        kp.save(&dir).expect("save failed");

        let loaded = ViKeypair::load(&dir).expect("load failed");
        assert_eq!(kp.kid, loaded.kid);

        // Clean up
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn public_jwk_has_required_fields() {
        let kp = ViKeypair::generate();
        let jwk = kp.public_jwk().expect("jwk export failed");
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());
        assert_eq!(jwk["kid"], kp.kid);
    }
}
