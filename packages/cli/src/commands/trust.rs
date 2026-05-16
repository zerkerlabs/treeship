//! `treeship trust` subcommand family.
//!
//! Manages pinned trust roots for the three self-signed verification
//! boundaries (Merkle checkpoint, hub-org JournalCheckpoint, agent
//! certificate). Roots live at `~/.treeship/trust_roots.json` (override
//! with the `TREESHIP_TRUST_ROOTS` env var) with mode `0o600`.
//!
//! Operators configure trust out-of-band: verify the issuer's public key
//! fingerprint via a channel they trust, then run `treeship trust add
//! <key_id> <pubkey> --kind <kind>`. There is no remote sync in this
//! release; the planned `treeship hub sync-trust` is referenced in
//! error messages but unimplemented.

use treeship_core::trust::{
    encode_ed25519_pubkey, TrustRoot, TrustRootError, TrustRootKind, TrustRootStore,
};

use crate::printer::{Format, Printer};

/// `treeship trust list`. Renders every pinned root, grouped by kind.
pub fn list(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let path = TrustRootStore::default_path();
    let store = match TrustRootStore::open(&path) {
        Ok(s)  => s,
        Err(TrustRootError::NotConfigured { .. }) | Err(TrustRootError::Empty { .. }) => {
            if printer.format == Format::Json {
                printer.json(&serde_json::json!({
                    "status": "ok",
                    "path":   path.display().to_string(),
                    "roots":  [],
                }));
                return Ok(());
            }
            printer.info(&format!(
                "no trust roots configured (would be at {})",
                path.display(),
            ));
            printer.hint("treeship trust add <key_id> <pubkey> --kind <hub_checkpoint|ship|agent_cert>");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    if printer.format == Format::Json {
        let roots: Vec<_> = store.roots().iter().map(|r| serde_json::json!({
            "key_id":     r.key_id,
            "public_key": r.public_key,
            "kind":       r.kind.as_str(),
            "label":      r.label,
            "added_at":   r.added_at,
        })).collect();
        printer.json(&serde_json::json!({
            "status": "ok",
            "path":   path.display().to_string(),
            "roots":  roots,
        }));
        return Ok(());
    }

    printer.info(&format!("trust roots ({}):", path.display()));
    for r in store.roots() {
        printer.info(&format!(
            "  {kind:<16} {key_id:<24} {pk:<58} {label}",
            kind   = r.kind.as_str(),
            key_id = r.key_id,
            pk     = r.public_key,
            label  = if r.label.is_empty() { "" } else { &r.label },
        ));
    }
    Ok(())
}

/// `treeship trust add <key_id> <pubkey> --kind <kind>`. Replaces any
/// previous `(key_id, kind)` entry.
pub fn add(
    key_id: &str,
    public_key: &str,
    kind: &str,
    label: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = TrustRootKind::parse(kind)
        .ok_or_else(|| format!(
            "unknown trust root kind '{kind}'. Expected one of: hub_checkpoint, ship, agent_cert",
        ))?;

    // Accept both `ed25519:<b64>` and bare base64url for ergonomics.
    // Normalize on write so the on-disk file is always prefixed.
    let parsed = treeship_core::trust::decode_ed25519_pubkey(public_key)
        .map_err(|m| format!("invalid public key: {m}"))?;
    let canonical_pk = encode_ed25519_pubkey(&parsed);

    if key_id.trim().is_empty() {
        return Err("key_id must not be empty".into());
    }

    let path = TrustRootStore::default_path();
    let mut store = match TrustRootStore::open(&path) {
        Ok(s) => s,
        Err(TrustRootError::NotConfigured { .. }) | Err(TrustRootError::Empty { .. }) => {
            TrustRootStore::empty()
        }
        Err(e) => return Err(e.into()),
    };

    let root = TrustRoot {
        key_id:     key_id.into(),
        public_key: canonical_pk.clone(),
        kind,
        label:      label.unwrap_or("").into(),
        added_at:   now_rfc3339(),
    };
    store.add(root);
    store.save(&path)?;

    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "status":     "ok",
            "message":    "trust root added",
            "key_id":     key_id,
            "kind":       kind.as_str(),
            "public_key": canonical_pk,
            "path":       path.display().to_string(),
        }));
        return Ok(());
    }
    printer.success("trust root added", &[
        ("key_id",     key_id),
        ("kind",       kind.as_str()),
        ("public_key", &canonical_pk),
        ("path",       &path.display().to_string()),
    ]);
    Ok(())
}

/// `treeship trust remove <key_id>`. Removes every entry matching `key_id`
/// across all kinds.
pub fn remove(
    key_id: &str,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = TrustRootStore::default_path();
    let mut store = match TrustRootStore::open(&path) {
        Ok(s) => s,
        Err(TrustRootError::NotConfigured { .. }) | Err(TrustRootError::Empty { .. }) => {
            if printer.format == Format::Json {
                printer.json(&serde_json::json!({
                    "status":  "ok",
                    "message": "no trust roots configured; nothing to remove",
                    "key_id":  key_id,
                    "removed": false,
                }));
                return Ok(());
            }
            printer.info("no trust roots configured; nothing to remove");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let removed = store.remove(key_id);
    store.save(&path)?;

    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "status":  "ok",
            "key_id":  key_id,
            "removed": removed,
            "path":    path.display().to_string(),
        }));
        return Ok(());
    }
    if removed {
        printer.success("trust root removed", &[("key_id", key_id)]);
    } else {
        printer.info(&format!("no trust root with key_id={key_id}"));
    }
    Ok(())
}

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    treeship_core::statements::unix_to_rfc3339(secs)
}
