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
//!
//! Audit lane J fix-up: `add` and `remove` print the affected key's
//! fingerprint and require either `--yes` or an interactive y/N
//! confirmation. Both subcommands previously overwrote silently.

use std::io::{self, BufRead, IsTerminal, Write};

use sha2::{Digest, Sha256};

use treeship_core::trust::{
    decode_ed25519_pubkey, encode_ed25519_pubkey, TrustRoot, TrustRootError, TrustRootKind,
    TrustRootStore,
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
            printer.hint("treeship trust add <key_id> <pubkey> --kind <hub_checkpoint|ship|agent_cert|session_host>");
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

/// `treeship trust add <key_id> <pubkey> --kind <kind> [--yes]`. Replaces
/// any previous `(key_id, kind)` entry.
///
/// Audit lane J fix-up: previously overwrote silently. Now prints the
/// pubkey fingerprint and asks for confirmation; `--yes` skips the
/// prompt; non-interactive stdin without `--yes` is refused so a
/// supply-chain script can't slip a new root in via curl|sh.
pub fn add(
    key_id: &str,
    public_key: &str,
    kind: &str,
    label: Option<&str>,
    yes: bool,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = TrustRootKind::parse(kind)
        .ok_or_else(|| format!(
            "unknown trust root kind '{kind}'. Expected one of: hub_checkpoint, ship, agent_cert, session_host",
        ))?;

    // Accept both `ed25519:<b64>` and bare base64url for ergonomics.
    // Normalize on write so the on-disk file is always prefixed.
    let parsed = decode_ed25519_pubkey(public_key)
        .map_err(|m| format!("invalid public key: {m}"))?;
    let canonical_pk = encode_ed25519_pubkey(&parsed);
    let fingerprint  = pubkey_fingerprint(&canonical_pk);

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

    // Is this replacing an existing (key_id, kind) entry?
    let replacing = store.roots().iter().find(|r| r.key_id == key_id && r.kind == kind).cloned();

    // Confirmation gate. JSON callers MUST pass --yes; an interactive
    // y/N prompt on stdout/stdin doesn't compose with --output json
    // anyway.
    if !yes {
        if printer.format == Format::Json {
            return Err(
                "trust add requires --yes when --output json (no interactive confirmation possible)".into(),
            );
        }
        if !io::stdin().is_terminal() {
            return Err(
                "trust add refuses to run non-interactively without --yes \
                 (pass --yes to skip the confirmation prompt)".into(),
            );
        }
        if let Some(ref prev) = replacing {
            let prev_fp = pubkey_fingerprint(&prev.public_key);
            printer.warn(
                &format!(
                    "WARNING: replacing existing root {} for kind={}",
                    prev_fp,
                    kind.as_str(),
                ),
                &[
                    ("existing_key_id", &prev.key_id),
                    ("existing_label",  if prev.label.is_empty() { "<none>" } else { &prev.label }),
                    ("new_fingerprint", &fingerprint),
                ],
            );
        } else {
            printer.info(&format!(
                "About to add trust root:\n  kind:        {}\n  key_id:      {}\n  fingerprint: {}\n  public_key:  {}",
                kind.as_str(), key_id, fingerprint, canonical_pk,
            ));
        }
        if !confirm("Add this trust root? [y/N] ") {
            printer.info("aborted; no changes made");
            return Ok(());
        }
    }

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
            "status":      "ok",
            "message":     "trust root added",
            "key_id":      key_id,
            "kind":        kind.as_str(),
            "public_key":  canonical_pk,
            "fingerprint": fingerprint,
            "replaced":    replacing.is_some(),
            "path":        path.display().to_string(),
        }));
        return Ok(());
    }
    printer.success("trust root added", &[
        ("key_id",      key_id),
        ("kind",        kind.as_str()),
        ("fingerprint", &fingerprint),
        ("public_key",  &canonical_pk),
        ("path",        &path.display().to_string()),
    ]);
    Ok(())
}

/// `treeship trust remove <key_id> [--yes]`. Removes every entry matching
/// `key_id` across all kinds.
///
/// Audit lane J fix-up: previously removed silently. Now prints which
/// entries would disappear (with their fingerprints) and asks for
/// confirmation. Same `--yes` / non-interactive contract as `add`.
pub fn remove(
    key_id: &str,
    yes: bool,
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

    // Collect what would be removed, for the confirmation message.
    let matches: Vec<TrustRoot> = store
        .roots()
        .iter()
        .filter(|r| r.key_id == key_id)
        .cloned()
        .collect();

    if matches.is_empty() {
        if printer.format == Format::Json {
            printer.json(&serde_json::json!({
                "status":  "ok",
                "key_id":  key_id,
                "removed": false,
                "path":    path.display().to_string(),
            }));
            return Ok(());
        }
        printer.info(&format!("no trust root with key_id={key_id}"));
        return Ok(());
    }

    if !yes {
        if printer.format == Format::Json {
            return Err(
                "trust remove requires --yes when --output json (no interactive confirmation possible)".into(),
            );
        }
        if !io::stdin().is_terminal() {
            return Err(
                "trust remove refuses to run non-interactively without --yes \
                 (pass --yes to skip the confirmation prompt)".into(),
            );
        }
        printer.info(&format!(
            "About to remove {} trust root(s) for key_id={}:",
            matches.len(),
            key_id,
        ));
        for r in &matches {
            printer.info(&format!(
                "  - kind={}  fingerprint={}  label={}",
                r.kind.as_str(),
                pubkey_fingerprint(&r.public_key),
                if r.label.is_empty() { "<none>" } else { &r.label },
            ));
        }
        if !confirm("Remove? [y/N] ") {
            printer.info("aborted; no changes made");
            return Ok(());
        }
    }

    let removed = store.remove(key_id);
    store.save(&path)?;

    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "status":  "ok",
            "key_id":  key_id,
            "removed": removed,
            "count":   matches.len(),
            "path":    path.display().to_string(),
        }));
        return Ok(());
    }
    if removed {
        printer.success("trust root removed", &[
            ("key_id", key_id),
            ("count",  &matches.len().to_string()),
        ]);
    } else {
        printer.info(&format!("no trust root with key_id={key_id}"));
    }
    Ok(())
}

/// Short fingerprint for a canonical `ed25519:<b64>` pubkey: first 16 hex
/// chars of SHA-256 over the encoded form. Long enough to be unique in
/// practice, short enough to read out loud.
fn pubkey_fingerprint(canonical_pk: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_pk.as_bytes());
    let bytes = hasher.finalize();
    let hex_full = hex::encode(bytes);
    hex_full[..16].to_string()
}

/// Interactive y/N confirmation. Reads one line from stdin; anything
/// other than "y" / "Y" / "yes" returns false.
fn confirm(msg: &str) -> bool {
    print!("{msg}");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    treeship_core::statements::unix_to_rfc3339(secs)
}
