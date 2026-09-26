use crate::{ctx, printer::Printer};

/// `treeship keys export` — print a key's public half in the pinnable
/// `ed25519:<base64url>` form, plus the exact `treeship trust add` command a
/// counterparty runs to pin it. This is the out-of-band half of the trust
/// model: every remote verification (resolve, audit, checkpoint) is checked
/// against the verifier's OWN trust roots, and until now there was no
/// sanctioned way to hand someone the key material those roots need. The
/// private key never leaves the store — only the public half is printed.
pub fn export(
    key_id: Option<&str>,
    agent: Option<&str>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let ctx = ctx::open(config)?;

    // Resolve which key to export: an agent's registered per-agent key, an
    // explicit key id, or the ship's default signing key.
    let (resolved_id, is_agent_key, subject) = match (key_id, agent) {
        (Some(_), Some(_)) => {
            return Err("--key and --agent cannot be used together".into());
        }
        (None, Some(actor)) => {
            let agents_dir = crate::commands::cards::agents_dir_for(&ctx.config_path);
            let Some(id) = crate::commands::cards::registered_key_for_actor(&agents_dir, actor)
            else {
                return Err(format!(
                    "no per-agent key registered for {actor}\n\n  Fix: treeship agent register --name <name> --own-key"
                )
                .into());
            };
            (id, true, actor.to_string())
        }
        (Some(id), None) => {
            // An explicit key id may be a per-agent key; suggest the right
            // trust kind by checking the local AgentCert pins.
            let pinned_agent_cert = treeship_core::trust::TrustRootStore::open_default_or_empty()
                .ok()
                .map(|t| {
                    t.roots().iter().any(|r| {
                        r.key_id == id && r.kind == treeship_core::trust::TrustRootKind::AgentCert
                    })
                })
                .unwrap_or(false);
            (id.to_string(), pinned_agent_cert, id.to_string())
        }
        (None, None) => {
            let id = ctx.keys.default_key_id()?;
            (id.to_string(), false, "ship default".to_string())
        }
    };

    let pub_bytes = ctx.keys.public_key(&resolved_id)?;
    let pub_b64 = URL_SAFE_NO_PAD.encode(&pub_bytes);
    let pinnable = format!("ed25519:{pub_b64}");

    // The trust kinds a counterparty pins this key under. A per-agent key
    // backs cards and receipts (AgentCert). A ship key signs several distinct
    // things, and Batch 5 split those into separate kinds so a counterparty
    // grants exactly the powers they intend: cert_issuer (vouch for this
    // ship's agent certs → `verified` on resolve), revoker (honor this ship's
    // capability revocations), hub_org (accept its hub-org single-use
    // checkpoints), hub_checkpoint (Merkle checkpoints → `anchored & verified`
    // on the transparency check). The deprecated `ship` kind is no longer
    // emitted.
    let kinds: &[&str] = if is_agent_key {
        &["agent_cert"]
    } else {
        &["cert_issuer", "revoker", "hub_org", "hub_checkpoint"]
    };

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "key_id": resolved_id,
            "subject": subject,
            "public_key": pinnable,
            "trust_kinds": kinds,
            "trust_add_commands": kinds
                .iter()
                .map(|k| format!("treeship trust add {resolved_id} {pinnable} --kind {k} --yes"))
                .collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    printer.success(
        "public key export",
        &[
            ("key", resolved_id.as_str()),
            ("subject", subject.as_str()),
            ("pubkey", pinnable.as_str()),
        ],
    );
    printer.blank();
    printer.info("  a counterparty pins it with (each line grants one power; hand over only the ones you mean):");
    for k in kinds {
        let note = match *k {
            "cert_issuer" => "  # verify the agent certificates this ship issues",
            "revoker" => "  # honour this ship's capability revocations: it can revoke cards on their machine",
            "hub_org" => "  # accept this ship's hub-org single-use checkpoints",
            "hub_checkpoint" => "  # verify this ship's Merkle checkpoints (the transparency anchor)",
            "agent_cert" => "  # this agent's own signed artifacts verify and import",
            _ => "",
        };
        printer.info(&format!(
            "    treeship trust add {resolved_id} {pinnable} --kind {k} --yes{note}"
        ));
    }
    printer.blank();
    Ok(())
}

pub fn list(config: Option<&str>, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let infos = ctx.keys.list()?;

    if infos.is_empty() {
        printer.info("no keys found -- run 'treeship init'");
        return Ok(());
    }

    if printer.format == crate::printer::Format::Json {
        let out: Vec<_> = infos
            .iter()
            .map(|k| {
                serde_json::json!({
                    "id":               k.id,
                    "algorithm":        k.algorithm,
                    "is_default":       k.is_default,
                    "created_at":       k.created_at,
                    "fingerprint":      k.fingerprint,
                    "valid_until":      k.valid_until,
                    "successor_key_id": k.successor_key_id,
                })
            })
            .collect();
        printer.json(&out);
        return Ok(());
    }

    for k in &infos {
        let default_marker = if k.is_default { " (default)" } else { "" };
        let lifecycle = match (&k.valid_until, &k.successor_key_id) {
            (Some(until), Some(succ)) => format!("  rotated -> {succ}, valid until {until}"),
            (Some(until), None) => format!("  valid until {until}"),
            (None, Some(succ)) => format!("  successor: {succ}"),
            (None, None) => String::new(),
        };
        printer.info(&format!(
            "  {}  {}  {}{}{}",
            k.id, k.algorithm, k.fingerprint, default_marker, lifecycle
        ));
    }
    Ok(())
}

pub fn rotate(
    key_id: Option<&str>,
    grace_hours: u64,
    set_default: bool,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let grace = std::time::Duration::from_secs(grace_hours.saturating_mul(3600));

    // One rotation at a time. Two `keys rotate` racing both rotated the
    // same predecessor and minted two successors for it; the lock makes
    // the second one rotate whatever the first left as default.
    let _lock = rotation_lock(&ctx.config.keys_dir)?;
    let result = ctx.keys.rotate(key_id, grace, set_default)?;

    // The keystore manifest is the one source of truth for the default
    // signer: attest, hub attach, prove and the dashboard all read it from
    // there. config.json's `default_key_id` is what `init` wrote and is
    // not consulted, so nothing here writes config.json. (Through 0.31.9
    // the readers disagreed: the keystore promoted the successor while
    // hub attach read the predecessor from config.json; a first fix wrote
    // config.json, which flattened a project stub onto itself and broke
    // the ship. 0.31.9 full test, CLI-9.)
    let default_now = ctx.keys.default_key_id()?;

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "predecessor": {
                "id":          result.predecessor.id,
                "fingerprint": result.predecessor.fingerprint,
                "valid_until": result.predecessor.valid_until,
            },
            "successor": {
                "id":          result.successor.id,
                "fingerprint": result.successor.fingerprint,
                "is_default":  result.successor.is_default,
            },
            "grace_period_until": result.grace_period_until,
            "default_key_id": default_now,
        }));
        return Ok(());
    }

    printer.info("rotated");
    printer.info(&format!(
        "  predecessor:  {}  ({})",
        result.predecessor.id, result.predecessor.fingerprint
    ));
    printer.info(&format!(
        "  successor:    {}  ({})",
        result.successor.id, result.successor.fingerprint
    ));
    printer.info(&format!(
        "  valid until:  {} (predecessor accepts new sigs until then)",
        result.grace_period_until
    ));
    if set_default {
        printer.info("  default:      successor is now the default signer");
    } else {
        printer.info("  default:      unchanged (use 'treeship keys list' to confirm)");
    }
    // Rotation is local. Nothing is minted, nothing travels in a bundle or
    // a presentation, and a counterparty's pin has no expiry: they keep
    // trusting the predecessor and cannot verify the successor until they
    // re-pin (TASKS-0.31.6 T2, T3). Say it, and say what to send.
    printer.blank();
    printer.warn(
        "rotation is local to this keystore",
        &[
            ("counterparties", "keep trusting the predecessor until they remove its pin, and cannot verify the successor until they pin it"),
            ("send them", &format!("treeship keys export {}   (the trust add lines it prints)", result.successor.id)),
            ("and ask them to run", &format!("treeship trust remove {}", result.predecessor.id)),
        ],
    );
    printer.hint("if the predecessor was compromised, treat every counterparty as trusting it until you hear back: the grace window above applies only here");
    Ok(())
}

/// An exclusive lock held for the duration of a rotation. The keystore
/// lives under `keys_dir`; the lock file sits beside it.
fn rotation_lock(keys_dir: &str) -> Result<std::fs::File, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(keys_dir).join(".rotate.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // Blocking: the second rotation waits for the first, then rotates
        // whatever the first left as default.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(file)
}
