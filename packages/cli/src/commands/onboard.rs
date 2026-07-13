//! `treeship onboard` — take an agent from nothing to verifiable in one
//! command.
//!
//! The full TLS-for-agents lifecycle is ~ten commands with four traps
//! (register takes `--name` while everything else takes an `agent://` URI; a
//! mismatched URI silently downgrades signing; the card, publish, checkpoint
//! and anchor steps each have their own invocation; and the trust material a
//! counterparty needs was, until `keys export`, not printable at all). Every
//! one of those was hit in a real end-to-end dogfood run. `onboard` composes
//! the existing commands — register `--own-key`, `attest card`, `publish`,
//! `merkle checkpoint` + `merkle publish` — into one idempotent pass and ends
//! by printing exactly what a counterparty runs to resolve and verify the
//! agent. It adds no new attestation surface of its own: every artifact it
//! produces is minted by the same code paths as the individual commands.

use crate::{ctx, printer::Printer};
use treeship_core::statements::{payload_type, ReceiptStatement};

pub struct OnboardArgs {
    /// Agent name or `agent://` URI (normalized either way).
    pub name: String,
    pub from_harness: Option<String>,
    pub tools_json: Option<String>,
    pub from_a2a: Option<String>,
    pub tools: Vec<String>,
    pub models: Vec<String>,
    pub description: Option<String>,
    /// Also publish + checkpoint + anchor to the attached Hub.
    pub publish: bool,
    pub config: Option<String>,
}

pub fn onboard(args: OnboardArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    // One name in, one URI out — the register-takes-a-name /
    // everything-else-takes-a-URI trap is normalized away here.
    let name = args
        .name
        .strip_prefix("agent://")
        .unwrap_or(&args.name)
        .to_string();
    if name.is_empty() || name.contains('/') {
        return Err(format!(
            "invalid agent name {:?} — use a bare name (deployer) or agent://<name>",
            args.name
        )
        .into());
    }
    let actor = format!("agent://{name}");

    // A card without a capability source is an empty declaration; require one
    // up front rather than minting a vacuous card.
    if args.from_harness.is_none()
        && args.tools_json.is_none()
        && args.from_a2a.is_none()
        && args.tools.is_empty()
    {
        return Err("no capability source — pass at least one of --from-harness <settings.json>, --tools-json <file>, --from-a2a <AgentCard.json>, or --tools <list>".into());
    }

    let ctx = ctx::open(args.config.as_deref())?;

    // ── 1/4 identity: per-agent key, certified + pinned ────────────────────
    // register --own-key is idempotent: an existing key is reused, never
    // duplicated, so onboard can run repeatedly (e.g. on every agent boot).
    printer.info(&format!(
        "[1/4] identity — registering {actor} with its own key"
    ));
    crate::commands::agent::register(
        &name,
        Vec::new(),
        args.models.first().cloned(),
        365,
        args.description.clone(),
        Vec::new(),
        Vec::new(),
        true, // --own-key
        true, // --quiet (no .agent dir dropped into cwd)
        args.config.as_deref(),
        printer,
    )?;
    let agents_dir = crate::commands::cards::agents_dir_for(&ctx.config_path);
    let key_id = crate::commands::cards::registered_key_for_actor(&agents_dir, &actor)
        .ok_or("registration did not yield a per-agent key (registered without --own-key?)")?;
    printer.info(&format!("      key: {key_id} (pinned under AgentCert)"));

    // ── 2/4 capability card ────────────────────────────────────────────────
    printer.info("[2/4] capability card");
    crate::commands::attest::card(
        crate::commands::attest::CardArgs {
            agent: actor.clone(),
            tools: args.tools.clone(),
            models: args.models.clone(),
            keyid: None,
            owner: None,
            version: "1".to_string(),
            policy_ref: None,
            from_harness: args.from_harness.clone(),
            tools_json: args.tools_json.clone(),
            from_a2a: args.from_a2a.clone(),
            config: args.config.clone(),
        },
        printer,
    )?;
    let card_id = latest_card_for(&ctx, &actor, &key_id);

    // ── 3/4 publish + anchor (opt-in) ──────────────────────────────────────
    let mut hub_endpoint: Option<String> = None;
    if args.publish {
        printer.info("[3/4] publish + anchor to Hub");
        // Fail loudly: --publish is an explicit request, and a silent local-only
        // onboard would let the operator believe the agent is resolvable.
        crate::commands::publish::publish(&actor, args.config.as_deref(), printer)?;
        crate::commands::merkle::checkpoint(args.config.as_deref(), printer)?;
        crate::commands::merkle::publish(args.config.as_deref(), printer)?;
        hub_endpoint = ctx
            .config
            .resolve_hub(None)
            .ok()
            .map(|(_, h)| h.endpoint.clone());
    } else {
        printer.info(
            "[3/4] publish — skipped (local only; re-run with --publish once a hub is attached)",
        );
    }

    // ── 4/4 the trust bundle: what a counterparty runs ─────────────────────
    // The out-of-band handshake, printed instead of implied. The agent key
    // pins under agent_cert (verifies the card + receipts); the ship key pins
    // under hub_checkpoint (verifies the transparency anchor).
    printer.info("[4/4] trust bundle — hand these to a counterparty:");
    printer.blank();
    let agent_pub = pinnable(&ctx, &key_id)?;
    printer.info(&format!(
        "    treeship trust add {key_id} {agent_pub} --kind agent_cert --yes"
    ));
    if args.publish {
        let ship_key = ctx.keys.default_key_id()?;
        let ship_pub = pinnable(&ctx, &ship_key)?;
        printer.info(&format!(
            "    treeship trust add {ship_key} {ship_pub} --kind hub_checkpoint --yes"
        ));
    }
    printer.blank();
    printer.success(
        "agent onboarded",
        &[
            ("agent", actor.as_str()),
            ("key", key_id.as_str()),
            ("card", card_id.as_deref().unwrap_or("(see above)")),
        ],
    );
    if let Some(endpoint) = hub_endpoint {
        printer.info("  a counterparty verifies with:");
        printer.info(&format!("    treeship resolve --hub {endpoint} {actor}"));
        printer.info(&format!("    treeship audit --hub {endpoint} {actor}"));
    } else {
        printer.hint(&format!("verify locally: treeship resolve {actor}"));
    }
    printer.blank();
    Ok(())
}

/// The `ed25519:<base64url>` pinnable form of a key's public half.
fn pinnable(ctx: &ctx::Ctx, key_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bytes = ctx.keys.public_key(key_id)?;
    Ok(format!("ed25519:{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// The newest agent_card.v1 for this actor signed by its registered key —
/// the same selection rule `resolve` applies, so onboard reports the card a
/// resolver would serve.
fn latest_card_for(ctx: &ctx::Ctx, actor: &str, key_id: &str) -> Option<String> {
    let receipt_pt = payload_type("receipt");
    let mut newest: Option<(String, String)> = None;
    for entry in ctx.storage.list_by_type(&receipt_pt) {
        let Ok(rec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind != "agent_card.v1" {
            continue;
        }
        let Some(payload) = stmt.payload else {
            continue;
        };
        if payload.get("agent").and_then(|v| v.as_str()) != Some(actor) {
            continue;
        }
        let signer = rec
            .envelope
            .signatures
            .first()
            .map(|s| s.keyid.as_str())
            .unwrap_or("");
        if signer != key_id {
            continue;
        }
        let is_newer = newest
            .as_ref()
            .map(|(_, t)| entry.signed_at > *t)
            .unwrap_or(true);
        if is_newer {
            newest = Some((entry.id.clone(), entry.signed_at.clone()));
        }
    }
    newest.map(|(id, _)| id)
}
