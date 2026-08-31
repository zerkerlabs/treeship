//! `treeship room create|status|participants` -- Phase 2 CLI sugar over
//! `treeship session`, per docs/specs/agent-invitations-rooms.md:
//!
//!   "The `treeship room` commands are sugar over `treeship session`. A
//!    room is just a session with the room field populated."
//!
//! `room close` is deliberately NOT implemented here -- plain
//! `treeship session close` already works on a room since a room is just
//! a session.
//!
//! Nothing in this module gates any authority decision on
//! `invitation_authority`. It is signed -- the composer binds `room` into
//! the `session.v1` receipt -- but signed is not enforced: nothing checks
//! that the invitations actually minted in a session conform to the
//! authority the receipt declares. Until that conformance check lands
//! (see `RoomInfo`'s doc comment in packages/core/src/session/manifest.rs,
//! and Phase 3 of docs/specs/agent-invitations-rooms.md), this module
//! displays `invitation_authority` and gates nothing on it.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use treeship_core::session::{InvitationAuthority, RoomInfo};
use treeship_core::statements::{payload_type, SessionParticipantStatement};

use crate::{ctx, printer::Printer};

use super::session as session_cmd;

// ---------------------------------------------------------------------------
// Argument shapes (re-exposed here so main.rs stays thin, mirroring the
// InviteArgs/JoinArgs/CountersignArgs pattern in commands/invitation.rs).
// ---------------------------------------------------------------------------

pub struct RoomCreateArgs {
    pub workflow_ref: Option<String>,
    /// Raw `--invitation-authority` value: "host-only" (default) |
    /// "delegated" | "open".
    pub invitation_authority: Option<String>,
    /// One or more `--delegate <pubkey>`. Only valid with `--invitation-authority delegated`.
    pub delegate: Vec<String>,
    /// Raw `--checkpoint-every` value. Must parse as a plain `u32` action
    /// count -- the old stringly-typed "50actions" form is rejected.
    pub checkpoint_every: Option<String>,
    pub format: String,
}

pub struct RoomStatusArgs {
    pub format: String,
}

pub struct RoomParticipantsArgs {
    pub format: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a room id. Same convention as `generate_event_id` /
/// `generate_session_id` elsewhere in the codebase: an `<prefix>_` tag
/// plus 16 hex chars (8 random bytes). A room id is a non-secret,
/// collision-avoidance-only identifier, not a key/nonce/token, so
/// `thread_rng` (not `OsRng`) is the right generator here -- same
/// rationale as `generate_session_id` (AUD-24).
fn generate_room_id() -> String {
    let mut buf = [0u8; 8];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut buf);
    format!("room_{}", hex::encode(buf))
}

/// Parse `--invitation-authority` + `--delegate` into an `InvitationAuthority`.
/// Defaults to `HostOnly` per Q3's recommendation in the spec. `delegated`
/// requires at least one `--delegate`; `--delegate` with any other mode is
/// rejected as a likely operator mistake rather than silently ignored.
fn parse_invitation_authority(
    raw: Option<&str>,
    delegates: &[String],
) -> Result<InvitationAuthority, String> {
    let mode = raw.unwrap_or("host-only");
    match mode {
        "host-only" => {
            if !delegates.is_empty() {
                return Err(
                    "--delegate is only valid with --invitation-authority delegated".into(),
                );
            }
            Ok(InvitationAuthority::HostOnly)
        }
        "delegated" => {
            if delegates.is_empty() {
                return Err(
                    "--invitation-authority delegated requires at least one --delegate <pubkey>"
                        .into(),
                );
            }
            Ok(InvitationAuthority::DelegatedTo {
                delegates: delegates.to_vec(),
            })
        }
        "open" => {
            // Spec-legal but explicitly recommended to stay
            // roadmap/unenforced (Q3). We allow setting it -- no
            // enforcement logic exists anywhere for it, by design.
            if !delegates.is_empty() {
                return Err(
                    "--delegate is only valid with --invitation-authority delegated".into(),
                );
            }
            Ok(InvitationAuthority::Open)
        }
        other => Err(format!(
            "--invitation-authority must be one of host-only|delegated|open (got `{other}`)"
        )),
    }
}

/// Parse `--checkpoint-every` as a plain action count. `checkpoint_every_actions`
/// was deliberately typed `u32` (not a free-form string) in PR #266 specifically
/// so the old "50actions" stringly-typed footgun can't come back in through the
/// CLI -- reject anything that isn't a bare non-negative integer.
fn parse_checkpoint_every(s: &str) -> Result<u32, String> {
    s.trim().parse::<u32>().map_err(|_| {
        format!(
            "--checkpoint-every must be a plain integer action count, e.g. `--checkpoint-every 50` \
             (got `{s}`). The old stringly-typed \"50actions\" form is rejected on purpose -- \
             checkpoint_every_actions is a u32."
        )
    })
}

// ---------------------------------------------------------------------------
// `treeship room create`
// ---------------------------------------------------------------------------

pub fn create(
    ctx_override: Option<&str>,
    args: RoomCreateArgs,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse everything before any side effect, same discipline as
    // `invitation::invite`'s restriction parsing: operator typos surface
    // before we touch the keystore or filesystem.
    let invitation_authority =
        parse_invitation_authority(args.invitation_authority.as_deref(), &args.delegate)?;
    let checkpoint_every_actions = match args.checkpoint_every.as_deref() {
        Some(s) => Some(parse_checkpoint_every(s)?),
        None => None,
    };

    // Start a normal session via the existing flow, reusing ALL of its
    // logic (dangerous-root guard, session-start artifact, event log,
    // manifest write) rather than duplicating any of it. The inner call
    // uses a quiet printer so `session::start`'s own success output
    // doesn't print -- JSON mode is a single-document API (see the
    // comment on this in `session::close`), and running `session::start`
    // with the real printer would emit a second JSON object ahead of
    // this command's own room-create response.
    let quiet_printer = Printer::new(printer.format, true, printer.no_color);
    session_cmd::start(None, None, None, false, ctx_override, &quiet_printer)?;

    let mut manifest = session_cmd::load_session()
        .ok_or("room create: session started but manifest not found on disk")?;

    let c = ctx::open(ctx_override)?;
    let host_signer = c.keys.default_signer()?;
    let host_pubkey = URL_SAFE_NO_PAD.encode(host_signer.public_key_bytes());

    let room_id = generate_room_id();
    let mut room = RoomInfo::new(room_id.clone(), host_pubkey);
    room.invitation_authority = invitation_authority;
    room.workflow_ref = args.workflow_ref.clone();
    room.checkpoint_every_actions = checkpoint_every_actions;
    manifest.room = Some(room);

    session_cmd::save_session(&manifest)?;

    if args.format == "json" {
        printer.json(&serde_json::json!({
            "status":     "ok",
            "room_id":    room_id,
            "session_id": manifest.session_id,
        }));
        return Ok(());
    }

    printer.blank();
    printer.success(
        "room created",
        &[
            ("room_id", room_id.as_str()),
            ("session_id", manifest.session_id.as_str()),
        ],
    );
    printer.blank();
    printer.hint("treeship room status");
    printer.hint("treeship session invite  to mint an invitation for another agent");
    printer.hint("treeship session close   when the room is done (a room is just a session)");
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// `treeship room status`
// ---------------------------------------------------------------------------

pub fn status(
    ctx_override: Option<&str>,
    args: RoomStatusArgs,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = session_cmd::load_session().ok_or(
        "no active room -- this session was not created with `treeship room create`\n\n  \
         Fix: treeship room create",
    )?;
    let room = manifest.room.clone().ok_or(
        "no active room -- this session was not created with `treeship room create`\n\n  \
         Fix: treeship room create",
    )?;

    let c = ctx::open(ctx_override)?;
    let root_verified = if let Some(ref root_id) = manifest.root_artifact_id {
        c.storage.read(root_id).is_ok()
    } else {
        false
    };
    let artifact_count = match &manifest.root_artifact_id {
        Some(root_id) => session_cmd::count_chain_artifacts(&c, root_id),
        None => 0,
    };
    let elapsed_ms = session_cmd::epoch_ms().saturating_sub(manifest.started_at_ms);

    if args.format == "json" {
        printer.json(&serde_json::json!({
            "status":           "active",
            "active":           true,
            "session_id":       manifest.session_id,
            "name":             manifest.name,
            "actor":            manifest.actor,
            "started_at":       manifest.started_at,
            "elapsed_ms":       elapsed_ms,
            "receipts":         artifact_count,
            "root_verified":    root_verified,
            "room": {
                "room_id":                  room.room_id,
                "host_pubkey":              room.host_pubkey,
                "invitation_authority":     room.invitation_authority,
                "workflow_ref":             room.workflow_ref,
                "checkpoint_every_actions": room.checkpoint_every_actions,
                "participant_count":        room.participants.len(),
            },
        }));
        return Ok(());
    }

    let elapsed_str = session_cmd::format_duration_ms(elapsed_ms);

    printer.blank();
    printer.section("session");
    printer.info(&format!("  id:        {}", manifest.session_id));
    if let Some(ref name) = manifest.name {
        printer.info(&format!("  name:      {}", name));
    }
    printer.info(&format!("  actor:     {}", manifest.actor));
    printer.info(&format!(
        "  started:   {} ({} ago)",
        manifest.started_at, elapsed_str
    ));
    printer.info(&format!(
        "  receipts:  {} (verified from chain)",
        artifact_count
    ));
    printer.blank();
    printer.section("room");
    printer.info(&format!("  room_id:              {}", room.room_id));
    printer.info(&format!("  host_pubkey:          {}", room.host_pubkey));
    printer.info(&format!(
        "  invitation_authority: {}",
        invitation_authority_label(&room.invitation_authority)
    ));
    printer.info(&format!(
        "  workflow_ref:         {}",
        room.workflow_ref.as_deref().unwrap_or("(none)")
    ));
    printer.info(&format!(
        "  checkpoint_every:     {}",
        room.checkpoint_every_actions
            .map(|n| n.to_string())
            .unwrap_or_else(|| "(none)".into())
    ));
    printer.info(&format!(
        "  participants:         {}",
        room.participants.len()
    ));
    printer.blank();
    printer.hint("treeship room participants");
    printer.hint("treeship session invite  to mint an invitation for another agent");
    printer.blank();

    Ok(())
}

fn invitation_authority_label(a: &InvitationAuthority) -> String {
    match a {
        InvitationAuthority::HostOnly => "host_only".into(),
        InvitationAuthority::DelegatedTo { delegates } => {
            format!("delegated_to ({} delegate(s))", delegates.len())
        }
        InvitationAuthority::Open => "open".into(),
    }
}

// ---------------------------------------------------------------------------
// `treeship room participants`
// ---------------------------------------------------------------------------

pub fn participants(
    ctx_override: Option<&str>,
    args: RoomParticipantsArgs,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = session_cmd::load_session().ok_or(
        "no active room -- this session was not created with `treeship room create`\n\n  \
         Fix: treeship room create",
    )?;
    let room = manifest.room.clone().ok_or(
        "no active room -- this session was not created with `treeship room create`\n\n  \
         Fix: treeship room create",
    )?;

    let c = ctx::open(ctx_override)?;

    // Derive the roster from countersigned participant artifacts rather
    // than reading `room.participants`.
    //
    // `room` rides inside the DSSE-signed session receipt, so whatever this
    // command reports is what the receipt will attest to. `room.participants`
    // is a plain list in session.json that anyone with write access can edit,
    // and countersign appends to it best-effort -- so trusting it would mean
    // signing a membership claim that is both forgeable and silently
    // incomplete.
    //
    // A participant artifact cannot be forged the same way: it carries two
    // signatures over identical canonical bytes (joining agent, then host
    // countersign), and `session countersign` re-validates it against the
    // trust-pinned invitation before attaching the second one. Requiring
    // both signatures here is what makes the roster self-proving: an entry
    // that appears cannot have been invented, and an entry that is missing
    // was never finalized.
    let mut entries: Vec<(String, SessionParticipantStatement)> = Vec::new();
    for idx in c.storage.list_by_type(&payload_type("session-participant")) {
        let rec = match c.storage.read(&idx.id) {
            Ok(r) => r,
            Err(_) => continue, // indexed but unreadable: not a member
        };
        // Exactly two signatures means finalized. A pending join (one
        // signature) is not membership, and anything else is malformed.
        if rec.envelope.signatures.len() != 2 {
            continue;
        }
        let stmt: SessionParticipantStatement = match rec.envelope.unmarshal_statement() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if stmt.session_ref != manifest.session_id {
            continue;
        }
        entries.push((idx.id.clone(), stmt));
    }
    // Stable, meaningful order: when they joined, not when the store
    // happened to index them.
    entries.sort_by(|a, b| a.1.joined_at.cmp(&b.1.joined_at).then(a.0.cmp(&b.0)));

    if args.format == "json" {
        let json_entries: Vec<_> = entries
            .iter()
            .map(|(id, stmt)| {
                serde_json::json!({
                    "participant_id": id,
                    "joining_agent":  stmt.joining_agent,
                    "joined_at":      stmt.joined_at,
                    "capabilities":   stmt.capabilities.action_types,
                })
            })
            .collect();
        printer.json(&serde_json::json!({
            "status":     "ok",
            "room_id":    room.room_id,
            "session_id": manifest.session_id,
            "count":      entries.len(),
            "participants": json_entries,
        }));
        return Ok(());
    }

    printer.blank();
    printer.section(&format!("room {} participants", room.room_id));
    if entries.is_empty() {
        printer.dim_info("  (no finalized participants yet)");
    } else {
        for (id, stmt) in &entries {
            printer.info(&format!("  {}", id));
            printer.info(&format!("    joining_agent: {}", stmt.joining_agent));
            printer.info(&format!("    joined_at:     {}", stmt.joined_at));
            printer.info(&format!(
                "    capabilities:  {}",
                stmt.capabilities.action_types.join(",")
            ));
        }
    }
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_authority_defaults_to_host_only() {
        assert_eq!(
            parse_invitation_authority(None, &[]).unwrap(),
            InvitationAuthority::HostOnly
        );
    }

    #[test]
    fn invitation_authority_host_only_rejects_delegates() {
        assert!(parse_invitation_authority(Some("host-only"), &["pk1".into()]).is_err());
    }

    #[test]
    fn invitation_authority_delegated_requires_delegate() {
        let err = parse_invitation_authority(Some("delegated"), &[]).unwrap_err();
        assert!(err.contains("at least one --delegate"));
    }

    #[test]
    fn invitation_authority_delegated_with_delegates() {
        let a =
            parse_invitation_authority(Some("delegated"), &["pk1".into(), "pk2".into()]).unwrap();
        match a {
            InvitationAuthority::DelegatedTo { delegates } => {
                assert_eq!(delegates, vec!["pk1".to_string(), "pk2".to_string()]);
            }
            other => panic!("expected DelegatedTo, got {other:?}"),
        }
    }

    #[test]
    fn invitation_authority_open_allowed_unenforced() {
        // Spec-legal, no enforcement anywhere -- just confirm it parses.
        assert_eq!(
            parse_invitation_authority(Some("open"), &[]).unwrap(),
            InvitationAuthority::Open
        );
    }

    #[test]
    fn invitation_authority_rejects_unknown_mode() {
        assert!(parse_invitation_authority(Some("bogus"), &[]).is_err());
    }

    #[test]
    fn checkpoint_every_accepts_plain_integer() {
        assert_eq!(parse_checkpoint_every("50").unwrap(), 50);
        assert_eq!(parse_checkpoint_every(" 12 ").unwrap(), 12);
        assert_eq!(parse_checkpoint_every("0").unwrap(), 0);
    }

    #[test]
    fn checkpoint_every_rejects_stringly_typed_form() {
        // The exact footgun PR #266 typed this field to avoid.
        assert!(parse_checkpoint_every("50actions").is_err());
    }

    #[test]
    fn checkpoint_every_rejects_non_numeric() {
        assert!(parse_checkpoint_every("fifty").is_err());
        assert!(parse_checkpoint_every("").is_err());
        assert!(parse_checkpoint_every("-1").is_err());
    }

    #[test]
    fn room_id_has_expected_shape() {
        let id = generate_room_id();
        assert!(id.starts_with("room_"));
        assert_eq!(id.len(), "room_".len() + 16);
        assert!(id["room_".len()..].chars().all(|c| c.is_ascii_hexdigit()));
    }
}
