//! `treeship session invite` / `join` / `countersign` -- Phase 1 of the
//! agent-invitations spec.
//!
//! See docs/specs/agent-invitations-rooms.md for the full design.
//!
//! Lifecycle:
//!
//!   host:    treeship session invite <session_id>
//!              -> signs an InvitationStatement, persists to the
//!                 artifact store, writes the bootstrap blob.
//!   joiner:  treeship session join --invite <blob> --actor agent://...
//!              -> parses + verifies signature, checks expiry +
//!                 restriction, consumes the nonce via the Approval Use
//!                 Journal, emits a single-sig pending participant
//!                 envelope.
//!   host:    treeship session countersign <participant_id>
//!              -> reads the pending envelope, adds the host
//!                 countersign, writes the finalized two-sig envelope.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use treeship_core::{
    attestation::Envelope,
    journal::{self, Journal},
    statements::{
        invitation::{
            generate_nonce, pubkey_fingerprint_short, GrantedCapabilities, InvitationStatement,
            InviteeRestriction, DEFAULT_INVITATION_LIFETIME_SECS, MAX_INVITATION_LIFETIME_SECS,
            TYPE_INVITATION,
        },
        nonce_digest, payload_type,
        session_participant::{
            verify_participant_envelope, SessionParticipantStatement, TYPE_SESSION_PARTICIPANT,
        },
        ApprovalUse, TYPE_APPROVAL_USE,
    },
    storage::Record,
    trust::{decode_ed25519_pubkey, TrustRootKind, TrustRootStore},
};

use crate::{
    ctx,
    printer::{Format, Printer},
};

// ---------------------------------------------------------------------------
// Bootstrap blob format
// ---------------------------------------------------------------------------

const BLOB_HEADER: &str = "-----BEGIN TREESHIP INVITATION-----";
const BLOB_FOOTER: &str = "-----END TREESHIP INVITATION-----";

/// Wire-format bundle of one invitation: a signed DSSE envelope plus a
/// little metadata for ergonomic verification on the join side. Serialized
/// as compact JSON, base64url-encoded, and wrapped in the
/// `-----BEGIN/END TREESHIP INVITATION-----` armor.
#[derive(serde::Serialize, serde::Deserialize)]
struct BootstrapBundle {
    /// Always 1 in Phase 1.
    v: u8,
    /// `art_<hex>` of the invitation envelope. Persisted by the host so
    /// the same id is referenced by the joiner's participant event.
    invitation_id: String,
    /// The signed DSSE envelope carrying the InvitationStatement.
    envelope: Envelope,
}

fn encode_bootstrap_blob(bundle: &BootstrapBundle) -> Result<String, String> {
    let json = serde_json::to_vec(bundle).map_err(|e| format!("encode bootstrap: {e}"))?;
    let body = URL_SAFE_NO_PAD.encode(&json);
    // Wrap every 64 chars so paste-buffers don't word-wrap mid-line.
    let mut out = String::with_capacity(body.len() + 128);
    out.push_str(BLOB_HEADER);
    out.push('\n');
    for chunk in body.as_bytes().chunks(64) {
        // chunk is ASCII (base64url) so the str cast is safe.
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(BLOB_FOOTER);
    out.push('\n');
    Ok(out)
}

fn decode_bootstrap_blob(s: &str) -> Result<BootstrapBundle, String> {
    // Tolerant of leading/trailing whitespace + intermixed comments.
    let mut in_blob = false;
    let mut body = String::new();
    for line in s.lines() {
        let l = line.trim();
        if l == BLOB_HEADER {
            in_blob = true;
            continue;
        }
        if l == BLOB_FOOTER {
            break;
        }
        if in_blob {
            body.push_str(l);
        }
    }
    if body.is_empty() {
        // Fall back: maybe the caller passed raw JSON or raw base64url
        // without armor. Try those before giving up so `--invite <raw>`
        // composes with shell glue that strips armoring.
        if let Ok(b) = URL_SAFE_NO_PAD.decode(s.trim().as_bytes()) {
            if let Ok(bundle) = serde_json::from_slice::<BootstrapBundle>(&b) {
                return Ok(bundle);
            }
        }
        if let Ok(bundle) = serde_json::from_str::<BootstrapBundle>(s.trim()) {
            return Ok(bundle);
        }
        return Err("invitation blob missing TREESHIP INVITATION header/footer".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .map_err(|e| format!("blob base64 decode: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("blob json decode: {e}"))
}

// ---------------------------------------------------------------------------
// Argument shapes (re-exposed here so main.rs stays thin)
// ---------------------------------------------------------------------------

pub struct InviteArgs {
    pub session_id: String,
    pub invitee_cert: Option<String>,
    pub invitee_pubkey: Option<String>,
    pub open: bool,
    pub capabilities: Option<String>,
    pub expires: Option<String>,
    pub format: String,
    pub no_armor: bool,
}

pub struct JoinArgs {
    pub invite: Option<String>,
    pub invite_file: Option<String>,
    pub actor: String,
    pub format: String,
}

pub struct CountersignArgs {
    pub participant_id: String,
    pub format: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_rfc3339() -> String {
    treeship_core::statements::unix_to_rfc3339(now_unix_secs())
}

fn parse_duration_to_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("expiry duration must not be empty".into());
    }
    // Suffix: s | m | h | d. Default to seconds when no suffix.
    let (digits, mult) = if let Some(d) = s.strip_suffix('d') {
        (d, 86_400u64)
    } else if let Some(d) = s.strip_suffix('h') {
        (d, 3600u64)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60u64)
    } else if let Some(d) = s.strip_suffix('s') {
        (d, 1u64)
    } else {
        (s, 1u64)
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid duration `{s}` (expected forms: 30s, 5m, 1h, 7d)"))?;
    Ok(n.saturating_mul(mult))
}

fn parse_capabilities(s: Option<&str>) -> GrantedCapabilities {
    let action_types = s
        .map(|raw| {
            raw.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    GrantedCapabilities { action_types }
}

fn parse_restriction(args: &InviteArgs) -> Result<InviteeRestriction, String> {
    let provided = [
        args.invitee_cert.is_some(),
        args.invitee_pubkey.is_some(),
        args.open,
    ];
    let count = provided.iter().filter(|b| **b).count();
    if count == 0 {
        return Err(
            "no invitee restriction specified. Pass --invitee-cert, --invitee-pubkey, \
             or explicitly --open. The Phase 1 default is cert-restriction \
             for production; --open is opt-in only because it accepts any holder \
             of the blob."
                .into(),
        );
    }
    if count > 1 {
        return Err(
            "more than one of --invitee-cert / --invitee-pubkey / --open specified; \
             pick exactly one restriction kind"
                .into(),
        );
    }
    if args.open {
        return Ok(InviteeRestriction::Open);
    }
    if let Some(fp) = &args.invitee_pubkey {
        // Accept either a 16-hex fingerprint OR a full canonical pubkey;
        // normalize to the short fingerprint form so the restriction
        // canonical bytes are stable regardless of which form the
        // operator typed.
        let fp = fp.trim();
        let fingerprint = if fp.len() == 16 && fp.chars().all(|c| c.is_ascii_hexdigit()) {
            fp.to_string()
        } else {
            // Treat as a pubkey (ed25519:<b64> or bare b64).
            let parsed =
                decode_ed25519_pubkey(fp).map_err(|e| format!("--invitee-pubkey invalid: {e}"))?;
            pubkey_fingerprint_short(&format!(
                "ed25519:{}",
                URL_SAFE_NO_PAD.encode(parsed.to_bytes()),
            ))
        };
        return Ok(InviteeRestriction::Pubkey { fingerprint });
    }
    if let Some(spec) = &args.invitee_cert {
        // Shape: <issuer_pubkey>:<subject1>,<subject2>,...
        // The issuer can itself contain ':' (e.g. `ed25519:<b64>`), so we
        // split on the LAST colon -- the cert spec puts subjects after
        // the rightmost colon, never inside. Subjects with embedded `:`
        // are unsupported in Phase 1.
        let (issuer, subjects) = spec.rsplit_once(':').ok_or_else(|| {
            format!(
                "--invitee-cert format is <issuer_pubkey>:<subject1,subject2,...> (got `{spec}`)",
            )
        })?;
        let issuer = issuer.trim().to_string();
        if issuer.is_empty() {
            return Err("--invitee-cert: issuer_pubkey must not be empty".into());
        }
        let allowed_subjects: Vec<String> = subjects
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if allowed_subjects.is_empty() {
            return Err("--invitee-cert: at least one subject is required".into());
        }
        return Ok(InviteeRestriction::Cert {
            issuer_pubkey: issuer,
            allowed_subjects,
        });
    }
    unreachable!("count > 0 above");
}

fn journal_dir_for_ctx(c: &ctx::Ctx) -> PathBuf {
    c.config_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("journals")
        .join("approval-use")
}

fn load_session_id_from_manifest() -> Option<String> {
    crate::commands::session::load_session().map(|m| m.session_id)
}

// ---------------------------------------------------------------------------
// `treeship session invite`
// ---------------------------------------------------------------------------

pub fn invite(
    ctx_override: Option<&str>,
    args: InviteArgs,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let c = ctx::open(ctx_override)?;

    // Resolve session id: use the explicit positional unless empty,
    // otherwise fall back to the active session manifest. Refuse if
    // both are absent.
    let session_id = if args.session_id.is_empty() {
        load_session_id_from_manifest().ok_or_else(|| {
            "no session id given and no active session manifest at .treeship/session.json"
                .to_string()
        })?
    } else {
        args.session_id.clone()
    };

    // Restriction parsing must happen before we touch the keystore so
    // operator typos surface fast.
    let restriction = parse_restriction(&args)?;

    // Capabilities default to a single tool.call entry when the operator
    // doesn't specify any, matching the spec's default room workflow.
    let capabilities = match args.capabilities.as_deref() {
        Some(s) => parse_capabilities(Some(s)),
        None => GrantedCapabilities {
            action_types: vec!["tool.call".into()],
        },
    };

    // Expiry: validate against the 7-day protocol max.
    let now = now_unix_secs();
    let lifetime = match args.expires.as_deref() {
        Some(s) => parse_duration_to_secs(s)?,
        None => DEFAULT_INVITATION_LIFETIME_SECS,
    };
    if lifetime > MAX_INVITATION_LIFETIME_SECS {
        return Err(format!(
            "--expires lifetime {lifetime}s exceeds protocol max {}s (7 days)",
            MAX_INVITATION_LIFETIME_SECS
        )
        .into());
    }
    let expires_at = treeship_core::statements::unix_to_rfc3339(now + lifetime);

    // Sign with the keystore's default key (the session's owning key).
    let host_signer = c.keys.default_signer()?;
    let issuer_b64 = URL_SAFE_NO_PAD.encode(host_signer.public_key_bytes());

    let nonce = generate_nonce();
    let invitation = InvitationStatement::new(
        session_id.clone(),
        issuer_b64.clone(),
        restriction.clone(),
        capabilities.clone(),
        expires_at.clone(),
        nonce.clone(),
    );

    // Validate before signing so the operator sees the error before
    // any side effect occurs.
    invitation
        .validate_for_mint(now)
        .map_err(|e| format!("invitation rejected at mint time: {e}"))?;

    // Sign via the DSSE envelope machinery so the invitation lives
    // alongside every other artifact under the same content-addressing
    // and verifier surface. The envelope's PAE-bound signature is what
    // the joiner verifies on `treeship session join`; the canonical
    // pipe-delimited form lives inside the payload's `canonical_for_signing`
    // and is what the InvitationStatement::verify_canonical path uses
    // when the joiner doesn't want to drag in the whole attestation
    // machinery (e.g. WASM verify-js).
    let sign_result =
        treeship_core::attestation::sign(&payload_type("invitation"), &invitation, &*host_signer)?;

    // Persist the invitation under the artifact store so the host can
    // refer to it later via artifact_id.
    let record = Record {
        artifact_id: sign_result.artifact_id.clone(),
        digest: sign_result.digest.clone(),
        payload_type: sign_result.envelope.payload_type.clone(),
        key_id: host_signer.key_id().to_string(),
        signed_at: now_rfc3339(),
        parent_id: None,
        envelope: sign_result.envelope.clone(),
        hub_url: None,
    };
    c.storage.write(&record)?;

    // Pre-register the invitation in the Approval Use Journal so a
    // racing host running `invite` twice with the same nonce can't
    // overwrite. The first journal entry is informational ("issued");
    // the join flow writes the actual "consumed" record. Phase 1 keeps
    // this implicit -- the journal-side write happens on consume to
    // keep the read shape symmetric with existing approval grants.

    // Build the bootstrap blob.
    let bundle = BootstrapBundle {
        v: 1,
        invitation_id: sign_result.artifact_id.clone(),
        envelope: sign_result.envelope.clone(),
    };
    let blob = if args.no_armor {
        serde_json::to_string_pretty(&bundle)?
    } else {
        encode_bootstrap_blob(&bundle)?
    };

    let format = Format::from_str(&args.format);
    if format == Format::Json {
        printer.json(&serde_json::json!({
            "status":         "ok",
            "invitation_id":  sign_result.artifact_id,
            "session_ref":    session_id,
            "issuer":         issuer_b64,
            "issuer_keyid":   host_signer.key_id(),
            "expires_at":     expires_at,
            "max_uses":       1,
            "bootstrap_blob": blob,
            "armored":        !args.no_armor,
        }));
        return Ok(());
    }

    printer.success(
        "invitation minted",
        &[
            ("invitation_id", &sign_result.artifact_id),
            ("session_ref", &session_id),
            ("expires_at", &expires_at),
            ("restriction", restriction_label(&restriction)),
        ],
    );
    printer.blank();
    printer.info("Send this blob to the joining agent:");
    // Write to stdout directly so the blob is machine-pasteable even
    // when printer adds decoration to info/success lines.
    println!("{blob}");
    printer.hint(&format!(
        "Joiner runs:  treeship session join --invite <paste> --actor agent://<their_id>"
    ));
    printer.hint(&format!(
        "Host countersigns:  treeship session countersign <participant_artifact_id>"
    ));
    Ok(())
}

fn restriction_label(r: &InviteeRestriction) -> &'static str {
    match r {
        InviteeRestriction::Pubkey { .. } => "pubkey",
        InviteeRestriction::Cert { .. } => "cert",
        InviteeRestriction::Open => "open",
    }
}

// ---------------------------------------------------------------------------
// `treeship session join`
// ---------------------------------------------------------------------------

pub fn join(
    ctx_override: Option<&str>,
    args: JoinArgs,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let c = ctx::open(ctx_override)?;

    // Resolve invitation blob from --invite (or stdin via '-'), or from
    // --invite-file.
    let blob_text = match (args.invite.as_deref(), args.invite_file.as_deref()) {
        (Some("-"), _) => {
            use std::io::Read;
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            s
        }
        (Some(s), _) => s.to_string(),
        (None, Some(p)) => {
            std::fs::read_to_string(p).map_err(|e| format!("read --invite-file {p}: {e}"))?
        }
        (None, None) => {
            return Err(
                "no invitation provided. Pass --invite <blob>, --invite -, or --invite-file <path>"
                    .into(),
            );
        }
    };
    let bundle = decode_bootstrap_blob(&blob_text)?;

    // Decode the embedded statement so we can run pre-flight checks.
    let invitation: InvitationStatement = bundle
        .envelope
        .unmarshal_statement()
        .map_err(|e| format!("invitation envelope payload decode: {e}"))?;
    if invitation.type_ != TYPE_INVITATION {
        return Err(format!(
            "envelope payload is not an invitation (got type={})",
            invitation.type_,
        )
        .into());
    }

    // Trust check: the issuer's pubkey must be pinned under SessionHost.
    let trust = TrustRootStore::open_default_or_empty()?;
    let issuer_pk_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(invitation.issuer.as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("invitation.issuer is not a 32-byte base64url Ed25519 pubkey")?;
    if !trust.contains_bytes(&issuer_pk_bytes, TrustRootKind::SessionHost) {
        return Err(format!(
            "invitation issuer pubkey is not pinned under SessionHost trust roots.\n\
             Add it with:  treeship trust add <key_id> ed25519:{} --kind session_host --yes",
            URL_SAFE_NO_PAD.encode(issuer_pk_bytes),
        )
        .into());
    }

    // Signature check via the DSSE envelope. The envelope's single
    // signature was made by the host over PAE(payload_type, payload).
    // We trust the issuer pubkey embedded in the invitation (which we
    // just gated on SessionHost trust roots above) against whatever
    // keyid the host signed under.
    let host_keyid = bundle
        .envelope
        .signatures
        .first()
        .map(|s| s.keyid.clone())
        .unwrap_or_else(|| "host".into());
    let issuer_vk = ed25519_dalek::VerifyingKey::from_bytes(&issuer_pk_bytes)
        .map_err(|e| format!("invitation issuer pubkey invalid: {e}"))?;
    treeship_core::attestation::verify_with_key(&bundle.envelope, &host_keyid, issuer_vk)
        .map_err(|e| format!("invitation envelope signature failed verification: {e}"))?;

    // Expiry.
    let now = now_unix_secs();
    if invitation.is_expired(now) {
        return Err(format!(
            "invitation expired at {} (now: {})",
            invitation.expires_at,
            treeship_core::statements::unix_to_rfc3339(now),
        )
        .into());
    }

    // Joining agent's signer.
    let joining_signer = c.keys.default_signer()?;
    let joiner_pk_b64 = URL_SAFE_NO_PAD.encode(joining_signer.public_key_bytes());
    let joiner_fingerprint = pubkey_fingerprint_short(&format!("ed25519:{}", joiner_pk_b64,));

    // Restriction check.
    let mut cert_ref: Option<String> = None;
    match &invitation.invitee_restriction {
        InviteeRestriction::Open => { /* unconditional */ }
        InviteeRestriction::Pubkey { fingerprint } => {
            if fingerprint != &joiner_fingerprint {
                return Err(format!(
                    "invitation is Pubkey-restricted to fingerprint {fingerprint}; \
                     this agent's fingerprint is {joiner_fingerprint}",
                )
                .into());
            }
        }
        InviteeRestriction::Cert {
            issuer_pubkey,
            allowed_subjects,
        } => {
            // Phase 1: cert presentation is checked by the operator via
            // a separate command (or out-of-band). We surface what's
            // required and refuse the join unless the env var
            // TREESHIP_AGENT_CERT_REF is set with the cert artifact id.
            // Future PRs land the keystore-side cert lookup.
            match std::env::var("TREESHIP_AGENT_CERT_REF") {
                Ok(id) if !id.is_empty() => {
                    cert_ref = Some(id);
                }
                _ => {
                    return Err(format!(
                        "invitation is Cert-restricted (issuer={issuer_pubkey}, \
                         subjects={:?}). Phase 1 join requires the joining agent's \
                         certificate artifact id in TREESHIP_AGENT_CERT_REF.",
                        allowed_subjects,
                    )
                    .into());
                }
            }
        }
    }

    // Consume-before-join: write the invitation's nonce into the
    // Approval Use Journal with max_uses=1. A second join attempt with
    // the same invitation fails here via JournalError::MaxUsesExceeded.
    let j_dir = journal_dir_for_ctx(&c);
    let j = Journal::new(&j_dir);
    let use_id = {
        // AUD-24: OS CSPRNG (policy §5), 16 bytes = 128 bits (was 64).
        let mut buf = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut buf);
        format!("use_inv_{}", hex::encode(buf))
    };
    let nonce_d = nonce_digest(&invitation.nonce);
    let use_record = ApprovalUse {
        type_: TYPE_APPROVAL_USE.into(),
        use_id: use_id.clone(),
        grant_id: bundle.invitation_id.clone(),
        grant_digest: digest_of_envelope(&bundle.envelope),
        nonce_digest: nonce_d.clone(),
        actor: args.actor.clone(),
        action: "session.join".into(),
        subject: invitation.session_ref.clone(),
        session_id: Some(invitation.session_ref.clone()),
        action_artifact_id: None,
        receipt_digest: None,
        use_number: 0,
        max_uses: Some(1),
        idempotency_key: None,
        created_at: now_rfc3339(),
        expires_at: Some(invitation.expires_at.clone()),
        previous_record_digest: String::new(),
        record_digest: String::new(),
        signature: None,
        signature_alg: None,
        signing_key_id: None,
    };
    journal::reserve_use(&j, use_record, Some(1))
        .map_err(|e| format!("invitation already consumed (or journal busy): {e}"))?;

    // Emit the participant event (single-sig, pending countersign).
    let participant = SessionParticipantStatement {
        type_: TYPE_SESSION_PARTICIPANT.into(),
        session_ref: invitation.session_ref.clone(),
        invitation_ref: bundle.invitation_id.clone(),
        joining_agent: joiner_pk_b64.clone(),
        joining_agent_cert_ref: cert_ref.clone(),
        joined_at: now_rfc3339(),
        capabilities: invitation.granted_capabilities.clone(),
    };
    let pending_env = participant
        .pending_envelope(&*joining_signer)
        .map_err(|e| format!("sign participant envelope: {e}"))?;

    // Persist as an artifact so the host can find it by id and
    // countersign without needing the joiner to ship the bytes
    // separately. The artifact id is the standard `art_<32hex>` shape
    // (`artifact_id_from_pae` truncates sha256 to 16 bytes); we hash
    // the pending envelope JSON to keep the id stable through the
    // countersign flow (the finalized envelope has different bytes
    // because of the extra signature, but it lands under the same id
    // so consumers that captured the id at join time still find it).
    let env_hash = sha2_digest(&serde_json::to_vec(&pending_env)?);
    let participant_id = format!("art_{}", hex::encode(&env_hash[..16]));
    let record = Record {
        artifact_id: participant_id.clone(),
        digest: digest_of_envelope(&pending_env),
        payload_type: pending_env.payload_type.clone(),
        key_id: joining_signer.key_id().to_string(),
        signed_at: now_rfc3339(),
        parent_id: Some(bundle.invitation_id.clone()),
        envelope: pending_env.clone(),
        hub_url: None,
    };
    c.storage.write(&record)?;

    let format = Format::from_str(&args.format);
    if format == Format::Json {
        printer.json(&serde_json::json!({
            "status":             "pending_countersign",
            "participant_id":     participant_id,
            "session_ref":        invitation.session_ref,
            "invitation_ref":     bundle.invitation_id,
            "joining_agent":      joiner_pk_b64,
            "joining_agent_fp":   joiner_fingerprint,
            "use_id":             use_id,
            "countersign_hint":   format!("treeship session countersign {}", participant_id),
        }));
        return Ok(());
    }

    printer.success(
        "invitation accepted; participant event signed",
        &[
            ("participant_id", &participant_id),
            ("session_ref", &invitation.session_ref),
            ("invitation_ref", &bundle.invitation_id),
            ("joining_agent", &joiner_pk_b64),
            ("joining_agent_fp", &joiner_fingerprint),
        ],
    );
    printer.blank();
    printer.warn(
        "participant event is PENDING the host's countersign",
        &[(
            "countersign_cmd",
            &format!("treeship session countersign {participant_id}"),
        )],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `treeship session countersign`
// ---------------------------------------------------------------------------

pub fn countersign(
    ctx_override: Option<&str>,
    args: CountersignArgs,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let c = ctx::open(ctx_override)?;

    // Read the pending participant artifact.
    let rec = c
        .storage
        .read(&args.participant_id)
        .map_err(|e| format!("participant artifact {}: {e}", args.participant_id))?;
    if rec.payload_type != payload_type("session-participant") {
        return Err(format!(
            "artifact {} is not a session-participant envelope (type={})",
            args.participant_id, rec.payload_type,
        )
        .into());
    }
    if rec.envelope.signatures.len() != 1 {
        return Err(format!(
            "participant artifact {} already has {} signatures; expected exactly 1 (pending)",
            args.participant_id,
            rec.envelope.signatures.len(),
        )
        .into());
    }

    // Decode the embedded statement so we can pull invitation_ref +
    // re-resolve the host pubkey it expects.
    let stmt: SessionParticipantStatement = rec
        .envelope
        .unmarshal_statement()
        .map_err(|e| format!("decode participant payload: {e}"))?;

    // Re-resolve the invitation so we can confirm the host that's
    // about to countersign matches the issuer the joining agent
    // verified at join time.
    let inv_rec = c
        .storage
        .read(&stmt.invitation_ref)
        .map_err(|e| format!("invitation artifact {}: {e}", stmt.invitation_ref))?;
    let invitation: InvitationStatement = inv_rec
        .envelope
        .unmarshal_statement()
        .map_err(|e| format!("decode invitation payload: {e}"))?;

    let host_signer = c.keys.default_signer()?;
    let host_pk_b64 = URL_SAFE_NO_PAD.encode(host_signer.public_key_bytes());
    if host_pk_b64 != invitation.issuer {
        return Err(format!(
            "default signing key ({}) does not match the invitation's issuer ({}); \
             countersign refused. The host must run this command on the same machine \
             that minted the invitation.",
            host_pk_b64, invitation.issuer,
        )
        .into());
    }

    // Re-derive the participant's terms from the TRUST-PINNED invitation.
    // countersign is the host's authorization gate; it must NOT trust the
    // bytes in the pending participant envelope. `join()` enforces expiry,
    // restriction, term-copying, and single-use consume — but `join()` is
    // just the honest CLI producing the pending envelope. A malicious joiner
    // (who holds their own signing key) can hand-craft a 1-signature
    // participant statement with inflated `capabilities` (e.g. add `admin.*`),
    // a different `session_ref`, or a `joining_agent` that fails the
    // invitation's restriction, and submit it straight to countersign. If we
    // only checked host==issuer, the host would bless it into a valid
    // 2-signature envelope claiming authority the invitation never granted.
    // Re-validate everything `join` validated, against the invitation.
    let now = now_unix_secs();
    if invitation.is_expired(now) {
        return Err(format!(
            "invitation expired at {} (now {}); countersign refused",
            invitation.expires_at,
            treeship_core::statements::unix_to_rfc3339(now),
        )
        .into());
    }
    if stmt.session_ref != invitation.session_ref {
        return Err(format!(
            "participant session_ref ({}) does not match the invitation's ({}); \
             countersign refused",
            stmt.session_ref, invitation.session_ref,
        )
        .into());
    }
    if stmt.capabilities != invitation.granted_capabilities {
        return Err(
            "participant capabilities do not match the invitation's granted_capabilities \
             (capability escalation attempt); countersign refused"
                .into(),
        );
    }
    match &invitation.invitee_restriction {
        InviteeRestriction::Open => {}
        InviteeRestriction::Pubkey { fingerprint } => {
            let joiner_fp = pubkey_fingerprint_short(&format!("ed25519:{}", stmt.joining_agent));
            if fingerprint != &joiner_fp {
                return Err(format!(
                    "participant joining_agent (fp {joiner_fp}) does not satisfy the \
                     invitation's Pubkey restriction (fp {fingerprint}); countersign refused"
                )
                .into());
            }
        }
        InviteeRestriction::Cert { .. } => {
            if stmt.joining_agent_cert_ref.is_none() {
                return Err(
                    "invitation is Cert-restricted but the participant carries no \
                     certificate reference; countersign refused"
                        .into(),
                );
            }
        }
    }
    // Single-use: the invitation nonce must ALREADY be consumed in the
    // Approval Use Journal (join consumes it with max_uses=1). This both
    // enforces single-use and forces the honest join path — a joiner who
    // hand-crafted a pending envelope to bypass join never consumed the
    // nonce, so there is no journal record and we refuse. `use_number` is
    // `consumed_count + 1`, so a consumed invitation reads >= 2.
    let j = Journal::new(&journal_dir_for_ctx(&c));
    let nonce_d = nonce_digest(&invitation.nonce);
    let replay = journal::check_replay(&j, &stmt.invitation_ref, &nonce_d, Some(1))
        .map_err(|e| format!("journal check failed: {e}"))?;
    let consumed = replay.use_number.map(|n| n >= 2).unwrap_or(false);
    if !consumed {
        return Err(
            "this invitation has not been consumed via `treeship session join` \
             (no single-use journal record) — countersign refused. A pending \
             participant envelope must come from a real join, not a hand-crafted \
             submission."
                .into(),
        );
    }

    let finalized =
        SessionParticipantStatement::attach_host_countersign(&rec.envelope, &*host_signer)
            .map_err(|e| format!("attach host countersign: {e}"))?;

    // Self-verify before persisting so we never write a broken envelope.
    verify_participant_envelope(&finalized, &invitation.issuer)
        .map_err(|e| format!("countersigned envelope failed self-verify: {e}"))?;

    // Overwrite the stored artifact with the finalized envelope. The
    // artifact id is the content hash of the pending envelope, NOT the
    // finalized one, so the id remains stable through the countersign.
    let new_record = Record {
        envelope: finalized.clone(),
        // Refresh the signed_at + digest. The artifact_id stays as-is
        // so consumers that captured the id at join time still find it.
        digest: digest_of_envelope(&finalized),
        signed_at: now_rfc3339(),
        ..rec
    };
    c.storage.write(&new_record)?;

    let format = Format::from_str(&args.format);
    if format == Format::Json {
        printer.json(&serde_json::json!({
            "status":          "finalized",
            "participant_id":  args.participant_id,
            "session_ref":     stmt.session_ref,
            "invitation_ref":  stmt.invitation_ref,
            "joining_agent":   stmt.joining_agent,
            "signatures":      2,
        }));
        return Ok(());
    }
    printer.success(
        "participant countersigned and finalized",
        &[
            ("participant_id", &args.participant_id),
            ("session_ref", &stmt.session_ref),
            ("invitation_ref", &stmt.invitation_ref),
        ],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Small local helpers
// ---------------------------------------------------------------------------

fn digest_of_envelope(env: &Envelope) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(env).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))
}

fn sha2_digest(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}

// Re-export `Path` so the unused-import warning doesn't fire above
// once any future helper drops Path from its signature.
#[allow(dead_code)]
fn _ensure_path_imported(_p: &Path) {}

// ---------------------------------------------------------------------------
// Tests (unit-level; CLI integration tests live in
// packages/cli/tests/invitation_cli.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_handles_suffixes() {
        assert_eq!(parse_duration_to_secs("30s").unwrap(), 30);
        assert_eq!(parse_duration_to_secs("5m").unwrap(), 300);
        assert_eq!(parse_duration_to_secs("1h").unwrap(), 3600);
        assert_eq!(parse_duration_to_secs("7d").unwrap(), 7 * 86_400);
        assert_eq!(parse_duration_to_secs("42").unwrap(), 42);
        assert!(parse_duration_to_secs("").is_err());
        assert!(parse_duration_to_secs("hello").is_err());
    }

    #[test]
    fn parse_restriction_requires_explicit_kind() {
        let args = InviteArgs {
            session_id: "ssn".into(),
            invitee_cert: None,
            invitee_pubkey: None,
            open: false,
            capabilities: None,
            expires: None,
            format: "text".into(),
            no_armor: false,
        };
        assert!(
            parse_restriction(&args).is_err(),
            "no restriction => must error"
        );
    }

    #[test]
    fn parse_restriction_open_explicit() {
        let args = InviteArgs {
            session_id: "ssn".into(),
            invitee_cert: None,
            invitee_pubkey: None,
            open: true,
            capabilities: None,
            expires: None,
            format: "text".into(),
            no_armor: false,
        };
        assert!(matches!(
            parse_restriction(&args).unwrap(),
            InviteeRestriction::Open
        ));
    }

    #[test]
    fn parse_restriction_cert_shape() {
        let args = InviteArgs {
            session_id: "ssn".into(),
            invitee_cert: Some("ed25519:ISSUER:org-x,org-y".into()),
            invitee_pubkey: None,
            open: false,
            capabilities: None,
            expires: None,
            format: "text".into(),
            no_armor: false,
        };
        match parse_restriction(&args).unwrap() {
            InviteeRestriction::Cert {
                issuer_pubkey,
                allowed_subjects,
            } => {
                assert_eq!(issuer_pubkey, "ed25519:ISSUER");
                assert_eq!(
                    allowed_subjects,
                    vec!["org-x".to_string(), "org-y".to_string()]
                );
            }
            other => panic!("expected Cert, got {other:?}"),
        }
    }

    #[test]
    fn bootstrap_blob_roundtrips() {
        // Minimal envelope with one signature.
        let env = Envelope {
            payload: URL_SAFE_NO_PAD.encode(b"{}"),
            payload_type: payload_type("invitation"),
            signatures: vec![treeship_core::attestation::Signature {
                keyid: "k".into(),
                sig: URL_SAFE_NO_PAD.encode([0u8; 64]),
            }],
        };
        let bundle = BootstrapBundle {
            v: 1,
            invitation_id: "art_test".into(),
            envelope: env,
        };
        let blob = encode_bootstrap_blob(&bundle).unwrap();
        assert!(blob.starts_with(BLOB_HEADER));
        assert!(blob.contains(BLOB_FOOTER));
        let back = decode_bootstrap_blob(&blob).unwrap();
        assert_eq!(back.invitation_id, "art_test");
    }
}
