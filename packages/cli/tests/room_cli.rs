//! End-to-end integration tests for `treeship room create|status|participants`
//! (Phase 2 of docs/specs/agent-invitations-rooms.md).
//!
//! Mirrors the `Workspace` helper pattern in `invitation_cli.rs`: an
//! isolated `.treeship` workspace per test, built via the real CLI binary,
//! so nothing leaks into the developer's real `~/.treeship`.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Workspace {
    _tmp: TempDir,
    root: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Self { _tmp: tmp, root }
    }

    fn config(&self) -> String {
        self.root
            .join(".treeship/config.json")
            .display()
            .to_string()
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root);
        c.env(
            "TREESHIP_TRUST_ROOTS",
            self.root
                .join(".treeship/trust_roots.json")
                .display()
                .to_string(),
        );
        c.env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1");
        c.current_dir(&self.root);
        c
    }

    fn init(&self) {
        let out = self
            .cmd()
            .args(["init", "--config"])
            .arg(self.config())
            .args(["--name", "room-test"])
            .output()
            .expect("treeship init");
        if !out.status.success() {
            panic!(
                "init failed: stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
        }
    }

    fn default_pubkey_b64(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let keys_dir = self.root.join(".treeship/keys");
        let manifest_path = keys_dir.join("manifest.json");
        let manifest_bytes = std::fs::read(&manifest_path)
            .unwrap_or_else(|e| panic!("read keystore manifest {}: {e}", manifest_path.display()));
        let manifest: serde_json::Value =
            serde_json::from_slice(&manifest_bytes).expect("manifest parses as JSON");
        let default_id = manifest["default_key_id"]
            .as_str()
            .expect("manifest has default_key_id");
        let key_path = keys_dir.join(format!("{default_id}.json"));
        let key_bytes = std::fs::read(&key_path)
            .unwrap_or_else(|e| panic!("read key file {}: {e}", key_path.display()));
        let entry: serde_json::Value =
            serde_json::from_slice(&key_bytes).expect("key file parses as JSON");
        let pk_array = entry["public_key"].as_array().expect("public_key is array");
        let pk: Vec<u8> = pk_array
            .iter()
            .map(|n| n.as_u64().expect("byte") as u8)
            .collect();
        assert_eq!(pk.len(), 32, "Ed25519 public key must be 32 bytes");
        URL_SAFE_NO_PAD.encode(&pk)
    }

    fn add_trust(&self, key_id: &str, pubkey_b64url: &str, kind: &str) {
        let canonical = format!("ed25519:{}", pubkey_b64url);
        let out = self
            .cmd()
            .args([
                "trust", "add", key_id, &canonical, "--kind", kind, "--yes", "--format", "json",
            ])
            .output()
            .expect("trust add");
        if !out.status.success() {
            panic!(
                "trust add failed: stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
        }
    }

    fn session_json(&self) -> serde_json::Value {
        let path = self.root.join(".treeship/session.json");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&bytes).unwrap()
    }
}

// ---------------------------------------------------------------------------
// room create
// ---------------------------------------------------------------------------

/// `room create` populates `SessionManifest.room` with sane defaults:
/// a fresh room_id, the default signer's pubkey as host_pubkey, and
/// HostOnly invitation authority when no flag overrides it.
#[test]
fn room_create_populates_room_info() {
    let ws = Workspace::new();
    ws.init();

    let out = ws
        .cmd()
        .args(["room", "create", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room create");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "room create failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    // Exactly one JSON document on stdout -- the inner `session::start`
    // call must not have also printed its own JSON object.
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("not a single JSON doc: {stdout}"));
    assert_eq!(parsed["status"], "ok");
    let room_id = parsed["room_id"].as_str().expect("room_id").to_string();
    assert!(room_id.starts_with("room_"));
    let session_id = parsed["session_id"]
        .as_str()
        .expect("session_id")
        .to_string();
    assert!(session_id.starts_with("ssn_"));

    let manifest = ws.session_json();
    assert_eq!(manifest["session_id"], session_id);
    let room = &manifest["room"];
    assert_eq!(room["room_id"], room_id);
    assert_eq!(room["invitation_authority"]["kind"], "host_only");
    assert!(room["host_pubkey"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(room["participants"].as_array().map(|a| a.len()), None); // omitted when empty
}

/// `--checkpoint-every` rejects non-numeric input, including the old
/// stringly-typed "50actions" form the field was specifically typed as
/// u32 to prevent.
#[test]
fn room_create_rejects_stringly_typed_checkpoint_every() {
    let ws = Workspace::new();
    ws.init();

    let out = ws
        .cmd()
        .args(["room", "create", "--checkpoint-every", "50actions"])
        .args(["--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room create");
    assert!(
        !out.status.success(),
        "room create with --checkpoint-every 50actions must fail"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        combined.contains("plain integer") || combined.contains("u32"),
        "expected a clear rejection message, got: {combined}",
    );

    // No session should have been started -- parsing failures happen
    // before any side effect.
    assert!(!ws.root.join(".treeship/session.json").exists());
}

#[test]
fn room_create_rejects_non_numeric_checkpoint_every() {
    let ws = Workspace::new();
    ws.init();

    let out = ws
        .cmd()
        .args(["room", "create", "--checkpoint-every", "fifty"])
        .args(["--config"])
        .arg(ws.config())
        .output()
        .expect("room create");
    assert!(!out.status.success());
}

/// `--invitation-authority delegated` requires at least one `--delegate`.
#[test]
fn room_create_delegated_requires_delegate() {
    let ws = Workspace::new();
    ws.init();

    let out = ws
        .cmd()
        .args(["room", "create", "--invitation-authority", "delegated"])
        .args(["--config"])
        .arg(ws.config())
        .output()
        .expect("room create");
    assert!(!out.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(combined.contains("--delegate"), "got: {combined}");
}

#[test]
fn room_create_delegated_with_delegate_succeeds() {
    let ws = Workspace::new();
    ws.init();

    let out = ws
        .cmd()
        .args([
            "room",
            "create",
            "--invitation-authority",
            "delegated",
            "--delegate",
            "ed25519:deadbeef",
        ])
        .args(["--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room create");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let manifest = ws.session_json();
    let authority = &manifest["room"]["invitation_authority"];
    assert_eq!(authority["kind"], "delegated_to");
    assert_eq!(authority["delegates"].as_array().map(|a| a.len()), Some(1));
}

// ---------------------------------------------------------------------------
// room status
// ---------------------------------------------------------------------------

/// `room status` errors clearly when the active session is a plain
/// session (not created via `room create`), instead of silently printing
/// session-only info.
#[test]
fn room_status_errors_on_non_room_session() {
    let ws = Workspace::new();
    ws.init();

    let start = ws
        .cmd()
        .args(["session", "start", "--config"])
        .arg(ws.config())
        .output()
        .expect("session start");
    assert!(start.status.success());

    let out = ws
        .cmd()
        .args(["room", "status", "--config"])
        .arg(ws.config())
        .output()
        .expect("room status");
    assert!(
        !out.status.success(),
        "room status on a non-room session must fail"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        combined.contains("no active room"),
        "expected a clear no-active-room error, got: {combined}",
    );
}

/// `room status` errors clearly when there is no active session at all.
#[test]
fn room_status_errors_on_no_session() {
    let ws = Workspace::new();
    ws.init();

    let out = ws
        .cmd()
        .args(["room", "status", "--config"])
        .arg(ws.config())
        .output()
        .expect("room status");
    assert!(!out.status.success());
}

/// `room status` succeeds and reports room fields when the session was
/// created via `room create`.
#[test]
fn room_status_reports_room_fields() {
    let ws = Workspace::new();
    ws.init();

    let create_out = ws
        .cmd()
        .args(["room", "create", "--workflow-ref", "wf_test"])
        .args(["--checkpoint-every", "25"])
        .args(["--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room create");
    assert!(create_out.status.success());
    let created: serde_json::Value = serde_json::from_slice(&create_out.stdout).unwrap();
    let room_id = created["room_id"].as_str().unwrap().to_string();

    let status_out = ws
        .cmd()
        .args(["room", "status", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room status");
    assert!(
        status_out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&status_out.stdout),
        String::from_utf8_lossy(&status_out.stderr),
    );
    let body: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(body["room"]["room_id"], room_id);
    assert_eq!(body["room"]["workflow_ref"], "wf_test");
    assert_eq!(body["room"]["checkpoint_every_actions"], 25);
    assert_eq!(body["room"]["participant_count"], 0);
}

// ---------------------------------------------------------------------------
// room participants (full invite -> join -> countersign cycle)
// ---------------------------------------------------------------------------

/// After a full invite -> join -> countersign cycle, `room participants`
/// shows the finalized participant, proving `countersign` wires the
/// participant id into `room.participants`.
#[test]
fn room_participants_shows_finalized_join_after_full_cycle() {
    let ws = Workspace::new();
    ws.init();

    let register = ws
        .cmd()
        .args(["agent", "register", "--name", "bob", "--own-key"])
        .output()
        .expect("register joining agent");
    assert!(
        register.status.success(),
        "register bob failed: stdout={} stderr={}",
        String::from_utf8_lossy(&register.stdout),
        String::from_utf8_lossy(&register.stderr),
    );

    // Before the room exists, participants must refuse (no active room).
    let too_early = ws
        .cmd()
        .args(["room", "participants", "--config"])
        .arg(ws.config())
        .output()
        .expect("room participants (too early)");
    assert!(!too_early.status.success());

    let create_out = ws
        .cmd()
        .args(["room", "create", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room create");
    assert!(create_out.status.success());
    let created: serde_json::Value = serde_json::from_slice(&create_out.stdout).unwrap();
    let session_id = created["session_id"].as_str().unwrap().to_string();
    let room_id = created["room_id"].as_str().unwrap().to_string();

    let pubkey = ws.default_pubkey_b64();
    ws.add_trust("host_default", &pubkey, "session_host");

    // Room with zero participants: valid, empty list.
    let empty_status = ws
        .cmd()
        .args(["room", "participants", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room participants (empty)");
    assert!(empty_status.status.success());
    let empty: serde_json::Value = serde_json::from_slice(&empty_status.stdout).unwrap();
    assert_eq!(empty["count"], 0);
    assert_eq!(empty["participants"].as_array().unwrap().len(), 0);

    // Mint an open invitation for the room's session.
    let invite_out = ws
        .cmd()
        .args(["session", "invite", &session_id, "--format", "json"])
        .args(["--open", "--config"])
        .arg(ws.config())
        .output()
        .expect("session invite");
    assert!(
        invite_out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&invite_out.stdout),
        String::from_utf8_lossy(&invite_out.stderr),
    );
    let mint: serde_json::Value = serde_json::from_slice(&invite_out.stdout).unwrap();
    let blob = mint["bootstrap_blob"].as_str().unwrap().to_string();
    let blob_path = ws.root.join("invite.blob");
    std::fs::write(&blob_path, &blob).unwrap();

    // Join as a different agent.
    let join_out = ws
        .cmd()
        .args(["session", "join", "--format", "json"])
        .args(["--invite-file"])
        .arg(&blob_path)
        .args(["--actor", "agent://joiner", "--config"])
        .arg(ws.config())
        .output()
        .expect("session join");
    assert!(
        join_out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&join_out.stdout),
        String::from_utf8_lossy(&join_out.stderr),
    );
    let join: serde_json::Value = serde_json::from_slice(&join_out.stdout).unwrap();
    let participant_id = join["participant_id"].as_str().unwrap().to_string();

    // Before countersign, the room's participant list is still empty --
    // only FINALIZED (two-sig) joins show up.
    let pending_status = ws
        .cmd()
        .args(["room", "participants", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room participants (pending)");
    assert!(pending_status.status.success());
    let pending: serde_json::Value = serde_json::from_slice(&pending_status.stdout).unwrap();
    assert_eq!(
        pending["count"], 0,
        "pending (uncountersigned) join must not appear yet"
    );

    // Countersign as host -- this is the plumbing under test: it must
    // wire the participant id into room.participants.
    let cs_out = ws
        .cmd()
        .args([
            "session",
            "countersign",
            &participant_id,
            "--format",
            "json",
        ])
        .args(["--config"])
        .arg(ws.config())
        .output()
        .expect("session countersign");
    assert!(
        cs_out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&cs_out.stdout),
        String::from_utf8_lossy(&cs_out.stderr),
    );

    // Manifest on disk must now carry the participant id.
    let manifest = ws.session_json();
    let room_participants = manifest["room"]["participants"].as_array().unwrap();
    assert_eq!(room_participants.len(), 1);
    assert_eq!(room_participants[0], participant_id);

    // `room participants` must now show the finalized join with decoded
    // statement fields.
    let final_status = ws
        .cmd()
        .args(["room", "participants", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room participants (final)");
    assert!(final_status.status.success());
    let final_body: serde_json::Value = serde_json::from_slice(&final_status.stdout).unwrap();
    assert_eq!(final_body["room_id"], room_id);
    assert_eq!(final_body["session_id"], session_id);
    assert_eq!(final_body["count"], 1);
    let entries = final_body["participants"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["participant_id"], participant_id);
    assert!(entries[0]["joining_agent"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert!(entries[0]["joined_at"].as_str().is_some());
    assert_eq!(
        entries[0]["capabilities"].as_array().unwrap(),
        &[serde_json::Value::String("tool.call".into())]
    );
}

// ---------------------------------------------------------------------------
// the roster is derived, not read from session.json
// ---------------------------------------------------------------------------

/// `room` rides inside the DSSE-signed session receipt, so whatever
/// `room participants` reports becomes an attested membership claim.
/// `room.participants` in session.json is a plain editable list, so the
/// roster must NOT come from it.
///
/// Writes two fabricated ids into `room.participants` -- the exact edit
/// available to anyone who can write the file -- and asserts the roster
/// stays empty. If this test ever fails, membership is forgeable with a
/// text editor.
#[test]
fn fabricated_participant_ids_in_session_json_do_not_become_members() {
    let ws = Workspace::new();
    ws.init();

    let create_out = ws
        .cmd()
        .args(["room", "create", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room create");
    assert!(create_out.status.success());

    // Forge membership the cheap way: edit the file.
    let path = ws.root.join(".treeship/session.json");
    let mut manifest = ws.session_json();
    manifest["room"]["participants"] = serde_json::json!([
        "art_forged000000000000000000000000",
        "art_forged111111111111111111111111",
    ]);
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    let out = ws
        .cmd()
        .args(["room", "participants", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room participants");

    // Must succeed: a forged list is not a crash, it is simply not evidence.
    // (Reading the list would instead have errored on the missing artifacts,
    // which is a different -- and still wrong -- behavior.)
    assert!(
        out.status.success(),
        "room participants failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        body["count"], 0,
        "fabricated ids in session.json became members: {body}"
    );
    assert_eq!(body["participants"].as_array().unwrap().len(), 0);
}

/// The inverse: a real countersigned participant must still be reported
/// even when `room.participants` was emptied. Membership comes from the
/// two-signature artifact, so deleting the cache cannot un-member anyone
/// -- otherwise the same editor that can't add members could silently
/// remove them, which is the same forgery in the other direction.
#[test]
fn clearing_the_cached_list_does_not_drop_a_real_member() {
    let ws = Workspace::new();
    ws.init();

    let register = ws
        .cmd()
        .args(["agent", "register", "--name", "bob", "--own-key"])
        .output()
        .expect("register joining agent");
    assert!(register.status.success());

    let create_out = ws
        .cmd()
        .args(["room", "create", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room create");
    assert!(create_out.status.success());
    let created: serde_json::Value = serde_json::from_slice(&create_out.stdout).unwrap();
    let session_id = created["session_id"].as_str().unwrap().to_string();

    let pubkey = ws.default_pubkey_b64();
    ws.add_trust("host_default", &pubkey, "session_host");

    let invite_out = ws
        .cmd()
        .args(["session", "invite", &session_id, "--format", "json"])
        .args(["--open", "--config"])
        .arg(ws.config())
        .output()
        .expect("session invite");
    assert!(invite_out.status.success());
    let invite: serde_json::Value = serde_json::from_slice(&invite_out.stdout).unwrap();
    let blob = invite["bootstrap_blob"].as_str().unwrap().to_string();
    let blob_path = ws.root.join("invite-clear.blob");
    std::fs::write(&blob_path, &blob).unwrap();

    let join_out = ws
        .cmd()
        .args(["session", "join", "--invite-file"])
        .arg(&blob_path)
        .args(["--actor", "agent://bob", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("session join");
    assert!(
        join_out.status.success(),
        "join failed: {}",
        String::from_utf8_lossy(&join_out.stderr)
    );
    let joined: serde_json::Value = serde_json::from_slice(&join_out.stdout).unwrap();
    let participant_id = joined["participant_id"].as_str().unwrap().to_string();

    let cs = ws
        .cmd()
        .args(["session", "countersign", &participant_id])
        .args(["--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("countersign");
    assert!(
        cs.status.success(),
        "countersign failed: {}",
        String::from_utf8_lossy(&cs.stderr)
    );

    // Wipe the cache. The signed artifact is untouched.
    let path = ws.root.join(".treeship/session.json");
    let mut manifest = ws.session_json();
    manifest["room"]["participants"] = serde_json::json!([]);
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    let out = ws
        .cmd()
        .args(["room", "participants", "--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .expect("room participants");
    assert!(out.status.success());
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        body["count"], 1,
        "clearing the cached list dropped a countersigned member: {body}"
    );
    assert_eq!(body["participants"][0]["participant_id"], participant_id);
}
