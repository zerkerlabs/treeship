//! End-to-end integration tests for `treeship session invite|join|countersign`
//! (Phase 1 of docs/specs/agent-invitations-rooms.md).
//!
//! These tests build the CLI binary via `env!("CARGO_BIN_EXE_treeship")`
//! (provided by cargo for binaries in the same package) and exercise the
//! mint -> join -> countersign flow against an isolated `.treeship`
//! workspace in a tempdir. No state escapes the tempdir; tests run in
//! parallel safely.

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// Build a self-contained scratch workspace for one test: a tempdir, a
/// per-test config that points all paths inside it, and a HOME override
/// so the trust roots file lands inside the dir too.
struct Workspace {
    _tmp: TempDir,
    root: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        // Let `treeship init` create config.json itself; pre-writing
        // it triggers the "already initialized" guard.
        Self { _tmp: tmp, root }
    }

    fn config(&self) -> String {
        self.root
            .join(".treeship/config.json")
            .display()
            .to_string()
    }

    /// Returns a `Command` for the treeship binary, with HOME and
    /// TREESHIP_TRUST_ROOTS pinned inside the tempdir so we never
    /// touch the developer's real trust file. Also bypasses the
    /// `0o600` perm gate for trust files written under /tmp on some
    /// CI environments.
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
            .args(["--name", "invitation-test"])
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

    fn session_start(&self) -> String {
        let out = self
            .cmd()
            .args(["session", "start", "--config"])
            .arg(self.config())
            .args(["--name", "host_session"])
            .output()
            .expect("session start");
        if !out.status.success() {
            panic!(
                "session start failed: stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
        }
        // Read the session_id from the on-disk manifest. Keeps the
        // assertion textual-output-agnostic.
        let mut path = self.root.join(".treeship/session.json");
        if !path.exists() {
            // session start may put it elsewhere; walk up looking.
            path = self.root.join(".treeship").join("session.json");
        }
        let json: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&path).unwrap_or_else(|_| panic!("read {}", path.display())),
        )
        .unwrap();
        json["session_id"].as_str().expect("session_id").to_string()
    }

    /// Read the host's default pubkey by walking the keystore on disk.
    /// `keys list --format json` doesn't include the raw bytes (only
    /// fingerprint + id) so we read the per-key file directly. The
    /// public_key field is a JSON byte array; we decode + base64url it.
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

    fn read_session_id(&self) -> Option<String> {
        let path = self.root.join(".treeship/session.json");
        let bytes = std::fs::read(&path).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        v["session_id"].as_str().map(String::from)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Headline lifecycle: mint -> join -> countersign on a single workspace
/// (host + joiner share keys for simplicity; the restriction is `Open`
/// so the join is unconditional). The countersign step writes the
/// finalized envelope with two signatures.
#[test]
fn treeship_session_invite_then_join_roundtrip() {
    let ws = Workspace::new();
    ws.init();
    let session_id = ws.session_start();
    let pubkey = ws.default_pubkey_b64();
    ws.add_trust("host_default", &pubkey, "session_host");

    // Mint an open invitation (default 1h expiry).
    let invite_out = ws
        .cmd()
        .args(["session", "invite", &session_id, "--format", "json"])
        .args(["--open", "--config"])
        .arg(ws.config())
        .output()
        .expect("session invite");
    let stdout = String::from_utf8_lossy(&invite_out.stdout).to_string();
    assert!(
        invite_out.status.success(),
        "invite failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&invite_out.stderr),
    );
    let mint: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("invite stdout not JSON: {stdout}"));
    assert_eq!(mint["status"], "ok");
    let invitation_id = mint["invitation_id"]
        .as_str()
        .expect("invitation_id")
        .to_string();
    let blob = mint["bootstrap_blob"]
        .as_str()
        .expect("bootstrap_blob")
        .to_string();
    assert!(blob.contains("-----BEGIN TREESHIP INVITATION-----"));
    assert!(blob.contains("-----END TREESHIP INVITATION-----"));

    // Stash the blob in a file so we exercise --invite-file.
    let blob_path = ws.root.join("invite.blob");
    std::fs::write(&blob_path, &blob).unwrap();

    let join_out = ws
        .cmd()
        .args(["session", "join", "--format", "json"])
        .args(["--invite-file"])
        .arg(&blob_path)
        .args(["--actor", "agent://joiner"])
        .args(["--config"])
        .arg(ws.config())
        .output()
        .expect("session join");
    let stdout = String::from_utf8_lossy(&join_out.stdout).to_string();
    assert!(
        join_out.status.success(),
        "join failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&join_out.stderr),
    );
    let join: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("join stdout not JSON: {stdout}"));
    assert_eq!(join["status"], "pending_countersign");
    assert_eq!(join["invitation_ref"], invitation_id);
    let participant_id = join["participant_id"]
        .as_str()
        .expect("participant_id")
        .to_string();

    // Countersign as host. After this the participant artifact carries
    // two signatures and verifies as finalized.
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
    let stdout = String::from_utf8_lossy(&cs_out.stdout).to_string();
    assert!(
        cs_out.status.success(),
        "countersign failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&cs_out.stderr),
    );
    let cs: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("countersign stdout not JSON: {stdout}"));
    assert_eq!(cs["status"], "finalized");
    assert_eq!(cs["signatures"], 2);

    // Second join attempt with the SAME invitation must fail -- single
    // use enforced by the Approval Use Journal.
    let join2 = ws
        .cmd()
        .args(["session", "join", "--format", "json"])
        .args(["--invite-file"])
        .arg(&blob_path)
        .args(["--actor", "agent://joiner"])
        .args(["--config"])
        .arg(ws.config())
        .output()
        .expect("session join (replay)");
    assert!(
        !join2.status.success(),
        "second join of the same invitation must fail (single-use)"
    );
    let stderr = String::from_utf8_lossy(&join2.stderr).to_string();
    let stdout = String::from_utf8_lossy(&join2.stdout).to_string();
    let combined = format!("{stderr}{stdout}");
    assert!(
        combined.contains("already consumed") || combined.contains("MaxUsesExceeded"),
        "expected single-use rejection, got: {combined}",
    );
}

/// Invitation against a nonexistent / unrelated session id is still
/// mintable (Phase 1 doesn't validate session existence at the mint
/// site -- the host knows what session id they meant), but if we pass
/// an empty session id AND there's no active session, the command
/// errors with a clear message rather than minting with an empty ref.
#[test]
fn treeship_session_invite_rejects_no_session_context() {
    let ws = Workspace::new();
    ws.init();
    // No session start -- no session.json on disk.
    assert!(ws.read_session_id().is_none());

    let out = ws
        .cmd()
        .args(["session", "invite", "--format", "json"])
        .args(["--open", "--config"])
        .arg(ws.config())
        .output()
        .expect("session invite no-session");
    assert!(
        !out.status.success(),
        "invite with no session context must fail"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        combined.contains("no session id") || combined.contains("no active session"),
        "expected no-session error, got: {combined}",
    );
}

/// After join, the participant artifact exists in storage with exactly
/// one signature -- the "pending countersign" state. Until the host
/// runs `treeship session countersign`, the artifact is flagged as
/// awaiting the second sig. We assert the on-disk shape directly so
/// the test doesn't depend on a future "list pending" CLI surface.
#[test]
fn treeship_session_join_no_countersign_appears_pending() {
    let ws = Workspace::new();
    ws.init();
    let session_id = ws.session_start();
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
    let mint: serde_json::Value = serde_json::from_slice(&invite_out.stdout).unwrap();
    let blob = mint["bootstrap_blob"].as_str().unwrap().to_string();

    // Use the equals form so clap doesn't eagerly parse `-----BEGIN`
    // as an unknown flag. This is the documented contract for inline
    // blobs with dash-leading content; --invite-file works without
    // this dance.
    let invite_arg = format!("--invite={blob}");
    let join_out = ws
        .cmd()
        .args(["session", "join", "--format", "json"])
        .arg(&invite_arg)
        .args(["--actor", "agent://joiner"])
        .args(["--config"])
        .arg(ws.config())
        .output()
        .expect("session join");
    assert!(
        join_out.status.success(),
        "join failed: stdout={} stderr={}",
        String::from_utf8_lossy(&join_out.stdout),
        String::from_utf8_lossy(&join_out.stderr),
    );
    let join: serde_json::Value = serde_json::from_slice(&join_out.stdout).unwrap();
    let participant_id = join["participant_id"].as_str().unwrap().to_string();

    // Walk the storage dir for the artifact file. `treeship init`
    // points storage_dir at `<.treeship dir>/artifacts`.
    let storage_dir = ws.root.join(".treeship/artifacts");
    let artifact_path = storage_dir.join(format!("{participant_id}.json"));
    if !artifact_path.exists() {
        let mut listing = String::new();
        if let Ok(rd) = std::fs::read_dir(&storage_dir) {
            for e in rd.flatten() {
                listing.push_str(&format!("  {}\n", e.path().display()));
            }
        }
        panic!(
            "expected participant artifact at {} (join JSON: {}, storage listing:\n{})",
            artifact_path.display(),
            join,
            listing,
        );
    }
    let bytes = std::fs::read(&artifact_path).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let sigs = record["envelope"]["signatures"]
        .as_array()
        .expect("envelope.signatures array");
    assert_eq!(
        sigs.len(),
        1,
        "pending participant must carry exactly one signature; got {sigs:?}",
    );
}

// Belt-and-suspenders: ensure we don't leak state across tests via the
// shared parent process env. Each Workspace constructor is fresh, but
// pinning the HOME inside the tempdir means the developer's real
// `~/.treeship` is never touched even on a panicking test.
fn _assertion_state_isolation_documented(_root: &Path) {}
