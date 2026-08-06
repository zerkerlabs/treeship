//! End-to-end: the CLI itself emits an action/v2 receipt that `verify` can read.
//!
//! Verification-side coverage already plants envelopes by hand. Emission is the
//! half that was missing through 0.22 — without this test, a CLI user still
//! cannot produce a receipt that exercises the mandate/effect path we ship.

use std::path::PathBuf;
use std::process::Command;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tempfile::TempDir;
use treeship_core::{keys::Store as KeyStore, statements::Grant};

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
        let ws = Self { _tmp: tmp, root };
        let out = ws.cmd().args(["init"]).output().unwrap();
        assert!(
            out.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ws
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root);
        c.current_dir(&self.root);
        c
    }

    fn keys_dir(&self) -> PathBuf {
        self.root.join(".treeship/keys")
    }

    fn grants_dir(&self) -> PathBuf {
        self.root.join(".treeship/grants")
    }

    /// Mint a root grant the same way `grant issue` will, written into the
    /// workspace store so `--grant <id>` can load it.
    fn plant_grant(&self, scope: &[&str], audience: &str, expiry: &str) -> Grant {
        let keys = KeyStore::open(self.keys_dir()).expect("open keystore");
        let signer = keys.default_signer().expect("default key");
        // issued_at well in the past so the mandate window check is not the
        // story regardless of the host clock; expiry is caller-chosen.
        let mut g = Grant {
            grant_id: String::new(),
            grantor: URL_SAFE_NO_PAD.encode(signer.public_key_bytes()),
            // Bound to the same key that signs the receipts in this suite, so
            // these fixtures exercise the holder-bound path rather than bearer.
            grantee: Some(URL_SAFE_NO_PAD.encode(signer.public_key_bytes())),
            issuer_sig: None,
            scope: scope.iter().map(|s| (*s).to_string()).collect(),
            audience: audience.into(),
            parent_request_id: None,
            parent_grant_id: None,
            delegation_depth: 0,
            issued_at: "2020-01-01T00:00:00Z".into(),
            expiry: expiry.into(),
            max_delegation: 3,
            objective_hash: None,
        };
        g.grant_id = g.derive_grant_id();
        g.issuer_sig = Some(g.sign_canonical(signer.as_ref()).unwrap());

        let dir = self.grants_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("{}.json", g.grant_id)),
            serde_json::to_string_pretty(&g).unwrap(),
        )
        .unwrap();
        g
    }

    fn verify_json(&self, id: &str) -> serde_json::Value {
        let out = self
            .cmd()
            .args(["verify", id, "--format", "json"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "verify failed: {}\n{}",
            String::from_utf8_lossy(&out.stderr),
            stdout
        );
        serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("verify emitted non-JSON ({e}): {stdout}"))
    }
}

#[test]
fn cli_emits_action_v2_that_verify_reads() {
    let ws = Workspace::new();
    let grant = ws.plant_grant(&["payments.charge"], "acme", "2099-01-01T00:00:00Z");

    let out = ws
        .cmd()
        .args([
            "--format",
            "json",
            "attest",
            "action",
            "--v2",
            "--actor",
            "agent://worker",
            "--action",
            "payments.charge",
            "--grant",
            &grant.grant_id,
            "--effect-confidence",
            "not_verified",
            "--finality",
            "initiated",
            "--provider",
            "anthropic",
            "--model",
            "claude-opus-4",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "attest action --v2 failed: {stderr}\n{stdout}"
    );

    let emitted: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("non-JSON attest ({e}): {stdout}"));
    let id = emitted["id"]
        .as_str()
        .unwrap_or_else(|| panic!("attest JSON missing id: {emitted}"));
    assert_eq!(emitted["type"], "action/v2");
    assert_eq!(emitted["grant"], grant.grant_id);

    let j = ws.verify_json(id);
    let check = &j["checks"][0];

    // Signature must verify — emission wrote a real DSSE envelope.
    assert_eq!(
        check["outcome"], "pass",
        "emitted v2 receipt must verify: {j}"
    );

    // Authority is unverified without a revocation resolver — never a false pass.
    assert_eq!(
        check["authority"]["outcome"], "unverified",
        "authority must be unverified without a revocation resolver: {j}"
    );

    // Effect claim reaches verify (kebab label on the machine surface).
    assert_eq!(
        check["effect"]["claimed_confidence"], "not-verified",
        "effect claim should surface: {j}"
    );
    assert_eq!(
        check["effect"]["claimed_finality"], "initiated",
        "finality claim should surface: {j}"
    );

    // Runtime is bound into the signed payload; the human timeline surfaces it.
    let text = ws
        .cmd()
        .args(["verify", id, "--full"])
        .output()
        .unwrap();
    let text_out = format!(
        "{}{}",
        String::from_utf8_lossy(&text.stdout),
        String::from_utf8_lossy(&text.stderr)
    );
    assert!(
        text_out.contains("claude-opus-4"),
        "runtime model should appear on verify --full timeline: {text_out}"
    );
}

#[test]
fn v2_without_grant_is_refused() {
    let ws = Workspace::new();
    let out = ws
        .cmd()
        .args([
            "attest",
            "action",
            "--v2",
            "--actor",
            "agent://worker",
            "--action",
            "payments.charge",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "must refuse --v2 without a grant");
    let err = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        err.contains("--grant") || err.contains("grant-file"),
        "error should name the missing grant flag: {err}"
    );
}

#[test]
fn root_grant_reports_delegation_not_claimed() {
    // A single-hop grant never asserted lineage. Stuffing the leaf into
    // mandate.chain would make verify report `holds` for a check that
    // never ran — the honesty bug caught in the grant-issue × emit integration.
    let ws = Workspace::new();
    let grant = ws.plant_grant(&["tool.call"], "local", "2099-01-01T00:00:00Z");
    assert!(
        grant.parent_grant_id.is_none(),
        "plant_grant must mint a root"
    );

    let out = ws
        .cmd()
        .args([
            "--format",
            "json",
            "attest",
            "action",
            "--v2",
            "--actor",
            "agent://worker",
            "--action",
            "tool.call",
            "--grant",
            &grant.grant_id,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "attest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let emitted: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let id = emitted["id"].as_str().unwrap();

    let j = ws.verify_json(id);
    assert_eq!(
        j["checks"][0]["delegation_chain"]["outcome"], "not_claimed",
        "root grant must not claim a holding chain: {j}"
    );
}

#[test]
fn grant_file_emits_without_workspace_store() {
    let ws = Workspace::new();
    let grant = ws.plant_grant(&["tool.call"], "local", "2099-01-01T00:00:00Z");
    let grant_path = ws.grants_dir().join(format!("{}.json", grant.grant_id));

    // Move it out of the store so --grant would fail; --grant-file must work.
    let external = ws.root.join("external-grant.json");
    std::fs::rename(&grant_path, &external).unwrap();

    let out = ws
        .cmd()
        .args([
            "--format",
            "json",
            "attest",
            "action",
            "--v2",
            "--actor",
            "agent://worker",
            "--action",
            "tool.call",
            "--grant-file",
            external.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "attest --grant-file failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let emitted: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout))
        .expect("attest JSON");
    assert_eq!(emitted["type"], "action/v2");
    assert_eq!(emitted["status"], "ok");
}
