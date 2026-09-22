//! The kill switch end to end: `treeship halt` signs a halt.v1 receipt and
//! writes a marker, `halt list` reports it as honoured, `--lift` signs the
//! lift and clears it, and a marker without a signed artifact from this
//! workspace is reported as ignored.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Ws {
    _tmp: TempDir,
    root: PathBuf,
}

impl Ws {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let ws = Self { _tmp: tmp, root };
        assert!(ws
            .cmd()
            .args(["init", "--name", "ws", "--config"])
            .arg(ws.config())
            .status()
            .unwrap()
            .success());
        ws
    }
    fn config(&self) -> PathBuf {
        self.root.join(".treeship/config.json")
    }
    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .env("TREESHIP_TRUST_ROOTS", self.root.join("trust_roots.json"))
            .current_dir(&self.root);
        c
    }
    fn run(&self, args: &[&str]) -> (bool, String) {
        let out = self
            .cmd()
            .args(args)
            .args(["--config"])
            .arg(self.config())
            .output()
            .unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }
}

#[test]
fn halt_then_lift_are_signed_and_sealed_in_the_session() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "k",
        "--actor",
        "agent://claude-code",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://claude-code",
        "--action",
        "tool.call",
    ]);
    assert!(ok, "{out}");

    let (ok, out) = ws.run(&[
        "halt",
        "agent://claude-code",
        "--reason",
        "off-task",
        "--format",
        "json",
    ]);
    assert!(ok, "halt: {out}");
    let halted: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(halted["status"], "halted");
    let halt_id = halted["halt"].as_str().unwrap().to_string();
    assert!(halt_id.starts_with("art_"));

    let (ok, out) = ws.run(&["halt", "list", "--format", "json"]);
    assert!(ok, "{out}");
    let list: Value = serde_json::from_str(out.trim()).unwrap();
    let rows = list["halts"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["actor"], "agent://claude-code");
    assert_eq!(rows[0]["honoured"], true);

    // A second halt on the same actor is refused until lifted.
    let (ok, out) = ws.run(&["halt", "agent://claude-code"]);
    assert!(!ok, "{out}");
    assert!(out.contains("already halted"), "{out}");

    let (ok, out) = ws.run(&["halt", "--lift", "agent://claude-code", "--format", "json"]);
    assert!(ok, "lift: {out}");
    let lifted: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(lifted["status"], "lifted");
    assert_eq!(lifted["halt"], halt_id);
    let lift_id = lifted["lift"].as_str().unwrap().to_string();

    let (ok, out) = ws.run(&["halt", "list", "--format", "json"]);
    assert!(ok, "{out}");
    assert_eq!(
        serde_json::from_str::<Value>(out.trim()).unwrap()["halts"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Both orders are on the session chain and the sealed package verifies.
    let (ok, out) = ws.run(&["verify", &lift_id, "--full"]);
    assert!(ok, "{out}");
    assert!(
        out.contains(&halt_id[..16]),
        "the lift should walk to the halt: {out}"
    );
    let (ok, out) = ws.run(&["session", "close", "--headline", "k", "--format", "json"]);
    assert!(ok, "{out}");
    let pkg = serde_json::from_str::<Value>(out.trim()).unwrap()["package"]
        .as_str()
        .unwrap()
        .to_string();
    let (ok, out) = ws.run(&["package", "verify", &pkg]);
    assert!(ok, "{out}");
    let receipt: Value = serde_json::from_str(
        &std::fs::read_to_string(PathBuf::from(&pkg).join("receipt.json")).unwrap(),
    )
    .unwrap();
    let ids: Vec<&str> = receipt["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["artifact_id"].as_str())
        .collect();
    assert!(
        ids.contains(&halt_id.as_str()) && ids.contains(&lift_id.as_str()),
        "{ids:?}"
    );
}

#[test]
fn a_forged_marker_without_a_signed_artifact_is_ignored() {
    let ws = Ws::new();
    let dir = ws.root.join(".treeship/halts");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("agent___mallory.json"),
        r#"{"actor":"agent://mallory","halt":"art_00000000000000000000000000000000","issued_at":"2026-09-18T10:00:00Z","reason":null,"key_id":"key_x"}"#,
    )
    .unwrap();
    let (ok, out) = ws.run(&["halt", "list", "--format", "json"]);
    assert!(ok, "{out}");
    let list: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(list["halts"][0]["honoured"], false, "{list}");
}

#[test]
fn halt_requires_an_actor_uri_or_star() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["halt", "claude-code"]);
    assert!(!ok);
    assert!(out.contains("agent://claude-code"), "{out}");
    let (ok, out) = ws.run(&["halt", "*", "--format", "json"]);
    assert!(ok, "{out}");
    assert_eq!(
        serde_json::from_str::<Value>(out.trim()).unwrap()["actor"],
        "*"
    );
}
