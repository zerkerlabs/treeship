//! Network scope: `treeship declare --network` puts a host allow-list in the
//! declaration, `session start` copies it into the manifest, and the sealed
//! receipt judges every recorded destination against it. `package verify`
//! reports the judgement as the `network_scope` row. No scope declared means
//! no judgement, never a silent all-clear.

use std::path::PathBuf;
use std::process::Command;

use serde::Deserialize;
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

fn first_json(out: &str) -> Value {
    let start = out.find('{').expect("json object in output");
    let mut de = serde_json::Deserializer::from_str(&out[start..]);
    Value::deserialize(&mut de).expect("parse json")
}

fn connect(ws: &Ws, host: &str) {
    let (ok, out) = ws.run(&[
        "session",
        "event",
        "--type",
        "agent.connected_network",
        "--destination",
        host,
        "--agent-name",
        "ci",
    ]);
    assert!(ok, "{out}");
}

fn close_and_read(ws: &Ws) -> (Value, PathBuf) {
    let (ok, out) = ws.run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let close = first_json(&out);
    let pkg = PathBuf::from(close["package"].as_str().unwrap());
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    (receipt, pkg)
}

fn row<'a>(verdict: &'a Value, name: &str) -> Option<&'a Value> {
    verdict["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
}

#[test]
fn declared_scope_is_sealed_and_off_scope_hosts_are_named() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "declare",
        "--tools",
        "read_file,web_fetch",
        "--network",
        "api.example.com,*.internal.net",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["declare", "--show"]);
    assert!(ok, "{out}");
    assert!(out.contains("api.example.com"), "{out}");

    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ci"]);
    assert!(ok, "{out}");
    connect(&ws, "api.example.com");
    connect(&ws, "db.internal.net");
    connect(&ws, "evil.example.com");
    let (receipt, pkg) = close_and_read(&ws);

    let tu = &receipt["tool_usage"];
    assert_eq!(
        tu["network_declared"],
        serde_json::json!(["api.example.com", "*.internal.net"])
    );
    assert_eq!(
        tu["network_off_scope"],
        serde_json::json!(["evil.example.com"])
    );
    assert_eq!(
        receipt["side_effects"]["network_connections"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    let (ok, out) = ws.run(&[
        "package",
        "verify",
        pkg.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let verdict = first_json(&out);
    let r = row(&verdict, "network_scope").expect("network_scope row");
    assert_eq!(r["status"], "warn", "{r}");
    let detail = r["detail"].as_str().unwrap();
    assert!(detail.contains("evil.example.com"), "{detail}");
    assert!(detail.contains("1 destination(s) outside"), "{detail}");
}

#[test]
fn all_in_scope_passes_the_row() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "declare",
        "--tools",
        "web_fetch",
        "--network",
        "*.example.com",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ci"]);
    assert!(ok, "{out}");
    connect(&ws, "api.example.com");
    connect(&ws, "EXAMPLE.COM");
    let (receipt, pkg) = close_and_read(&ws);
    assert!(
        receipt["tool_usage"]["network_off_scope"].is_null(),
        "{}",
        receipt["tool_usage"]
    );

    let (ok, out) = ws.run(&[
        "package",
        "verify",
        pkg.to_str().unwrap(),
        "--strict",
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let verdict = first_json(&out);
    assert_eq!(verdict["verdict"], "verified", "{out}");
    let r = row(&verdict, "network_scope").expect("network_scope row");
    assert_eq!(r["status"], "pass", "{r}");
    assert!(
        r["detail"]
            .as_str()
            .unwrap()
            .contains("2 recorded connection(s)"),
        "{r}"
    );
}

#[test]
fn no_scope_declared_means_no_row_and_no_judgement() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ci"]);
    assert!(ok, "{out}");
    connect(&ws, "evil.example.com");
    let (receipt, pkg) = close_and_read(&ws);
    assert!(receipt["tool_usage"]["network_declared"].is_null());
    assert!(receipt["tool_usage"]["network_off_scope"].is_null());
    assert_eq!(
        receipt["side_effects"]["network_connections"][0]["destination"],
        "evil.example.com"
    );

    let (ok, out) = ws.run(&[
        "package",
        "verify",
        pkg.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let verdict = first_json(&out);
    assert!(row(&verdict, "network_scope").is_none(), "no scope, no row");
}

#[test]
fn register_and_card_carry_the_network_scope() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "agent",
        "register",
        "--name",
        "fetcher",
        "--tools",
        "net.fetch",
        "--network",
        "api.example.com,*.internal.net",
        "--own-key",
        "--quiet",
    ]);
    assert!(ok, "{out}");
    // The on-disk card the gate reads.
    let agents = ws.root.join(".treeship/agents");
    let card_file = std::fs::read_dir(&agents)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            std::fs::read_to_string(p)
                .map(|s| s.contains("\"fetcher\""))
                .unwrap_or(false)
        })
        .expect("card written");
    let card: Value = serde_json::from_slice(&std::fs::read(&card_file).unwrap()).unwrap();
    assert_eq!(
        card["capabilities"]["network"],
        serde_json::json!(["api.example.com", "*.internal.net"])
    );

    // The signed agent_card.v1 receipt verify-capability reads.
    let (ok, out) = ws.run(&[
        "attest",
        "card",
        "--agent",
        "agent://fetcher",
        "--tools",
        "net.fetch",
        "--network",
        "api.example.com",
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let minted = first_json(&out);
    let id = minted["id"]
        .as_str()
        .or_else(|| minted["artifact_id"].as_str())
        .or_else(|| minted["card"].as_str())
        .expect("card id in output")
        .to_string();
    let (_ok, out) = ws.run(&["verify-capability", &id, "--format", "json"]);
    let v = first_json(&out);
    assert_eq!(
        v["declared_network"],
        serde_json::json!(["api.example.com"]),
        "{out}"
    );
}
