//! `session event --type agent.spawned` and `agent.returned` end to end: the
//! child's events land in the same session, and the sealed receipt's agent
//! graph carries the parent_child edge and counts the spawn.

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
fn spawn_and_return_land_in_the_receipt_graph() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "swarm",
        "--actor",
        "agent://claude-code",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["session", "status", "--format", "json"]);
    assert!(ok, "{out}");
    let status: Value = serde_json::from_str(out.trim()).unwrap();
    let session_id = status["session_id"].as_str().unwrap().to_string();

    // The parent does one thing.
    let (ok, out) = ws.run(&[
        "session",
        "event",
        "--type",
        "agent.called_tool",
        "--tool",
        "Read",
        "--agent-name",
        "claude-code",
    ]);
    assert!(ok, "{out}");

    // It spawns a child; the child works; the child returns.
    let (ok, out) = ws.run(&[
        "session",
        "event",
        "--type",
        "agent.spawned",
        "--agent-name",
        "Explore#abcdef12",
        "--meta",
        r#"{"spawned_by":"claude-code","reason":"find the config loader"}"#,
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "session",
        "event",
        "--type",
        "agent.read_file",
        "--file",
        "src/config.rs",
        "--agent-name",
        "Explore#abcdef12",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "session",
        "event",
        "--type",
        "agent.returned",
        "--agent-name",
        "Explore#abcdef12",
        "--meta",
        r#"{"returned_to":"claude-code"}"#,
    ]);
    assert!(ok, "{out}");

    let (ok, out) = ws.run(&["session", "close", "--headline", "spawn test"]);
    assert!(ok, "{out}");

    let receipt_path = ws
        .root
        .join(".treeship/sessions")
        .join(format!("{session_id}.treeship"))
        .join("receipt.json");
    let receipt: Value =
        serde_json::from_str(&std::fs::read_to_string(&receipt_path).unwrap()).unwrap();

    assert_eq!(
        receipt["participants"]["spawned_subagents"], 1,
        "{}",
        receipt["participants"]
    );
    assert!(
        receipt["participants"]["total_agents"].as_u64().unwrap() >= 2,
        "{}",
        receipt["participants"]
    );
    let edges = receipt["agent_graph"]["edges"].as_array().unwrap();
    assert!(
        edges.iter().any(|e| {
            e["edge_type"] == "parent_child"
                && e["from_instance_id"] == "claude-code"
                && e["to_instance_id"] == "Explore#abcdef12"
        }),
        "parent_child edge missing: {edges:?}"
    );
    assert!(
        edges.iter().any(|e| e["edge_type"] == "return"),
        "return edge missing: {edges:?}"
    );

    // The child's file read is attributed to the child, not the parent.
    let timeline = receipt["timeline"].as_array().unwrap();
    assert!(
        timeline.iter().any(|t| {
            t["event_type"] == "agent.read_file" && t["agent_instance_id"] == "Explore#abcdef12"
        }),
        "{timeline:?}"
    );
}

#[test]
fn unsupported_type_lists_the_new_types() {
    let ws = Ws::new();
    let (ok, _) = ws.run(&["session", "start", "--name", "s"]);
    assert!(ok);
    let (ok, out) = ws.run(&["session", "event", "--type", "agent.teleported"]);
    assert!(!ok);
    assert!(
        out.contains("agent.spawned") && out.contains("agent.returned"),
        "{out}"
    );
}
