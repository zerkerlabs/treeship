//! `--format json` always emits JSON (T3, the JSON half).
//!
//! In 0.31.9 seven commands wrote nothing at all in JSON mode and exited 0,
//! because every line they printed went through a printer call that is a
//! no-op there (0.31.9 full test, CLI-10). This test runs every command that
//! can answer without a hub, a network or a second machine, in JSON mode,
//! and requires a non-empty document that parses.
//!
//! Coverage is enforced from the binary's own command tree (`__dump-cli`):
//! every leaf is either run here or named in SKIP with a reason. A new
//! command fails this test until someone classifies it, which is the point.

use std::path::PathBuf;
use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Ship {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
    config: PathBuf,
}

impl Ship {
    fn init() -> Self {
        let home = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let config = work.path().join(".treeship/config.json");
        let ship = Self { home, work, config };
        let out = ship.run(&["init", "--name", "json-contract"]);
        assert!(
            out.status.success(),
            "init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ship
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .env_remove("TREESHIP_OTEL_ENDPOINT")
            .args(args)
            .arg("--config")
            .arg(&self.config)
            .output()
            .expect("run treeship")
    }

    fn run_json(&self, args: &[&str]) -> serde_json::Value {
        self.try_json(args).unwrap_or_else(|e| panic!("{e}"))
    }

    /// One JSON document on stdout, exit 0, or a message saying which of
    /// the three failed.
    fn try_json(&self, args: &[&str]) -> Result<serde_json::Value, String> {
        let mut full: Vec<&str> = args.to_vec();
        full.push("--format");
        full.push("json");
        let out = self.run(&full);
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() {
            return Err(format!(
                "`treeship {}` exited {:?}\n  stdout: {}\n  stderr: {}",
                args.join(" "),
                out.status.code(),
                stdout.trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        if stdout.trim().is_empty() {
            return Err(format!(
                "`treeship {} --format json` wrote nothing to stdout (exit 0)",
                args.join(" ")
            ));
        }
        serde_json::from_str(&stdout).map_err(|e| {
            format!(
                "`treeship {} --format json` is not one JSON document: {e}\n{stdout}",
                args.join(" ")
            )
        })
    }

    fn must(&self, args: &[&str]) -> Output {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "`treeship {}`: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }
}

/// Leaves that cannot run here, each with the reason. A leaf in neither
/// this list nor the run below fails `every_leaf_is_classified`.
const SKIP: &[(&str, &str)] = &[
    ("__dump-cli", "is the tree itself"),
    (
        "add",
        "detects and instruments installed agents on this machine",
    ),
    ("agents approve", "needs a pending card review"),
    (
        "agents remove",
        "mutates the card store; register is covered",
    ),
    ("agents review", "interactive"),
    ("approve", "consumes a pending approval from a shell hook"),
    (
        "attest endorsement",
        "needs a subject and is a signing path, not a report",
    ),
    ("audit", "needs a hub"),
    (
        "bundle create",
        "signing path; export/import are file round-trips",
    ),
    ("bundle export", "file round-trip"),
    ("bundle import", "file round-trip"),
    (
        "checkpoint",
        "merkle.rs is Lane A's until W1-5 merges; JSON root truncation is a known follow-up",
    ),
    ("daemon start", "spawns a long-running process (W1-11)"),
    ("daemon status", "W1-11"),
    ("daemon stop", "W1-11"),
    ("dashboard", "serves HTTP until stopped"),
    ("deny", "consumes a pending approval from a shell hook"),
    ("grant revoke", "signing path; issue/list/show are covered"),
    ("harness inspect", "needs a harness id; list is covered"),
    ("harness smoke", "runs the harness"),
    ("hook post", "shell hook handler"),
    ("hook pre", "shell hook handler"),
    ("hub attach", "device-code flow against a hub"),
    ("hub detach", "needs a hub connection"),
    ("hub kill", "needs a hub connection"),
    ("hub open", "opens a browser"),
    ("hub pull", "needs a hub"),
    (
        "hub push",
        "needs a hub (covered with a mock in hub_share_urls_cli.rs)",
    ),
    ("hub use", "needs a hub connection"),
    ("init", "already ran"),
    ("install", "edits shell rc files"),
    ("uninstall", "edits shell rc files"),
    ("match", "needs a hub"),
    ("merkle proof", "merkle.rs is Lane A's until W1-5 merges"),
    ("merkle publish", "needs a hub; merkle.rs is Lane A's"),
    (
        "merkle status",
        "merkle.rs is Lane A's until W1-5 merges; known 0-byte JSON, follow-up",
    ),
    ("merkle verify", "merkle.rs is Lane A's until W1-5 merges"),
    ("onboard", "signing path with optional hub publish"),
    ("otel disable", "prints shell guidance only"),
    ("otel enable", "prints shell guidance only"),
    ("otel export", "needs a collector"),
    ("otel test", "needs a collector"),
    ("present", "needs a checkpoint"),
    ("profile", "needs work history"),
    ("prove", "zk build only"),
    ("prove-chain", "zk build only"),
    ("publish", "needs a hub"),
    ("quickstart", "interactive"),
    (
        "room create",
        "needs a session; room status/participants covered",
    ),
    ("room participants", "needs a room"),
    ("room status", "needs a room"),
    ("session abandon", "destructive; close is covered"),
    ("session answer-challenge", "needs a challenge"),
    ("session countersign", "needs a joined invitation"),
    (
        "session invite",
        "needs an open session and a pinned invitee",
    ),
    ("session join", "needs an invitation"),
    ("session mint-challenge", "needs a session"),
    ("session report", "uploads to a hub"),
    ("setup", "detects and instruments installed agents"),
    ("template apply", "writes config.yaml"),
    ("template save", "interactive"),
    ("template validate", "needs a file; preview is covered"),
    ("ui", "needs a terminal"),
    ("verify-capability", "needs a card"),
    ("verify-presentation", "needs a presentation file"),
    ("verify-profile", "needs an attested profile"),
    ("verify-proof", "zk build only"),
    ("vi attest", "needs a VI credential set"),
    ("vi check", "needs a mandate file"),
    ("vi keys export", "needs a VI key"),
    ("vi keys import", "needs a JWK file"),
    ("vi verify", "needs a VI credential set"),
    ("workflow verify", "needs a workflow declaration"),
    ("wrap", "covered in wrap_json_cli.rs"),
    ("zk-setup", "informational, zk build"),
    ("zk-tls-setup", "informational"),
    ("attest handoff", "needs artifacts to hand off"),
    ("history", "needs an agent with a transparency log"),
    ("resolve", "needs a card; error path covered in contract.rs"),
    ("revoke-capability", "needs a card"),
    ("trust add", "needs a key; list is covered"),
    ("trust remove", "needs a pinned key"),
    ("keys rotate", "W1-12"),
    ("halt", "signs a halt; covered in halt_cli.rs"),
    (
        "session event",
        "needs an open session; covered in session_cli.rs",
    ),
    ("judge", "covered in judge_cli.rs"),
];

#[test]
fn every_json_capable_command_emits_json() {
    let ship = Ship::init();

    // State the reports need: an artifact, a grant, a declaration, and a
    // closed session with its package.
    let first = ship.run_json(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "probe",
    ]);
    let first_id = first["id"].as_str().unwrap().to_string();
    let grant = ship.run_json(&[
        "grant",
        "issue",
        "--scope",
        "payments.refund",
        "--audience",
        "agent://x",
        "--expiry",
        "30d",
        "--grantee-self",
    ]);
    let grant_id = grant["grant_id"].as_str().unwrap().to_string();
    ship.must(&["declare", "--tools", "read_file"]);
    ship.must(&["session", "start", "--name", "json"]);
    ship.must(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "in-session",
    ]);
    let close = ship.run_json(&["session", "close"]);
    let pkg = close
        .as_object()
        .and_then(|m| {
            m.values()
                .find_map(|v| v.as_str().filter(|s| s.ends_with(".treeship")))
        })
        .map(str::to_string)
        .unwrap_or_else(|| panic!("session close JSON names no package: {close}"));

    let mut ran: Vec<String> = Vec::new();
    let mut wrong: Vec<String> = Vec::new();
    let mut check = |leaf: &str, args: &[&str]| {
        match ship.try_json(args) {
            Ok(v) if v.is_object() || v.is_array() => {}
            Ok(v) => wrong.push(format!(
                "`treeship {}`: JSON is a bare scalar: {v}",
                args.join(" ")
            )),
            Err(e) => wrong.push(e),
        }
        ran.push(leaf.to_string());
    };

    // The seven that wrote nothing in 0.31.9.
    check("doctor", &["doctor"]);
    check("package inspect", &["package", "inspect", &pkg]);
    check("pending", &["pending"]);
    check("declare", &["declare", "--show"]);
    check("otel status", &["otel", "status"]);
    check("templates", &["templates"]);
    check("version", &["version"]);
    // Everything else that answers locally.
    check("status", &["status"]);
    check("keys list", &["keys", "list"]);
    check("keys export", &["keys", "export"]);
    check("trust list", &["trust", "list"]);
    check("agents list", &["agents", "list"]);
    check(
        "agent register",
        &["agent", "register", "--name", "json-bot"],
    );
    check(
        "grant issue",
        &[
            "grant",
            "issue",
            "--scope",
            "x",
            "--audience",
            "agent://y",
            "--expiry",
            "30d",
            "--grantee-self",
        ],
    );
    check("grant list", &["grant", "list"]);
    check("grant show", &["grant", "show", &grant_id]);
    check("approval uses", &["approval", "uses", &grant_id]);
    check("approval status", &["approval", "status", &grant_id]);
    check(
        "approval journal verify",
        &["approval", "journal", "verify"],
    );
    check("log", &["log"]);
    check("verify", &["verify", "last"]);
    check("package verify", &["package", "verify", &pkg]);
    check("receipt export", &["receipt", "export", &first_id]);
    check("session status", &["session", "status"]);
    check("session start", &["session", "start", "--name", "again"]);
    check("session close", &["session", "close"]);
    check(
        "attest action",
        &[
            "attest",
            "action",
            "--actor",
            "agent://a",
            "--action",
            "json",
        ],
    );
    check(
        "attest approval",
        &[
            "attest",
            "approval",
            "--approver",
            "human://h",
            "--allowed-action",
            "x",
            "--max-uses",
            "1",
        ],
    );
    check(
        "attest card",
        &["attest", "card", "--agent", "agent://a", "--tools", "read"],
    );
    check(
        "attest decision",
        &[
            "attest",
            "decision",
            "--actor",
            "agent://a",
            "--model",
            "m",
            "--summary",
            "chose x",
        ],
    );
    check(
        "attest receipt",
        &[
            "attest",
            "receipt",
            "--system",
            "system://t",
            "--kind",
            "confirmation",
            "--payload",
            "{}",
        ],
    );
    check("harness list", &["harness", "list"]);
    check("hub ls", &["hub", "ls"]);
    check("hub status", &["hub", "status"]);
    check(
        "template preview",
        &["template", "preview", "github-contributor"],
    );
    check("vi keygen", &["vi", "keygen"]);
    check("vi keys list", &["vi", "keys", "list"]);

    assert!(
        wrong.is_empty(),
        "JSON contract broken ({} of {} commands):\n{}",
        wrong.len(),
        ran.len(),
        wrong.join("\n")
    );
    let ran_leaves: std::collections::BTreeSet<String> = ran.into_iter().collect();
    let skipped: std::collections::BTreeSet<String> =
        SKIP.iter().map(|(l, _)| l.to_string()).collect();
    let both: Vec<&String> = ran_leaves.intersection(&skipped).collect();
    assert!(both.is_empty(), "leaves both run and skipped: {both:?}");
}

#[test]
fn every_leaf_is_classified() {
    let ship = Ship::init();
    let tree = ship.run_json(&["__dump-cli"]);
    let mut leaves = Vec::new();
    fn walk(node: &serde_json::Value, path: Vec<String>, out: &mut Vec<String>) {
        let subs = node["subcommands"].as_array().unwrap();
        if subs.is_empty() {
            out.push(path.join(" "));
        }
        for s in subs {
            let mut p = path.clone();
            p.push(s["name"].as_str().unwrap().to_string());
            walk(s, p, out);
        }
    }
    walk(&tree, Vec::new(), &mut leaves);
    assert!(
        leaves.len() > 100,
        "dump-cli found only {} leaves",
        leaves.len()
    );

    // The leaves the JSON test runs are the `check("<leaf>", …)` calls in
    // this file; read them from the source so the two lists cannot drift.
    let src = include_str!("json_contract.rs");
    let ran: std::collections::BTreeSet<String> = src
        .match_indices("check(")
        .filter_map(|(i, _)| {
            let rest = src[i + "check(".len()..].trim_start();
            let rest = rest.strip_prefix('"')?;
            rest.split('"').next().map(str::to_string)
        })
        .collect();
    let skipped: std::collections::BTreeSet<String> =
        SKIP.iter().map(|(l, _)| l.to_string()).collect();
    let unclassified: Vec<&String> = leaves
        .iter()
        .filter(|l| !ran.contains(*l) && !skipped.contains(*l))
        .collect();
    assert!(
        unclassified.is_empty(),
        "commands neither run in JSON mode nor listed in SKIP with a reason: {unclassified:?}"
    );
    let stale: Vec<&str> = SKIP
        .iter()
        .map(|(l, _)| *l)
        .filter(|l| !leaves.iter().any(|x| x == l))
        .collect();
    assert!(
        stale.is_empty(),
        "SKIP names commands that no longer exist: {stale:?}"
    );
}
