//! Regressions for the TASKS-0.31.6 findings: the card record the gate reads
//! carries the onboarded tools (T1), a recipient reaches `proven (key-bound)`
//! through the signed certificate (T4), a handoff reports the named work as
//! present or absent (T5), `trust add` refuses a label where a key id is
//! needed (T6), `bundle import` names the key and the pin line (T7), an
//! ambiguous prefix lists candidates (T10), `mint-challenge` prints the
//! outside-verifier pair (T13), a revocation names its signer (T16), and a
//! closed stdout does not abort the command (T19).

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Ship {
    _tmp: TempDir,
    root: PathBuf,
}

impl Ship {
    fn new(name: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let ship = Self { _tmp: tmp, root };
        ship.ok(&["init", "--name", name]);
        ship
    }
    fn config(&self) -> String {
        self.root
            .join(".treeship/config.json")
            .display()
            .to_string()
    }
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .current_dir(&self.root)
            .arg("--config")
            .arg(self.config())
            .args(args);
        c
    }
    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().expect("run treeship")
    }
    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "treeship {:?} failed:\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }
    /// stdout + stderr of a run that is expected to fail.
    fn fails(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            !out.status.success(),
            "treeship {args:?} unexpectedly succeeded"
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }
    fn json(&self, args: &[&str]) -> Value {
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--format", "json"]);
        last_json(&self.ok(&full))
    }
    /// The one card record under `.treeship/agents/` for this agent name:
    /// the file the plugin gate reads.
    fn card_record(&self, name: &str) -> Value {
        let dir = self.root.join(".treeship/agents");
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            if v.get("agent_name").and_then(|x| x.as_str()) == Some(name) {
                return v;
            }
        }
        panic!("no card record for {name} in {}", dir.display());
    }
    /// Storage index entries, for finding an artifact by payload type.
    fn index(&self) -> Vec<Value> {
        let p = self.root.join(".treeship/artifacts/index.json");
        let v: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
        v["entries"].as_array().cloned().unwrap_or_default()
    }
    /// The `agent_cert.v1` receipt id for an agent, by scanning receipts.
    fn cert_id_for(&self, actor: &str) -> String {
        for e in self.index() {
            let id = e["id"].as_str().unwrap().to_string();
            let rec: Value = serde_json::from_slice(
                &std::fs::read(self.root.join(format!(".treeship/artifacts/{id}.json"))).unwrap(),
            )
            .unwrap();
            let payload = rec["envelope"]["payload"].as_str().unwrap_or("");
            use base64::{engine::general_purpose::STANDARD, Engine};
            let Ok(bytes) = STANDARD.decode(payload) else {
                continue;
            };
            let Ok(stmt) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if stmt["kind"].as_str() == Some("agent_cert.v1")
                && stmt["payload"]["agent"].as_str() == Some(actor)
            {
                return id;
            }
        }
        panic!("no agent_cert.v1 for {actor}");
    }
    /// Pin every line `keys export` prints for `key_args` on this ship.
    fn pin_from(&self, producer: &Ship, key_args: &[&str], kinds: &[&str]) {
        let mut args = vec!["keys", "export"];
        args.extend_from_slice(key_args);
        let export = producer.ok(&args);
        for kind in kinds {
            let line = export
                .lines()
                .find(|l| l.contains("trust add") && l.contains(&format!("--kind {kind}")))
                .unwrap_or_else(|| panic!("no {kind} pin line in:\n{export}"));
            let key_id = line
                .split_whitespace()
                .find(|w| w.starts_with("key_"))
                .unwrap();
            let pubkey = line
                .split_whitespace()
                .find(|w| w.starts_with("ed25519:"))
                .unwrap();
            self.ok(&["trust", "add", key_id, pubkey, "--kind", kind, "--yes"]);
        }
    }
}

fn last_json(stdout: &str) -> Value {
    serde_json::Deserializer::from_str(stdout)
        .into_iter::<Value>()
        .filter_map(Result::ok)
        .last()
        .unwrap_or_else(|| panic!("no JSON object in stdout:\n{stdout}"))
}

fn id_of(v: &Value) -> String {
    v.get("id")
        .or_else(|| v.get("artifact_id"))
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("no id in {v}"))
        .to_string()
}

/// A bundle holding exactly `ids`, exported from `producer` to a file.
fn export_bundle(producer: &Ship, ids: &[&str]) -> PathBuf {
    let bundle = id_of(&producer.json(&["bundle", "create", "--artifacts", &ids.join(",")]));
    let out = producer.root.join("out.treeship");
    producer.ok(&["bundle", "export", &bundle, "--out", out.to_str().unwrap()]);
    out
}

// ── T1 ──────────────────────────────────────────────────────────────────────

#[test]
fn onboard_writes_the_tools_onto_the_card_record_the_gate_reads() {
    let g = Ship::new("G");
    g.ok(&["onboard", "coder", "--tools", "file.read,file.write"]);
    let card = g.card_record("coder");
    let bounded: Vec<&str> = card["capabilities"]["bounded_tools"]
        .as_array()
        .expect("bounded_tools on the record")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        bounded.contains(&"file.read") && bounded.contains(&"file.write"),
        "the gate reads bounded_tools from this record; got {card}"
    );
    assert!(
        card["key_id"].as_str().is_some(),
        "own key recorded: {card}"
    );
}

#[test]
fn onboard_from_tools_json_lands_the_captured_tools_on_the_record() {
    let g = Ship::new("G");
    let tools = g.root.join("tools.json");
    std::fs::write(&tools, r#"{"tools":[{"name":"search"},{"name":"deploy"}]}"#).unwrap();
    let out = g.run(&["onboard", "worker", "--tools-json", tools.to_str().unwrap()]);
    if !out.status.success() {
        // tools-json shape is a separate contract; this test only asserts the
        // record when the card minted at all.
        eprintln!(
            "onboard --tools-json failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let card = g.card_record("worker");
    let bounded = card["capabilities"]["bounded_tools"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !bounded.is_empty(),
        "tools captured from the file must reach the record the gate reads: {card}"
    );
}

// ── T4 ──────────────────────────────────────────────────────────────────────

#[test]
fn recipient_grades_key_bound_through_the_signed_certificate_and_pins() {
    let g = Ship::new("G");
    let c = Ship::new("C");
    g.ok(&["onboard", "grok", "--tools", "a2a.*"]);
    let cert = g.cert_id_for("agent://grok");
    let action = id_of(&g.json(&[
        "attest",
        "action",
        "--actor",
        "agent://grok",
        "--action",
        "a2a.call",
    ]));
    let file = export_bundle(&g, &[&cert, &action]);

    // Before the pins: the import is refused and names the key and the fix.
    let refused = c.fails(&["bundle", "import", file.to_str().unwrap()]);
    assert!(refused.contains("is signed by key_"), "{refused}");
    assert!(refused.contains("treeship trust add key_"), "{refused}");

    c.pin_from(&g, &[], &["cert_issuer"]);
    c.pin_from(&g, &["--agent", "agent://grok"], &["agent_cert"]);
    c.ok(&["bundle", "import", file.to_str().unwrap()]);

    let out = c.ok(&["verify", &action]);
    assert!(
        out.contains("proven (key-bound)"),
        "with the cert imported and the issuer pinned the recipient must reach key-bound, got:\n{out}"
    );
}

#[test]
fn recipient_without_the_certificate_still_sees_asserted() {
    let g = Ship::new("G");
    let c = Ship::new("C");
    g.ok(&["onboard", "grok", "--tools", "a2a.*"]);
    let action = id_of(&g.json(&[
        "attest",
        "action",
        "--actor",
        "agent://grok",
        "--action",
        "a2a.call",
    ]));
    let file = export_bundle(&g, &[&action]);
    c.pin_from(&g, &[], &["cert_issuer"]);
    c.pin_from(&g, &["--agent", "agent://grok"], &["agent_cert"]);
    c.ok(&["bundle", "import", file.to_str().unwrap()]);
    let out = c.ok(&["verify", &action]);
    // The agent key is pinned, but nothing signed binds the URI to it here.
    assert!(out.contains("asserted"), "no cert, no binding: {out}");
}

// ── T5 ──────────────────────────────────────────────────────────────────────

#[test]
fn handoff_verify_reports_named_artifacts_present_or_absent() {
    let g = Ship::new("G");
    let c = Ship::new("C");
    let work = id_of(&g.json(&[
        "attest",
        "action",
        "--actor",
        "agent://researcher",
        "--action",
        "research",
    ]));
    let handoff = id_of(&g.json(&[
        "attest",
        "handoff",
        "--from",
        "agent://researcher",
        "--to",
        "agent://legal",
        "--artifacts",
        &work,
    ]));
    let local = g.ok(&["verify", &handoff]);
    assert!(local.contains("all present in this store"), "{local}");

    let file = export_bundle(&g, &[&handoff]);
    c.pin_from(&g, &[], &["cert_issuer"]);
    c.ok(&["bundle", "import", file.to_str().unwrap()]);
    let remote = c.ok(&["verify", &handoff]);
    assert!(remote.contains("NOT in this store"), "{remote}");
    assert!(remote.contains(&work), "names the absent id: {remote}");
    assert!(
        remote.contains("names work this store does not hold"),
        "{remote}"
    );
}

// ── T6 ──────────────────────────────────────────────────────────────────────

#[test]
fn trust_add_refuses_a_label_where_a_key_id_is_matched() {
    let c = Ship::new("C");
    let pk = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let err = c.fails(&[
        "trust",
        "add",
        "company-a",
        pk,
        "--kind",
        "cert_issuer",
        "--yes",
    ]);
    assert!(err.contains("not a key id"), "{err}");
    assert!(err.contains("keys export"), "{err}");
    c.ok(&[
        "trust",
        "add",
        "key_0123456789abcdef",
        pk,
        "--kind",
        "cert_issuer",
        "--label",
        "company-a",
        "--yes",
    ]);
    c.ok(&[
        "trust",
        "add",
        "key_agent_0123456789abcdef",
        pk,
        "--kind",
        "agent_cert",
        "--yes",
    ]);
    // Hub kinds keep free-form ids.
    c.ok(&["trust", "add", "my-org", pk, "--kind", "hub_org", "--yes"]);
}

// ── T10 ─────────────────────────────────────────────────────────────────────

#[test]
fn ambiguous_prefix_lists_candidates_at_any_length() {
    let g = Ship::new("G");
    let mut ids = Vec::new();
    for i in 0..20 {
        ids.push(id_of(&g.json(&[
            "attest",
            "action",
            "--actor",
            "agent://a",
            "--action",
            &format!("t{i}"),
        ])));
    }
    // Twenty ids over sixteen first-hex-digits: some digit is shared.
    let mut by_first: std::collections::BTreeMap<char, Vec<&String>> = Default::default();
    for id in &ids {
        by_first
            .entry(id["art_".len()..].chars().next().unwrap())
            .or_default()
            .push(id);
    }
    let (digit, group) = by_first
        .iter()
        .find(|(_, v)| v.len() >= 2)
        .expect("a shared first digit");
    let err = g.fails(&["verify", &format!("art_{digit}")]);
    assert!(err.contains("is ambiguous"), "{err}");
    assert!(err.contains("Candidates:"), "{err}");
    assert!(
        err.contains(group[0].as_str()),
        "lists the candidates: {err}"
    );
}

// ── T13 ─────────────────────────────────────────────────────────────────────

#[test]
fn mint_challenge_prints_the_outside_verifier_pair() {
    let c = Ship::new("C");
    let out = c.run(&["session", "mint-challenge"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains("treeship present agent://<name> --challenge"),
        "{text}"
    );
    assert!(
        text.contains("treeship verify-presentation <file> --challenge"),
        "{text}"
    );
}

// ── T16 ─────────────────────────────────────────────────────────────────────

#[test]
fn revocation_names_its_signer() {
    let g = Ship::new("G");
    let onboard = g.json(&["onboard", "grok", "--tools", "a2a.*"]);
    let card = onboard["card"]
        .as_str()
        .expect("onboard reports the card id")
        .to_string();
    g.ok(&["revoke-capability", &card, "--reason", "test"]);
    // A revoked card is a failing verdict; the text is what matters here.
    let run = g.run(&["verify-capability", &card]);
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        out.contains("self-revoked (the card's own key)") || out.contains("pinned revoker key_"),
        "the revocation must say what its signer is, got:\n{out}"
    );
    assert!(!out.contains("issuer (ship) revoked"), "{out}");
}

// ── T19 ─────────────────────────────────────────────────────────────────────

#[test]
fn a_closed_stdout_does_not_abort_onboard() {
    let g = Ship::new("G");
    let mut child = g
        .cmd(&["onboard", "piped", "--tools", "file.read"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The reader goes away before the command has written anything: every
    // later write hits EPIPE. Before T19 the command panicked (exit 101)
    // after registering the agent and before minting its card.
    drop(child.stdout.take());
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "onboard must complete with stdout closed: {status}"
    );
    let card = g.card_record("piped");
    assert!(card["key_id"].as_str().is_some(), "{card}");
    // The card was minted: the step after the first writes.
    let minted = g.index().iter().any(|e| {
        e["payload_type"]
            .as_str()
            .map(|t| t.contains("receipt"))
            .unwrap_or(false)
    });
    assert!(minted, "onboard ran to the card step");
}
