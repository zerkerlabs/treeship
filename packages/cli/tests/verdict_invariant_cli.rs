//! The verdict invariant, as one suite across every command that can print
//! a verdict:
//!
//!     No green verdict is reachable without signature verification against
//!     a key the verifier trusts.
//!
//! Three advisories in four months (v0.10.4, v0.19, v0.31.2) shared one root
//! cause: a surface said "verified" without a signature check anchored to a
//! pinned key. Each got its own regression test. This file is the class,
//! not the instance: a matrix of the verdict-printing commands against the
//! mutations that have produced false greens, each on its own copy of a real
//! workspace, asserting the same two things every time: the exit code is
//! nonzero and the output carries no green verdict.
//!
//! Commands covered: verify, verify-capability, verify-presentation,
//! verify-profile, package verify, session report, workflow verify, vi verify.
//! Mutations: flipped payload byte, stripped signatures, forged artifact id,
//! unknown signing key, reordered chain, emptied package, unpinned root.

use std::path::{Path, PathBuf};
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
    fn empty() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Self { _tmp: tmp, root }
    }
    fn new() -> Self {
        let ws = Self::empty();
        let (ok, out) = ws.run(&["init", "--name", "inv"]);
        assert!(ok, "init: {out}");
        ws
    }
    fn config(&self) -> PathBuf {
        self.root.join(".treeship/config.json")
    }
    fn trust_roots(&self) -> PathBuf {
        self.root.join("trust_roots.json")
    }
    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .env("TREESHIP_TRUST_ROOTS", self.trust_roots())
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
    fn json(&self, args: &[&str]) -> Value {
        let (ok, out) = self.run(&[args, &["--format", "json"]].concat());
        assert!(ok, "{args:?}: {out}");
        // JSON output is pretty-printed over many lines; take from the first
        // brace to the end and let serde stop at the closing one.
        let start = out.find('{').unwrap_or(out.len());
        let mut de = serde_json::Deserializer::from_str(&out[start..]);
        Value::deserialize(&mut de).unwrap_or_else(|e| panic!("json from {args:?}: {e}\n{out}"))
    }
    /// An independent copy of this workspace for one mutation.
    fn fork(&self) -> Ws {
        let ws = Ws::empty();
        copy_dir(&self.root, &ws.root);
        ws
    }
    fn artifact_path(&self, id: &str) -> PathBuf {
        self.root
            .join(".treeship/artifacts")
            .join(format!("{id}.json"))
    }
    fn package(&self) -> PathBuf {
        let dir = self.root.join(".treeship/sessions");
        std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().map(|x| x == "treeship").unwrap_or(false))
            .expect("a sealed package")
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let p = e.path();
        let dest = to.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &dest);
        } else {
            std::fs::copy(&p, &dest).unwrap();
        }
    }
}

fn read_json(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn write_json(p: &Path, v: &Value) {
    std::fs::write(p, serde_json::to_string_pretty(v).unwrap()).unwrap();
}

// ---------------------------------------------------------------- mutations

/// Mutations act on a DSSE envelope: `{payload, payloadType, signatures}`.
/// A store record wraps one under `envelope`; a package artifact file is
/// the bare envelope; a presentation carries the card's as a JSON string.
fn flip_payload(env: &mut Value) {
    let p = env["payload"].as_str().unwrap().to_string();
    let mut b: Vec<char> = p.chars().collect();
    let i = 8;
    b[i] = if b[i] == 'A' { 'B' } else { 'A' };
    env["payload"] = Value::String(b.into_iter().collect());
}
fn strip_signatures(env: &mut Value) {
    env["signatures"] = Value::Array(vec![]);
}
fn unknown_key(env: &mut Value) {
    env["signatures"][0]["keyid"] = Value::String("key_deadbeefdeadbeef".into());
}

fn mutate_store_artifact(ws: &Ws, id: &str, f: fn(&mut Value)) {
    let p = ws.artifact_path(id);
    let mut v = read_json(&p);
    f(&mut v["envelope"]);
    if v["envelope"]["signatures"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(true)
    {
        // keep the record's own key_id consistent with an absent signature
    } else if let Some(k) = v["envelope"]["signatures"][0]["keyid"].as_str() {
        let k = k.to_string();
        v["key_id"] = Value::String(k);
    }
    write_json(&p, &v);
}

/// A forged id: the same signed envelope filed under an invented artifact
/// id, listed in the index as if it had always been there.
fn forge_id(ws: &Ws, real: &str) -> String {
    let forged = "art_00000000000000000000000000000001".to_string();
    let mut v = read_json(&ws.artifact_path(real));
    v["artifact_id"] = Value::String(forged.clone());
    v["digest"] = Value::String(
        "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
    );
    write_json(&ws.artifact_path(&forged), &v);
    let idx_path = ws.root.join(".treeship/artifacts/index.json");
    let mut idx = read_json(&idx_path);
    let mut entry = idx["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == real)
        .cloned()
        .unwrap();
    entry["id"] = Value::String(forged.clone());
    idx["entries"].as_array_mut().unwrap().push(entry);
    write_json(&idx_path, &idx);
    forged
}

fn mutate_package_artifact(pkg: &Path, f: fn(&mut Value)) {
    let dir = pkg.join("artifacts");
    let first = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    let mut v = read_json(&first);
    f(&mut v);
    write_json(&first, &v);
}

fn empty_package(pkg: &Path) {
    for e in std::fs::read_dir(pkg.join("artifacts")).unwrap().flatten() {
        std::fs::remove_file(e.path()).unwrap();
    }
    let rp = pkg.join("receipt.json");
    let mut r = read_json(&rp);
    r["artifacts"] = Value::Array(vec![]);
    write_json(&rp, &r);
}

// ------------------------------------------------------------ green detector

/// True when the output carries a green verdict for `cmd`. Kept deliberately
/// broad: any success marker on any surface counts, so a new marker that
/// slips past a signature check is caught here rather than missed.
fn is_green(cmd: &str, ok: bool, out: &str) -> bool {
    if !ok {
        return false;
    }
    let text = out.contains("✓ verified")
        || out.contains("✓ package verified")
        || out.contains("✓ capability card")
        || out.contains("✓ presentation")
        || out.contains("✓ profile")
        || out.contains("\"outcome\": \"pass\"")
        || out.contains("\"outcome\":\"pass\"");
    if text {
        return true;
    }
    let Some(start) = out.find('{') else {
        return false;
    };
    let mut de = serde_json::Deserializer::from_str(&out[start..]);
    let Ok(v) = Value::deserialize(&mut de) else {
        return false;
    };
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("");
    match cmd {
        "verify" | "vi verify" => s("outcome") == "pass",
        "verify-capability" => s("verdict") == "verified" || v["ok"] == true,
        "verify-presentation" => {
            v["ok"] == true
                || s("verdict").starts_with("verified")
                || s("signature").starts_with("verified")
        }
        "verify-profile" => v["ok"] == true || s("verdict").starts_with("checked"),
        "package verify" => s("verdict") == "verified" || (s("status") == "ok" && v["failed"] == 0),
        "session report" => s("verification_status") == "pass",
        "workflow verify" => true, // exit 0 with a report is the green path
        _ => false,
    }
}

fn assert_not_green(label: &str, cmd: &str, ws: &Ws, args: &[&str]) {
    let (ok, out) = ws.run(args);
    assert!(
        !ok,
        "[{label}] {cmd}: exit code was 0 after the mutation.\n{out}"
    );
    assert!(
        !is_green(cmd, ok, &out),
        "[{label}] {cmd}: a green verdict survived the mutation.\n{out}"
    );
    // JSON surface too, when the command has one.
    let (ok_j, out_j) = ws.run(&[args, &["--format", "json"]].concat());
    assert!(
        !is_green(cmd, ok_j, &out_j),
        "[{label}] {cmd} --format json: a green verdict survived the mutation.\n{out_j}"
    );
}

// ------------------------------------------------------------------ fixture

struct Fixture {
    ws: Ws,
    action: String,
    card: String,
    profile: String,
    presentation: PathBuf,
}

/// One real workspace with every verdict surface exercised on the happy path.
fn fixture() -> Fixture {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "agent",
        "register",
        "--name",
        "deployer",
        "--tools",
        "file.read",
        "--own-key",
        "--quiet",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "inv",
        "--actor",
        "agent://deployer",
    ]);
    assert!(ok, "{out}");
    let a = ws.json(&[
        "attest",
        "action",
        "--actor",
        "agent://deployer",
        "--action",
        "file.read",
    ]);
    let action = a["id"].as_str().unwrap().to_string();
    let c = ws.json(&[
        "attest",
        "card",
        "--agent",
        "agent://deployer",
        "--tools",
        "file.read",
    ]);
    let card = c["id"]
        .as_str()
        .or_else(|| c["card"].as_str())
        .unwrap()
        .to_string();
    let (ok, out) = ws.run(&["checkpoint"]);
    assert!(ok, "{out}");
    let presentation = ws.root.join("pres.json");
    let (ok, out) = ws.run(&[
        "present",
        "agent://deployer",
        "--out",
        presentation.to_str().unwrap(),
    ]);
    assert!(ok, "{out}");
    let p = ws.json(&["profile", "agent://deployer", "--attest"]);
    let profile = p["attested_artifact_id"].as_str().unwrap().to_string();
    let (ok, out) = ws.run(&["session", "close", "--headline", "inv"]);
    assert!(ok, "{out}");

    // Every surface is green on the untouched fixture, or the matrix below
    // would pass vacuously.
    let f = Fixture {
        ws,
        action,
        card,
        profile,
        presentation,
    };
    let pkg = f.ws.package();
    let checks: [(&str, Vec<&str>); 6] = [
        ("verify", vec!["verify", &f.action]),
        ("verify-capability", vec!["verify-capability", &f.card]),
        (
            "verify-presentation",
            vec!["verify-presentation", f.presentation.to_str().unwrap()],
        ),
        ("verify-profile", vec!["verify-profile", &f.profile]),
        (
            "package verify",
            vec!["package", "verify", pkg.to_str().unwrap()],
        ),
        ("session report", vec!["session", "report", "--no-upload"]),
    ];
    for (cmd, args) in checks {
        let (ok, out) = f.ws.run(&args);
        assert!(
            is_green(cmd, ok, &out) || (cmd == "session report" && ok),
            "fixture is not green for {cmd}:\n{out}"
        );
    }
    f
}

// ------------------------------------------------------------------- matrix

#[test]
fn verify_rejects_every_mutation() {
    let f = fixture();
    for (label, m) in [
        ("flipped payload", flip_payload as fn(&mut Value)),
        ("stripped signatures", strip_signatures),
        ("unknown key", unknown_key),
    ] {
        let ws = f.ws.fork();
        mutate_store_artifact(&ws, &f.action, m);
        assert_not_green(label, "verify", &ws, &["verify", &f.action]);
    }
    let ws = f.ws.fork();
    let forged = forge_id(&ws, &f.action);
    assert_not_green("forged id", "verify", &ws, &["verify", &forged]);

    // Reordered chain: storage claims a parent the signature does not name.
    let ws = f.ws.fork();
    let p = ws.artifact_path(&f.action);
    let mut v = read_json(&p);
    v["parent_id"] = Value::String(f.card.clone());
    write_json(&p, &v);
    assert_not_green(
        "reordered chain",
        "verify",
        &ws,
        &["verify", &f.action, "--full"],
    );
}

#[test]
fn verify_capability_rejects_every_mutation() {
    let f = fixture();
    for (label, m) in [
        ("flipped payload", flip_payload as fn(&mut Value)),
        ("stripped signatures", strip_signatures),
        ("unknown key", unknown_key),
    ] {
        let ws = f.ws.fork();
        mutate_store_artifact(&ws, &f.card, m);
        assert_not_green(
            label,
            "verify-capability",
            &ws,
            &["verify-capability", &f.card],
        );
    }
    let ws = f.ws.fork();
    let forged = forge_id(&ws, &f.card);
    assert_not_green(
        "forged id",
        "verify-capability",
        &ws,
        &["verify-capability", &forged],
    );
}

#[test]
fn verify_presentation_rejects_every_mutation() {
    let f = fixture();
    let pres = f.presentation.clone();

    // The presentation carries the card's envelope as a JSON string.
    fn mutate_presentation_card(ws: &Ws, f: fn(&mut Value)) -> PathBuf {
        let pp = ws.root.join("pres.json");
        let mut v = read_json(&pp);
        let raw = v["card"]["envelope_json"].as_str().unwrap().to_string();
        let mut env: Value = serde_json::from_str(&raw).unwrap();
        f(&mut env);
        v["card"]["envelope_json"] = Value::String(env.to_string());
        write_json(&pp, &v);
        pp
    }
    for (label, m) in [
        ("flipped card payload", flip_payload as fn(&mut Value)),
        ("stripped card signatures", strip_signatures),
        ("unknown card key", unknown_key),
    ] {
        let ws = f.ws.fork();
        let pp = mutate_presentation_card(&ws, m);
        assert_not_green(
            label,
            "verify-presentation",
            &ws,
            &["verify-presentation", pp.to_str().unwrap()],
        );
    }

    // Unpinned root: a stranger with no trust roots and no keys must not get
    // a green verdict from a presentation, whatever it carries.
    let stranger = Ws::empty();
    std::fs::create_dir_all(stranger.root.join(".treeship")).unwrap();
    std::fs::copy(&pres, stranger.root.join("pres.json")).unwrap();
    std::fs::write(stranger.trust_roots(), "{\"roots\":[]}").unwrap();
    let (ok, out) = stranger
        .cmd()
        .args(["verify-presentation", "pres.json"])
        .output()
        .map(|o| {
            (
                o.status.success(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
            )
        })
        .unwrap();
    assert!(
        !is_green("verify-presentation", ok, &out),
        "[unpinned root] verify-presentation went green for a stranger with no roots:\n{out}"
    );
}

#[test]
fn verify_profile_rejects_every_mutation() {
    let f = fixture();
    for (label, m) in [
        ("flipped payload", flip_payload as fn(&mut Value)),
        ("stripped signatures", strip_signatures),
        ("unknown key", unknown_key),
    ] {
        let ws = f.ws.fork();
        mutate_store_artifact(&ws, &f.profile, m);
        assert_not_green(
            label,
            "verify-profile",
            &ws,
            &["verify-profile", &f.profile],
        );
    }
}

#[test]
fn package_verify_rejects_every_mutation_and_never_says_verified_unpinned() {
    let f = fixture();
    for (label, m) in [
        ("flipped payload", flip_payload as fn(&mut Value)),
        ("stripped signatures", strip_signatures),
        ("unknown key", unknown_key),
    ] {
        let ws = f.ws.fork();
        let pkg = ws.package();
        mutate_package_artifact(&pkg, m);
        assert_not_green(
            label,
            "package verify",
            &ws,
            &["package", "verify", pkg.to_str().unwrap()],
        );
    }
    let ws = f.ws.fork();
    let pkg = ws.package();
    empty_package(&pkg);
    assert_not_green(
        "emptied package",
        "package verify",
        &ws,
        &["package", "verify", pkg.to_str().unwrap()],
    );

    // A stranger with nothing pinned: signatures may pass, but the verdict
    // is never "verified", and --strict fails.
    let stranger = Ws::new();
    let src = f.ws.package();
    let dst = stranger.root.join("pkg.treeship");
    copy_dir(&src, &dst);
    let v = stranger.json(&["package", "verify", dst.to_str().unwrap()]);
    assert_ne!(
        v["verdict"], "verified",
        "unpinned stranger got verdict=verified: {v}"
    );
    assert_eq!(v["signer_pinned"], false, "{v}");
    let (ok, out) = stranger.run(&["package", "verify", dst.to_str().unwrap(), "--strict"]);
    assert!(!ok, "--strict must fail for an unpinned signer:\n{out}");
}

#[test]
fn session_report_fails_on_a_tampered_package() {
    let f = fixture();
    let ws = f.ws.fork();
    let pkg = ws.package();
    mutate_package_artifact(&pkg, flip_payload);
    let (ok, out) = ws.run(&["session", "report", "--no-upload", "--format", "json"]);
    assert!(!ok, "session report exited 0 on a tampered package:\n{out}");
    let start = out.find('{').unwrap_or(out.len());
    let mut de = serde_json::Deserializer::from_str(&out[start..]);
    let v = Value::deserialize(&mut de).unwrap_or(Value::Null);
    assert_eq!(v["verification_status"], "fail", "{out}");
}

#[test]
fn workflow_verify_rejects_a_tampered_declaration() {
    let ws = Ws::new();
    let decl = serde_json::json!({
        "kind": "workflow.v1", "schema_version": "1", "workflow_id": "single-step",
        "authority": "human://operator", "entry_node": "qa", "terminal_nodes": ["qa"],
        "nodes": [{"id": "qa", "executor": {"capability": "qa.browser"}, "allowed_tools": ["gstack.qa"]}],
        "edges": [], "loops": []
    });
    let d = ws.json(&[
        "attest",
        "receipt",
        "--system",
        "human://operator",
        "--kind",
        "workflow.v1",
        "--payload",
        &decl.to_string(),
    ]);
    let workflow_id = d["id"].as_str().unwrap().to_string();
    let (ok, out) = ws.run(&["session", "start", "--workflow-ref", &workflow_id]);
    assert!(ok, "{out}");
    let manifest = read_json(&ws.root.join(".treeship/session.json"));
    let first_run = manifest["root_artifact_id"].as_str().unwrap().to_string();
    let run = serde_json::json!({
        "run_id": "run_inv", "status": "completed", "workflow_ref": workflow_id,
        "pre_existence": {"grade": "checked", "declaration_checkpoint": "chk_1", "declaration_tree_size": 1, "first_run_leaf_index": 2, "consistency_to": "chk_2"},
        "attempts": [{"node_id": "qa", "iteration": 0, "actor": "agent://claude-code", "capabilities": ["qa.browser"], "tools": ["gstack.qa"], "outcome": "pass", "grade": "checked", "evidence": ["art_qa"]}]
    });
    let run_path = ws.root.join("observed.json");
    std::fs::write(&run_path, run.to_string()).unwrap();
    let (ok, out) = ws.run(&[
        "workflow",
        "verify",
        "--workflow",
        &workflow_id,
        "--first-run",
        &first_run,
        "--run",
        run_path.to_str().unwrap(),
    ]);
    assert!(ok, "happy path should verify: {out}");

    for (label, m) in [
        ("flipped payload", flip_payload as fn(&mut Value)),
        ("stripped signatures", strip_signatures),
        ("unknown key", unknown_key),
    ] {
        let w2 = ws.fork();
        mutate_store_artifact(&w2, &workflow_id, m);
        let rp = w2.root.join("observed.json");
        assert_not_green(
            label,
            "workflow verify",
            &w2,
            &[
                "workflow",
                "verify",
                "--workflow",
                &workflow_id,
                "--first-run",
                &first_run,
                "--run",
                rp.to_str().unwrap(),
            ],
        );
    }
}

#[test]
fn vi_verify_rejects_a_tampered_attestation_or_credential() {
    let fx: Value = serde_json::from_str(include_str!(
        "../../core/tests/fixtures/vi/reference-v0.1.json"
    ))
    .unwrap();
    let ws = Ws::new();
    for (name, key) in [
        ("l1.sdjwt", "l1"),
        ("l2.sdjwt", "l2"),
        ("checkout.jwt", "checkout_jwt"),
    ] {
        std::fs::write(ws.root.join(name), fx[key].as_str().unwrap()).unwrap();
    }
    std::fs::write(
        ws.root.join("agent.jwk"),
        fx["agent_private_jwk"].to_string(),
    )
    .unwrap();
    std::fs::write(
        ws.root.join("issuer.jwk"),
        fx["issuer_public_jwk"].to_string(),
    )
    .unwrap();
    ws.json(&[
        "vi",
        "keys",
        "import",
        "--jwk",
        "agent.jwk",
        "--label",
        "reference",
    ]);
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "vi",
        "--actor",
        "agent://shopping",
    ]);
    assert!(ok, "{out}");
    let purchase = [
        "--mandate",
        "l2.sdjwt",
        "--merchant",
        "merchant-uuid-1",
        "--item",
        "BAB86345",
        "--amount",
        "27999",
        "--currency",
        "USD",
    ];
    let s = ws.json(
        &[
            &["vi", "attest"],
            &purchase[..],
            &[
                "--checkout-jwt",
                "checkout.jwt",
                "--aud-network",
                "https://www.mastercard.com",
                "--aud-merchant",
                "https://tennis-warehouse.com",
                "--iss",
                "https://agent.example.com",
                "--out",
                "vi-out",
            ],
        ]
        .concat(),
    );
    assert_eq!(s["status"], "ok", "{s}");
    let att = s["attestation"]["artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let verify_args = [
        "vi",
        "verify",
        "--mandate",
        "l2.sdjwt",
        "--l3a",
        "vi-out/l3a.sdjwt",
        "--l3b",
        "vi-out/l3b.sdjwt",
        "--l2-payment",
        "vi-out/l2-payment.sdjwt",
        "--l2-checkout",
        "vi-out/l2-checkout.sdjwt",
        "--l1",
        "l1.sdjwt",
        "--issuer-jwk",
        "issuer.jwk",
        "--local",
        "--require-attestation",
    ];
    let r = ws.json(&verify_args);
    assert_eq!(r["outcome"], "pass", "{r}");

    for (label, m) in [
        ("flipped payload", flip_payload as fn(&mut Value)),
        ("stripped signatures", strip_signatures),
        ("unknown key", unknown_key),
    ] {
        let w2 = ws.fork();
        mutate_store_artifact(&w2, &att, m);
        assert_not_green(label, "vi verify", &w2, &verify_args);
    }
    // A flipped character in the Layer 3 credential itself.
    let w2 = ws.fork();
    let p = w2.root.join("vi-out/l3a.sdjwt");
    let mut t = std::fs::read_to_string(&p).unwrap();
    let i = t.find('.').unwrap() + 5;
    let ch = t.as_bytes()[i] as char;
    t.replace_range(i..i + 1, if ch == 'A' { "B" } else { "A" });
    std::fs::write(&p, t).unwrap();
    assert_not_green("flipped credential", "vi verify", &w2, &verify_args);
}
