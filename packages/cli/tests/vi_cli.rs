//! `treeship vi` end to end on an isolated ship: import the reference
//! fixture's agent key, check a purchase, sign the Layer 3 pair at the end
//! of a real receipt chain, verify it locally, and watch the failure modes
//! fail (outside the mandate, tampered credential, wrong presentation).

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
        let out = ws
            .cmd()
            .args(["init", "--name", "vi-test", "--config"])
            .arg(ws.config())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ws
    }
    fn config(&self) -> PathBuf {
        self.root.join(".treeship/config.json")
    }
    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root);
        c.env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1");
        c.current_dir(&self.root);
        c
    }
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let out = self
            .cmd()
            .args(args)
            .arg("--config")
            .arg(self.config())
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }
    fn json(&self, args: &[&str]) -> Value {
        let (ok, stdout, stderr) = self.run(&[args, &["--format", "json"]].concat());
        assert!(ok, "{:?} failed: {stdout}\n{stderr}", args);
        serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("json from {:?}: {e}\n{stdout}", args))
    }
    fn write(&self, name: &str, content: &str) -> String {
        let p = self.root.join(name);
        std::fs::write(&p, content).unwrap();
        p.display().to_string()
    }
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../core/tests/fixtures/vi/reference-v0.1.json"
    ))
    .unwrap()
}

/// Files from the fixture, the imported agent key, and a three-artifact
/// session chain to attest at the end of.
fn prepared() -> (Ws, Value) {
    let ws = Ws::new();
    let fx = fixture();
    ws.write("l1.sdjwt", fx["l1"].as_str().unwrap());
    ws.write("l2.sdjwt", fx["l2"].as_str().unwrap());
    ws.write("checkout.jwt", fx["checkout_jwt"].as_str().unwrap());
    ws.write("agent.jwk", &fx["agent_private_jwk"].to_string());
    ws.write("issuer.jwk", &fx["issuer_public_jwk"].to_string());
    let imported = ws.json(&[
        "vi",
        "keys",
        "import",
        "--jwk",
        "agent.jwk",
        "--label",
        "reference",
    ]);
    assert_eq!(imported["kid"], "agent-key-1");

    let (ok, _, err) = ws.run(&[
        "session",
        "start",
        "--name",
        "vi-cli",
        "--actor",
        "agent://shopping",
    ]);
    assert!(ok, "{err}");
    let root = ws.json(&["session", "status"])["root_artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let a1 = ws.json(&[
        "attest",
        "action",
        "--actor",
        "agent://shopping",
        "--action",
        "commerce.tool.search_products.intent",
        "--parent",
        &root,
    ]);
    let id1 = a1["id"]
        .as_str()
        .or_else(|| a1["artifact_id"].as_str())
        .unwrap()
        .to_string();
    let a2 = ws.json(&[
        "attest",
        "action",
        "--actor",
        "agent://shopping",
        "--action",
        "commerce.checkout.handoff",
        "--parent",
        &id1,
    ]);
    let id2 = a2["id"]
        .as_str()
        .or_else(|| a2["artifact_id"].as_str())
        .unwrap()
        .to_string();
    (ws, serde_json::json!({"root": root, "head": id2}))
}

const PURCHASE: &[&str] = &[
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

#[test]
fn keygen_lists_and_exports_a_public_jwk() {
    let ws = Ws::new();
    let k = ws.json(&["vi", "keygen", "--label", "shop"]);
    let kid = k["kid"].as_str().unwrap();
    assert!(kid.starts_with("vik_"));
    assert_eq!(k["public_jwk"]["crv"], "P-256");
    assert_eq!(k["public_jwk"]["kid"], kid);
    assert!(
        k["public_jwk"].get("d").is_none(),
        "keygen must never print the private scalar"
    );
    let list = ws.json(&["vi", "keys", "list"]);
    assert_eq!(list["keys"].as_array().unwrap().len(), 1);
    let exp = ws.json(&["vi", "keys", "export"]);
    assert_eq!(exp["public_jwk"]["x"], k["public_jwk"]["x"]);
}

#[test]
fn check_passes_inside_the_mandate_and_exits_1_outside() {
    let (ws, _) = prepared();
    let r = ws.json(&[&["vi", "check"], PURCHASE].concat());
    assert_eq!(r["satisfied"], true, "{r}");
    assert!(r["checked"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "mandate.payment.amount_range"));
    let (ok, stdout, _) = ws.run(&[
        "vi",
        "check",
        "--mandate",
        "l2.sdjwt",
        "--merchant",
        "merchant-uuid-1",
        "--item",
        "BAB86345",
        "--amount",
        "40001",
        "--format",
        "json",
    ]);
    assert!(!ok);
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["status"], "violation");
    assert!(v["violations"][0]
        .as_str()
        .unwrap()
        .contains("exceeds maximum"));
    let (ok, _, err) = ws.run(&[
        "vi",
        "check",
        "--mandate",
        "l2.sdjwt",
        "--merchant",
        "nobody",
        "--item",
        "BAB86345",
        "--amount",
        "100",
    ]);
    assert!(!ok && err.contains("not in the mandate"), "{err}");
}

#[test]
fn attest_then_verify_locally_with_l1_and_issuer() {
    let (ws, ids) = prepared();
    let head = ids["head"].as_str().unwrap();
    let s = ws.json(
        &[
            &["vi", "attest"],
            PURCHASE,
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
    assert_eq!(s["status"], "ok");
    assert_eq!(s["attestation"]["chain_head"], head);
    assert_eq!(s["attestation"]["chain_length"], 3);
    assert_eq!(s["attestation"]["reaches_session_root"], true);
    assert!(s["attestation"]["checkpoint"]
        .as_str()
        .unwrap()
        .starts_with("mroot_"));
    assert_eq!(s["attestation"]["recorded"], true);
    for f in [
        "l3a.sdjwt",
        "l3b.sdjwt",
        "l2-payment.sdjwt",
        "l2-checkout.sdjwt",
        "attestation.json",
        "summary.json",
    ] {
        assert!(ws.root.join("vi-out").join(f).exists(), "{f}");
    }
    // The attestation is now the chain head, chained onto the previous one.
    let att_id = s["attestation"]["artifact_id"].as_str().unwrap();
    let v = ws.json(&["verify", att_id]);
    assert_eq!(v["outcome"], "pass");
    assert_eq!(v["total"], 4);

    let r = ws.json(&[
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
    ]);
    assert_eq!(r["outcome"], "pass", "{r}");
    assert_eq!(r["failed"], 0);
    assert_eq!(r["attestation"]["chain_head"], head);
    let names: Vec<&str> = r["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    for must in [
        "l1_signature",
        "l2_signature",
        "l2_sd_hash",
        "l3a_signature",
        "l3b_signature",
        "l3a_sd_hash",
        "l3b_sd_hash",
        "l3_cross_reference",
        "l3a_constraints",
        "l3b_constraints",
        "l3a_attestation",
        "attestation_mandate_digest",
        "local_checkpoint",
    ] {
        assert!(names.contains(&must), "missing check {must}: {names:?}");
    }
}

#[test]
fn attest_refuses_outside_the_mandate_and_signs_nothing() {
    let (ws, _) = prepared();
    let before = ws.json(&["session", "status"])["receipts"].clone();
    let (ok, _, err) = ws.run(&[
        "vi",
        "attest",
        "--mandate",
        "l2.sdjwt",
        "--merchant",
        "merchant-uuid-1",
        "--item",
        "BAB86345",
        "--amount",
        "40001",
        "--checkout-jwt",
        "checkout.jwt",
        "--aud-network",
        "x",
        "--aud-merchant",
        "y",
        "--out",
        "vi-bad",
    ]);
    assert!(!ok && err.contains("refused"), "{err}");
    assert!(!ws.root.join("vi-bad").exists());
    assert_eq!(
        ws.json(&["session", "status"])["receipts"],
        before,
        "a refused attest must not add a receipt"
    );
}

#[test]
fn a_tampered_half_or_the_wrong_presentation_fails() {
    let (ws, _) = prepared();
    ws.json(
        &[
            &["vi", "attest"],
            PURCHASE,
            &[
                "--checkout-jwt",
                "checkout.jwt",
                "--aud-network",
                "https://www.mastercard.com",
                "--aud-merchant",
                "https://tennis-warehouse.com",
                "--out",
                "vi-out",
            ],
        ]
        .concat(),
    );
    let l3b = std::fs::read_to_string(ws.root.join("vi-out/l3b.sdjwt")).unwrap();
    let (jwt, rest) = l3b.split_once('~').unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    let payload = treeship_core::vi::jws::b64u_decode(parts[1]).unwrap();
    let edited = String::from_utf8(payload)
        .unwrap()
        .replace("tennis-warehouse", "evil");
    let tampered = format!(
        "{}.{}.{}~{}",
        parts[0],
        treeship_core::vi::jws::b64u(edited.as_bytes()),
        parts[2],
        rest
    );
    ws.write("l3b-tampered.sdjwt", &tampered);
    let (ok, stdout, _) = ws.run(&[
        "vi",
        "verify",
        "--mandate",
        "l2.sdjwt",
        "--l3b",
        "l3b-tampered.sdjwt",
        "--l2-checkout",
        "vi-out/l2-checkout.sdjwt",
        "--format",
        "json",
    ]);
    assert!(!ok);
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "l3b_signature" && c["pass"] == false));
    // Right credential, wrong presentation: sd_hash does not bind.
    let (ok, stdout, _) = ws.run(&[
        "vi",
        "verify",
        "--mandate",
        "l2.sdjwt",
        "--l3a",
        "vi-out/l3a.sdjwt",
        "--l2-payment",
        "vi-out/l2-checkout.sdjwt",
        "--format",
        "json",
    ]);
    assert!(!ok);
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "l3a_sd_hash" && c["pass"] == false));
}
