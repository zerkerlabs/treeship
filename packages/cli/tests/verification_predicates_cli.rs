//! The two verification predicates end to end through the CLI: a prover
//! signs a `verification.packet.v1` receipt, a verifier signs a
//! `verification.recompute.v1` receipt about it, the pair chains, and a
//! payload outside the vocabulary is refused before anything is signed.

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

const PACKET: &str = r#"{"schema":"verification.packet.v1","packet_id":"pkt_000042","stream_id":"tap-7/req-9f2a","sequence":42,"prev_packet_id":"pkt_000041","model_digest":"sha256:aa11","input_digest":"sha256:bb22","output_digest":"sha256:cc33","reproducibility":"bit_exact","produced_at":"2026-09-17T15:00:00Z"}"#;

#[test]
fn packet_then_recompute_chain_and_verify() {
    let ws = Ws::new();

    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "system://prover-dc-1",
        "--kind",
        "verification.packet.v1",
        "--payload",
        PACKET,
        "--format",
        "json",
    ]);
    assert!(ok, "packet receipt: {out}");
    let packet: Value = serde_json::from_str(out.trim()).unwrap();
    let packet_id = packet["id"].as_str().unwrap().to_string();
    assert!(packet_id.starts_with("art_"));

    let recompute = format!(
        r#"{{"schema":"verification.recompute.v1","packet":"{packet_id}","packet_id":"pkt_000042","method":"difr","verdict":"match","distance":0.0012,"threshold":0.01,"sample_seed":"seed-2026-09-17-a","recomputed_at":"2026-09-17T15:05:00Z"}}"#
    );
    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "system://verifier-recompute-1",
        "--kind",
        "verification.recompute.v1",
        "--subject",
        &packet_id,
        "--payload",
        &recompute,
        "--format",
        "json",
    ]);
    assert!(ok, "recompute receipt: {out}");
    let result: Value = serde_json::from_str(out.trim()).unwrap();
    let result_id = result["id"].as_str().unwrap().to_string();

    // The result verifies, and the walk reaches the packet it checks: two
    // artifacts on an intact chain, and the full timeline names the packet.
    let (ok, out) = ws.run(&["verify", &result_id]);
    assert!(ok, "verify: {out}");
    assert!(
        out.contains("2 artifacts") && out.contains("chain intact"),
        "verify should walk from the result to the packet receipt: {out}"
    );
    let (ok, out) = ws.run(&["verify", &result_id, "--full"]);
    assert!(ok, "verify --full: {out}");
    assert!(
        out.contains(&packet_id[..16]),
        "the full timeline should name the packet receipt: {out}"
    );
}

#[test]
fn out_of_vocabulary_verdict_is_refused_before_signing() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "system://verifier-recompute-1",
        "--kind",
        "verification.recompute.v1",
        "--payload",
        r#"{"schema":"verification.recompute.v1","packet":"art_0123","packet_id":"pkt_1","method":"difr","verdict":"mostly","recomputed_at":"2026-09-17T15:05:00Z"}"#,
    ]);
    assert!(!ok, "a verdict outside the enum must be refused: {out}");
    assert!(out.contains("verdict"), "{out}");
}

#[test]
fn packet_missing_output_digest_is_refused_before_signing() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "system://prover-dc-1",
        "--kind",
        "verification.packet.v1",
        "--payload",
        r#"{"schema":"verification.packet.v1","packet_id":"pkt_1","stream_id":"s","sequence":0,"model_digest":"sha256:aa","input_digest":"sha256:bb","produced_at":"2026-09-17T15:00:00Z"}"#,
    ]);
    assert!(!ok, "{out}");
    assert!(out.contains("output_digest"), "{out}");
}
