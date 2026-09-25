//! `checkpoint`, `merkle proof` and `merkle status` in JSON mode: whole
//! hashes and real numbers. In 0.31.9 status wrote 0 bytes and the other
//! two shortened the root to 16 hex and wrote numbers as strings (0.31.9
//! full test, CLI-10; the merkle half waited for W1-5).

use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Ship {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Ship {
    fn init() -> Self {
        let home = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let ship = Self { home, work };
        let out = ship.run(&["init", "--name", "merkle-json"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        ship
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .arg("--config")
            .arg(self.work.path().join(".treeship/config.json"))
            .output()
            .expect("run treeship")
    }

    fn json(&self, args: &[&str]) -> serde_json::Value {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "`treeship {}`: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "`treeship {}`: not JSON ({e}): {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }
}

fn is_full_root(v: &serde_json::Value) -> bool {
    v.as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .map(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false)
}

#[test]
fn checkpoint_proof_and_status_emit_whole_hashes_and_numbers() {
    let ship = Ship::init();
    let before = ship.json(&["merkle", "status", "--format", "json"]);
    assert_eq!(before["checkpoints"], 0, "{before}");
    assert!(before["latest"].is_null(), "{before}");

    let a = ship.json(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "one",
        "--format",
        "json",
    ]);
    let id = a["id"].as_str().unwrap().to_string();
    ship.json(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "two",
        "--format",
        "json",
    ]);

    let cp = ship.json(&["checkpoint", "--format", "json"]);
    assert!(
        is_full_root(&cp["root"]),
        "root is shortened or missing: {cp}"
    );
    assert!(
        cp["tree_size"].is_u64() && cp["index"].is_u64() && cp["height"].is_u64(),
        "numbers as strings: {cp}"
    );
    assert_eq!(cp["tree_size"], 2, "{cp}");

    let proof = ship.json(&["merkle", "proof", &id, "--format", "json"]);
    assert!(is_full_root(&proof["root"]), "{proof}");
    assert!(
        proof["leaf_hash"].as_str().is_some_and(|s| s.len() >= 64),
        "{proof}"
    );
    assert_eq!(proof["root"], cp["root"], "{proof}");
    assert!(
        proof["leaf_index"].is_u64() && proof["tree_size"].is_u64(),
        "{proof}"
    );
    assert!(
        std::path::Path::new(proof["file"].as_str().unwrap()).is_absolute()
            || ship
                .work
                .path()
                .join(proof["file"].as_str().unwrap())
                .exists()
    );

    let status = ship.json(&["merkle", "status", "--format", "json"]);
    assert_eq!(status["checkpoints"], 1, "{status}");
    assert_eq!(status["total_artifacts"], 2, "{status}");
    assert_eq!(status["uncheckpointed"], 0, "{status}");
    assert_eq!(status["latest"]["root"], cp["root"], "{status}");
    assert!(status["latest"]["tree_size"].is_u64(), "{status}");
}
