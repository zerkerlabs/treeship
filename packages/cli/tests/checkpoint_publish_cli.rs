//! `checkpoint --publish` seals and pushes in one command and exits nonzero
//! when the push fails; `checkpoint.every` shows in `doctor` only as it
//! actually runs (0.31.9 full test, WEB-4 / W4-4).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// A mock hub that answers every request with `status` and a JSON body,
/// for as many requests as the command makes, and counts them.
fn serve(
    status: &'static str,
    body: &'static str,
) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf);
                if let Some(end) = text.find("\r\n\r\n") {
                    let len = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (format!("http://{addr}"), hits)
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
        let out = ship.run(&["init", "--name", "cadence"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = ship.run(&["attest", "action", "--actor", "agent://a", "--action", "x"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        ship
    }

    fn config_path(&self) -> std::path::PathBuf {
        self.work.path().join(".treeship/config.json")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .arg("--config")
            .arg(self.config_path())
            .output()
            .expect("run treeship")
    }

    fn attach_fake_hub(&self, endpoint: &str) {
        let raw = std::fs::read_to_string(self.config_path()).unwrap();
        let mut cfg: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let key_id = cfg["default_key_id"].as_str().unwrap().to_string();
        cfg["hub_connections"]["local"] = serde_json::json!({
            "hub_id": "dock_test0000000000",
            "key_id": key_id,
            "endpoint": endpoint,
            "created_at": "2026-09-26T00:00:00Z",
            "hub_public_key": "00".repeat(32),
            "hub_secret_key": "11".repeat(32),
        });
        cfg["active_hub"] = serde_json::json!("local");
        std::fs::write(
            self.config_path(),
            serde_json::to_string_pretty(&cfg).unwrap(),
        )
        .unwrap();
    }

    /// Numbered checkpoint files under HOME's .treeship/merkle/checkpoints.
    /// `latest.json` is a pointer and `leaves/` holds leaf order, so neither
    /// counts as a sealed checkpoint.
    fn checkpoints(&self) -> usize {
        std::fs::read_dir(self.home.path().join(".treeship/merkle/checkpoints"))
            .map(|d| {
                d.flatten()
                    .filter(|e| {
                        e.path().extension().is_some_and(|ext| ext == "json")
                            && e.file_name() != "latest.json"
                    })
                    .count()
            })
            .unwrap_or(0)
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn publish_without_a_hub_seals_but_exits_nonzero() {
    let ship = Ship::init();
    let out = ship.run(&["checkpoint", "--publish"]);
    assert!(
        !out.status.success(),
        "no hub attached, yet exit 0:\n{}",
        text(&out)
    );
    assert_eq!(
        ship.checkpoints(),
        1,
        "the checkpoint itself should still be sealed"
    );
}

#[test]
fn publish_to_a_hub_that_accepts_exits_zero_and_one_that_fails_exits_nonzero() {
    let ship = Ship::init();
    let (ok_hub, hits) = serve("200 OK", r#"{"id":1}"#);
    ship.attach_fake_hub(&ok_hub);
    let out = ship.run(&["checkpoint", "--publish"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        hits.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "nothing reached the hub"
    );

    let (bad_hub, _) = serve("500 Internal Server Error", r#"{"error":"boom"}"#);
    ship.attach_fake_hub(&bad_hub);
    let out = ship.run(&["checkpoint", "--publish"]);
    assert!(
        !out.status.success(),
        "push failed, yet exit 0:\n{}",
        text(&out)
    );
    assert_eq!(
        ship.checkpoints(),
        2,
        "each --publish seals before it pushes"
    );
}

/// One JSON document per command, and the publish result inside it:
/// 0.31.10 wrote 0 bytes for `--format json merkle publish` and gave
/// `checkpoint --publish` the same document as a plain `checkpoint`.
#[test]
fn publish_and_checkpoint_publish_report_the_publish_in_json() {
    let ship = Ship::init();
    let (hub, hits) = serve("200 OK", r#"{"id":41}"#);
    ship.attach_fake_hub(&hub);
    let out = ship.run(&["checkpoint", "--publish", "--format", "json"]);
    assert!(out.status.success(), "{}", text(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("not one JSON document ({e}):\n{}", text(&out)));
    assert_eq!(doc["status"], "ok");
    assert!(doc["root"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(doc["publish"]["status"], "ok", "{doc}");
    assert_eq!(doc["publish"]["hub_checkpoint_id"], 41, "{doc}");
    assert!(doc["publish"]["proofs_published"].is_u64(), "{doc}");
    assert!(doc["publish"]["consistency"]["status"].is_string(), "{doc}");
    assert!(hits.load(std::sync::atomic::Ordering::SeqCst) >= 1);

    let out = ship.run(&["merkle", "publish", "--format", "json"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        !out.stdout.is_empty(),
        "merkle publish wrote nothing on success"
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("not one JSON document ({e}):\n{}", text(&out)));
    assert_eq!(doc["status"], "ok");
    assert_eq!(doc["hub_checkpoint_id"], 41);
    assert_eq!(doc["index"], 1);

    // A plain checkpoint carries no publish result.
    let out = ship.run(&["checkpoint", "--format", "json"]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(doc.get("publish").is_none(), "{doc}");
}

#[test]
fn doctor_reports_the_cadence_only_as_it_runs() {
    let ship = Ship::init();
    let yaml = ship.work.path().join(".treeship/config.yaml");
    let mut text_yaml = std::fs::read_to_string(&yaml).unwrap_or_default();
    text_yaml.push_str("\ncheckpoint:\n  every: 6h\n");
    std::fs::write(&yaml, text_yaml).unwrap();

    let out = ship.run(&["doctor", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("doctor JSON: {e}\n{}", text(&out)));
    let row = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["label"] == "checkpoint cadence")
        .unwrap_or_else(|| panic!("no cadence row: {v}"));
    // No daemon runs in this test, so the row must say nothing publishes.
    assert_eq!(row["status"], "warn", "{row}");
    assert!(
        row["detail"].as_str().unwrap().contains("every 6h"),
        "{row}"
    );
    assert!(
        row["detail"]
            .as_str()
            .unwrap()
            .contains("nothing publishes"),
        "{row}"
    );
}
