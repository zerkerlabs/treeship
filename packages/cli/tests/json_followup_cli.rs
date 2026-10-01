//! One JSON document on stdout, errors on stderr, shell-like exit codes:
//! the three overclaims left after 0.31.11 (A) and the notes beside them.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// stdout parses as exactly one JSON document.
fn one_document(out: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}):\n{}", text(out)))
}

struct Ship {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Ship {
    fn init() -> Self {
        let ship = Self {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        };
        let out = ship.run(&["init", "--name", "j"]);
        assert!(out.status.success(), "{}", text(&out));
        ship
    }
    fn cfg(&self) -> std::path::PathBuf {
        self.work.path().join(".treeship/config.json")
    }
    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .env_remove("TREESHIP_PARENT");
        c
    }
    fn run(&self, args: &[&str]) -> Output {
        self.cmd()
            .args(args)
            .arg("--config")
            .arg(self.cfg())
            .output()
            .expect("run treeship")
    }
    fn attach_fake_hub(&self, endpoint: &str) {
        let raw = std::fs::read_to_string(self.cfg()).unwrap();
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
        std::fs::write(self.cfg(), serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
    }
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

/// A hub that answers every request with `status` and `body`.
fn serve(status: &'static str, body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
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
                let t = String::from_utf8_lossy(&buf);
                if let Some(end) = t.find("\r\n\r\n") {
                    let len = t[..end]
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
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}")
}

// R2: `--out -` in JSON mode puts the envelope inside the one result document.
#[test]
fn attest_out_stdout_in_json_mode_is_one_document_with_the_envelope() {
    let ship = Ship::init();
    let out = ship.run(&[
        "--format",
        "json",
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "x",
        "--out",
        "-",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let doc = one_document(&out);
    assert_eq!(doc["status"], "ok", "{doc}");
    assert!(doc["id"].as_str().unwrap().starts_with("art_"), "{doc}");
    assert!(
        doc["envelope"]["payload"].is_string(),
        "the envelope is not in the document: {doc}"
    );
    assert!(doc["envelope"]["signatures"].is_array(), "{doc}");

    let out = ship.run(&[
        "--format",
        "json",
        "attest",
        "endorsement",
        "--endorser",
        "agent://b",
        "--subject",
        doc["id"].as_str().unwrap(),
        "--kind",
        "review",
        "--out",
        "-",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let doc = one_document(&out);
    assert!(doc["envelope"]["payload"].is_string(), "{doc}");

    // Text mode still prints the raw envelope, then the result.
    let out = ship.run(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "y",
        "--out",
        "-",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim_start().starts_with('{') && stdout.contains("action attested"),
        "{stdout}"
    );
}

// `--quiet` silences commentary, not output that was asked for: with
// `--out -` the envelope still arrives, inside the one JSON document.
#[test]
fn quiet_json_attest_out_stdout_still_prints_the_envelope_document() {
    let ship = Ship::init();
    let action = ship.run(&[
        "--quiet",
        "--format",
        "json",
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "x",
        "--out",
        "-",
    ]);
    assert!(action.status.success(), "{}", text(&action));
    let doc = one_document(&action);
    assert!(doc["envelope"]["payload"].is_string(), "{doc}");
    let id = doc["id"].as_str().unwrap().to_string();

    let out = ship.run(&[
        "--quiet",
        "--format",
        "json",
        "attest",
        "endorsement",
        "--endorser",
        "agent://b",
        "--subject",
        &id,
        "--kind",
        "review",
        "--out",
        "-",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(one_document(&out)["envelope"]["signatures"].is_array());

    // Without --out, quiet JSON stays silent as before.
    let out = ship.run(&[
        "--quiet",
        "--format",
        "json",
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "y",
    ]);
    assert!(
        out.status.success() && out.stdout.is_empty(),
        "{}",
        text(&out)
    );
}

// R3: no hub in JSON mode is an error on stderr, not a report on stdout.
#[test]
fn session_report_without_a_hub_in_json_mode_errors_on_stderr() {
    let ship = Ship::init();
    assert!(ship
        .run(&["session", "start", "--name", "s", "--actor", "agent://a"])
        .status
        .success());
    let out = ship.run(&["session", "close", "--format", "json"]);
    assert!(out.status.success(), "{}", text(&out));
    let out = ship.run(&["session", "report", "--format", "json"]);
    assert!(
        !out.status.success(),
        "no hub attached, yet exit 0:\n{}",
        text(&out)
    );
    assert!(
        out.stdout.is_empty(),
        "an error document went to stdout:\n{}",
        text(&out)
    );
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap_or_else(|e| {
        panic!(
            "stderr is not one JSON error document ({e}):\n{}",
            text(&out)
        )
    });
    assert_eq!(err["status"], "error", "{err}");
    assert!(
        err["error"].as_str().unwrap().contains("--no-upload"),
        "{err}"
    );

    // The local verdict is one flag away, as one document.
    let out = ship.run(&["session", "report", "--format", "json", "--no-upload"]);
    assert!(out.status.success(), "{}", text(&out));
    let doc = one_document(&out);
    assert!(doc["verification_status"].is_string(), "{doc}");
}

// R1: `add` in JSON mode prints one document whatever it finds.
#[test]
fn add_in_json_mode_prints_one_document() {
    let ship = Ship::init();
    // Nothing is installed under a fresh HOME.
    let out = ship
        .cmd()
        .args(["--format", "json", "add", "--dry-run", "--all"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let doc = one_document(&out);
    assert_eq!(doc["status"], "ok", "{doc}");
    assert!(
        doc["configured"].is_array() && doc["skipped"].is_array() && doc["failed"].is_array(),
        "{doc}"
    );
    assert_eq!(doc["dry_run"], true, "{doc}");

    // A harness that is present: Hermes is detected from a config directory.
    std::fs::create_dir_all(ship.home.path().join(".hermes")).unwrap();
    let out = ship
        .cmd()
        .args(["--format", "json", "add", "--dry-run", "--all"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let doc = one_document(&out);
    let n = doc["configured"].as_array().map(|a| a.len()).unwrap_or(0)
        + doc["skipped"].as_array().map(|a| a.len()).unwrap_or(0)
        + doc["failed"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        n >= 1
            || doc["detected"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true),
        "{doc}"
    );

    let out = ship
        .cmd()
        .args(["--format", "json", "add", "--dry-run", "no-such-agent"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let doc = one_document(&out);
    assert_eq!(
        doc["requested"],
        serde_json::json!(["no-such-agent"]),
        "{doc}"
    );
}

// N1: a failed publish still reports the sealed checkpoint, once.
#[test]
fn checkpoint_publish_failure_reports_the_sealed_checkpoint_in_json() {
    let ship = Ship::init();
    assert!(ship
        .run(&["attest", "action", "--actor", "agent://a", "--action", "x"])
        .status
        .success());
    ship.attach_fake_hub(&serve("500 Internal Server Error", r#"{"error":"boom"}"#));
    let out = ship.run(&["checkpoint", "--publish", "--format", "json"]);
    assert!(
        !out.status.success(),
        "publish failed, yet exit 0:\n{}",
        text(&out)
    );
    let doc = one_document(&out);
    assert!(
        doc["root"].as_str().unwrap().starts_with("sha256:"),
        "{doc}"
    );
    assert_eq!(doc["publish"]["ok"], false, "{doc}");
    assert_eq!(doc["publish"]["status"], "failed", "{doc}");
    assert!(
        doc["publish"]["error"]
            .as_str()
            .is_some_and(|e| !e.is_empty()),
        "{doc}"
    );
    assert_eq!(ship.checkpoints(), 1, "the checkpoint was sealed");
}

// N2 / N4: signal deaths and unstartable commands, as a shell reports them.
#[cfg(unix)]
#[test]
fn wrap_reports_a_signal_death_as_128_plus_signal_with_the_signal_named() {
    let ship = Ship::init();
    let out = ship
        .cmd()
        .args(["--format", "json", "--config"])
        .arg(ship.cfg())
        .args(["wrap", "--", "sh", "-c", "kill -9 $$"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(137), "{}", text(&out));
    let doc = one_document(&out);
    assert_eq!(doc["exit_code"], 137, "{doc}");
    assert_eq!(doc["signal"], 9, "{doc}");
    assert_eq!(doc["succeeded"], false, "{doc}");

    let out = ship
        .cmd()
        .args(["--format", "json", "--config"])
        .arg(ship.cfg())
        .args(["wrap", "--", "true"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(one_document(&out)["signal"].is_null());
}

#[test]
fn wrap_exits_127_when_the_command_cannot_start() {
    let ship = Ship::init();
    for format in [&["--format", "json"][..], &[][..]] {
        let out = ship
            .cmd()
            .args(format)
            .arg("--config")
            .arg(ship.cfg())
            .args(["wrap", "--", "/nonexistent/binary/for/treeship", "x"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(127), "{}", text(&out));
        assert!(
            out.stdout.is_empty(),
            "nothing to attest, yet stdout has output:\n{}",
            text(&out)
        );
        assert!(text(&out).contains("could not start"), "{}", text(&out));
    }
}
