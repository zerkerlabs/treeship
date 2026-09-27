//! `treeship hub unpublish`: a DPoP-signed DELETE to the hub, and honest
//! exits when the hub refuses.

use std::io::{Read, Write};
use std::net::TcpListener;
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
        let ship = Self {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        };
        let cfg = ship.config();
        let out = ship.run(&["init", "--name", "t", "--config", &cfg]);
        assert!(out.status.success(), "{}", text(&out));
        ship
    }
    fn config(&self) -> String {
        self.work
            .path()
            .join(".treeship/config.json")
            .to_string_lossy()
            .into_owned()
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .output()
            .expect("run treeship")
    }
    fn attach_fake_hub(&self, endpoint: &str) {
        let path = self.work.path().join(".treeship/config.json");
        let mut cfg: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let key_id = cfg["default_key_id"].as_str().unwrap().to_string();
        cfg["hub_connections"]["local"] = serde_json::json!({
            "hub_id": "dock_test0000000000",
            "key_id": key_id,
            "endpoint": endpoint,
            "created_at": "2026-09-27T00:00:00Z",
            "hub_public_key": "00".repeat(32),
            "hub_secret_key": "11".repeat(32),
        });
        cfg["active_hub"] = serde_json::json!("local");
        std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// One-answer server that also records the request line and headers.
fn serve(
    status: &'static str,
    body: &'static str,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
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
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf).into_owned());
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (format!("http://{addr}"), seen)
}

#[test]
fn unpublish_sends_a_dpop_signed_delete_and_reports_the_tombstone() {
    let ship = Ship::init();
    let (hub, seen) = serve(
        "200 OK",
        r#"{"session_id":"ssn_0123456789abcdef","status":"tombstoned","tombstoned_at":1759000000}"#,
    );
    ship.attach_fake_hub(&hub);
    let cfg = ship.config();
    let out = ship.run(&[
        "hub",
        "unpublish",
        "ssn_0123456789abcdef",
        "--reason",
        "leaked paths",
        "--format",
        "json",
        "--config",
        &cfg,
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["status"], "ok");
    assert_eq!(doc["tombstoned_at"], 1759000000);
    let requests = seen.lock().unwrap();
    let req = requests.first().expect("no request reached the hub");
    assert!(
        req.starts_with("DELETE /v1/receipt/ssn_0123456789abcdef "),
        "{req}"
    );
    assert!(
        req.contains("Authorization: DPoP dock_test0000000000"),
        "{req}"
    );
    assert!(req.to_ascii_lowercase().contains("dpop: "), "{req}");
    assert!(req.contains("leaked paths"), "{req}");
}

#[test]
fn unpublish_by_another_dock_is_refused_and_exits_nonzero() {
    let ship = Ship::init();
    let (hub, _) = serve(
        "403 Forbidden",
        r#"{"error":"session_id is owned by another dock"}"#,
    );
    ship.attach_fake_hub(&hub);
    let cfg = ship.config();
    let out = ship.run(&["hub", "unpublish", "ssn_0123456789abcdef", "--config", &cfg]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("only the publisher"), "{}", text(&out));
    let out = ship.run(&["hub", "unpublish", "not-a-session", "--config", &cfg]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
}
