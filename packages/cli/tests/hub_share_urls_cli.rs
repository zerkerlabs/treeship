//! After pushing to a self-hosted hub, the CLI printed treeship.dev share
//! URLs (0.31.9 full test, CLI-12). The URL comes from the hub's reply, so
//! the fix is mostly in the hub; this test pins the CLI's side: it prints
//! the URL the hub returned, and when the hub returns none it derives one
//! from the attached endpoint, never from treeship.dev.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// A one-shot HTTP server: reads one request (headers + Content-Length body),
/// answers with the body `reply` builds from the server's own endpoint, and
/// hands back the request it saw.
fn serve_once(reply: impl FnOnce(&str) -> String) -> (String, std::sync::mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{addr}");
    let body = reply(&endpoint);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
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
            let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });
    (endpoint, rx)
}

struct Ship {
    _home: tempfile::TempDir,
    work: tempfile::TempDir,
    config: std::path::PathBuf,
}

impl Ship {
    fn init() -> Self {
        let home = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let config = work.path().join(".treeship/config.json");
        let ship = Self {
            _home: home,
            work,
            config,
        };
        let out = ship.run(&["init", "--name", "share-urls"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        ship
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self._home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .arg("--config")
            .arg(&self.config)
            .output()
            .expect("run treeship")
    }

    /// Attach a hub connection by writing it into config.json: the same
    /// shape `hub attach` writes, with a legacy plaintext DPoP secret so no
    /// keystore sealing is needed.
    fn attach_fake_hub(&self, endpoint: &str) {
        let raw = std::fs::read_to_string(&self.config).unwrap();
        let mut cfg: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let key_id = cfg["default_key_id"].as_str().unwrap().to_string();
        cfg["hub_connections"]["local"] = serde_json::json!({
            "hub_id": "dock_test0000000000",
            "key_id": key_id,
            "endpoint": endpoint,
            "created_at": "2026-09-25T00:00:00Z",
            "hub_public_key": "00".repeat(32),
            "hub_secret_key": "11".repeat(32),
        });
        cfg["active_hub"] = serde_json::json!("local");
        std::fs::write(&self.config, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
    }
}

fn push_json(ship: &Ship) -> serde_json::Value {
    let out = ship.run(&["hub", "push", "last", "--format", "json"]);
    assert!(
        out.status.success(),
        "push: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "push stdout is not JSON: {e}\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

#[test]
fn push_prints_the_url_the_hub_returned() {
    let ship = Ship::init();
    let out = ship.run(&["attest", "action", "--actor", "agent://a", "--action", "x"]);
    assert!(out.status.success());
    // The hub answers with a URL under its own origin; the CLI must print
    // that URL, not one it made up.
    let (endpoint, _seen) = serve_once(|endpoint| {
        format!(
            r#"{{"artifact_id":"art_from_hub","hub_url":"{endpoint}/v1/artifacts/art_from_hub"}}"#
        )
    });
    let hub_url = format!("{endpoint}/v1/artifacts/art_from_hub");
    ship.attach_fake_hub(&endpoint);
    let v = push_json(&ship);
    assert_eq!(v["url"].as_str(), Some(hub_url.as_str()), "{v}");
}

#[test]
fn push_derives_the_url_from_the_attached_hub_when_the_hub_returns_none() {
    let ship = Ship::init();
    let out = ship.run(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "x",
        "--format",
        "json",
    ]);
    assert!(out.status.success());
    let attested: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let id = attested["id"].as_str().unwrap().to_string();

    let (endpoint, seen) = serve_once(|_| format!(r#"{{"artifact_id":"{id}"}}"#));
    ship.attach_fake_hub(&endpoint);
    let v = push_json(&ship);
    let url = v["url"].as_str().unwrap_or("");
    assert_eq!(url, format!("{endpoint}/v1/artifacts/{id}"), "{v}");
    assert!(!url.contains("treeship.dev"), "{v}");
    let req = seen.recv().unwrap();
    assert!(req.starts_with("POST /v1/artifacts "), "{req}");
}
