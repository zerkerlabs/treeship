//! Retest 2026-09-27, track 1, new bugs 4, 7 and the P3s: hints that leave
//! out required flags, arguments accepted without validation, a removal that
//! reports success for nothing, a second `init` that reads as a failure of
//! the wrong thing, and a self-hosted hub's session token sent to
//! treeship.dev.

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
        // A workspace of its own (a plain `init` writes a stub that extends
        // the global config, and a stub's hub fields are ignored).
        let config = ship.config();
        let out = ship.run(&["init", "--name", "t", "--config", &config]);
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
        self.run_in(self.work.path(), args)
    }
    fn run_in(&self, dir: &std::path::Path, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(dir)
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

/// A one-answer HTTP server: every request gets `status` and `body`.
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

#[test]
fn match_refuses_an_unknown_class_before_asking_the_hub() {
    let ship = Ship::init();
    // Nothing listens on TCP 1; a network attempt would fail differently.
    let out = ship.run(&[
        "match",
        "--hub",
        "http://127.0.0.1:1",
        "--exercised",
        "Bash(git:*)",
        "--class",
        "bogus",
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(text(&out).contains("countersigned"), "{}", text(&out));
}

#[test]
fn room_create_refuses_a_delegate_that_is_not_a_key() {
    let ship = Ship::init();
    let out = ship.run(&[
        "room",
        "create",
        "--invitation-authority",
        "delegated",
        "--delegate",
        "bogus",
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(text(&out).contains("ed25519:"), "{}", text(&out));
    assert!(
        !ship.work.path().join(".treeship/session.json").exists(),
        "a room was created around a delegate that can never sign"
    );
}

#[test]
fn agents_remove_of_a_missing_card_is_an_error() {
    let ship = Ship::init();
    let out = ship.run(&["agents", "remove", "agent_000000000000missing"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("no agent card"), "{}", text(&out));
    assert!(!text(&out).contains("removed"), "{}", text(&out));
}

#[test]
fn a_second_init_in_a_fresh_directory_says_the_global_workspace_exists() {
    let ship = Ship::init();
    // A plain `init` somewhere else creates the global workspace in HOME
    // (and a stub there); the fresh directory below then has no workspace
    // of its own while the global one exists.
    let elsewhere = tempfile::tempdir().unwrap();
    let out = ship.run_in(elsewhere.path(), &["init", "--name", "global"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(ship.home.path().join(".treeship/config.json").is_file());
    let fresh = tempfile::tempdir().unwrap();
    let out = ship.run_in(fresh.path(), &["init", "--name", "again"]);
    assert!(!out.status.success(), "{}", text(&out));
    let t = text(&out);
    assert!(t.contains("no Treeship workspace of its own"), "{t}");
    assert!(t.contains("global workspace at"), "{t}");
    assert!(t.contains("nothing was changed"), "{t}");
    assert!(!t.contains("already initialized"), "{t}");
    assert!(
        t.contains("treeship init --config .treeship/config.json"),
        "{t}"
    );
    assert!(!t.contains("no Treeship workspace here"), "{t}");
}

#[test]
fn hub_open_on_a_self_hosted_hub_keeps_the_token_on_that_hub() {
    let ship = Ship::init();
    let hub = serve("200 OK", r#"{"token":"tok_local_secret"}"#);
    ship.attach_fake_hub(&hub);
    let out = ship.run(&["hub", "open", "--no-open", "--config", &ship.config()]);
    assert!(out.status.success(), "{}", text(&out));
    let t = text(&out);
    let line = t
        .lines()
        .find(|l| l.contains("session=tok_local_secret"))
        .unwrap_or_else(|| panic!("no workspace URL printed:\n{t}"));
    assert!(line.trim().starts_with(&hub), "{line}");
    assert!(
        !t.contains("treeship.dev"),
        "the local hub's token went to treeship.dev:\n{t}"
    );
}

#[test]
fn init_help_does_not_call_the_key_machine_bound() {
    let ship = Ship::init();
    let out = ship.run(&["init", "--help"]);
    let t = text(&out);
    assert!(!t.contains("machine's identity"), "{t}");
    assert!(!t.contains("tied to this machine"), "{t}");
    assert!(t.contains("seed file"), "{t}");
}
