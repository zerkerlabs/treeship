//! OpenTelemetry export in the default build: `treeship otel` works without
//! a rebuild, sends an OTLP/HTTP JSON span to whatever `TREESHIP_OTEL_ENDPOINT`
//! names, and never fails `session close` when the collector is unreachable.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

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
            .env_remove("TREESHIP_OTEL_ENDPOINT")
            .env_remove("TREESHIP_OTEL_ENABLED")
            .current_dir(&self.root);
        c
    }
    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
        let mut c = self.cmd();
        for (k, v) in env {
            c.env(k, v);
        }
        let out = c
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
    fn run(&self, args: &[&str]) -> (bool, String) {
        self.run_env(args, &[])
    }
}

fn first_json(out: &str) -> Value {
    let start = out.find('{').expect("json object in output");
    let mut de = serde_json::Deserializer::from_str(&out[start..]);
    Value::deserialize(&mut de).expect("parse json")
}

/// A one-shot OTLP collector: accepts one HTTP request, answers 200, and
/// hands the request head and body back on the channel.
fn one_shot_collector() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        // Read until the body announced by Content-Length is complete.
        let mut expected_total: Option<usize> = None;
        loop {
            let n = match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            buf.extend_from_slice(&chunk[..n]);
            if expected_total.is_none() {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let len = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    expected_total = Some(pos + 4 + len);
                }
            }
            if let Some(t) = expected_total {
                if buf.len() >= t {
                    break;
                }
            }
        }
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
    });
    (format!("http://{addr}"), rx)
}

#[test]
fn otel_status_without_endpoint_says_not_configured_and_exits_zero() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["otel", "status"]);
    assert!(ok, "{out}");
    assert!(out.contains("otel not configured"), "{out}");
    assert!(
        !out.contains("not compiled into this binary"),
        "otel must be in the default build: {out}"
    );
}

#[test]
fn otel_export_sends_an_otlp_span_for_the_artifact() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://ci",
        "--action",
        "npm test",
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let id = first_json(&out)["id"].as_str().unwrap().to_string();

    let (endpoint, rx) = one_shot_collector();
    let (ok, out) = ws.run_env(
        &["otel", "export", &id],
        &[
            ("TREESHIP_OTEL_ENDPOINT", &endpoint),
            ("TREESHIP_OTEL_SERVICE", "ci-suite"),
        ],
    );
    assert!(ok, "{out}");
    assert!(out.contains("exported"), "{out}");

    let request = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("collector got a request");
    assert!(request.starts_with("POST /v1/traces "), "{request}");
    let body = &request[request.find("\r\n\r\n").unwrap() + 4..];
    let payload: Value = serde_json::from_str(body).expect("OTLP JSON body");
    let span = &payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
    assert_eq!(span["name"], "npm test");
    let attrs: Vec<(String, String)> = span["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["key"].as_str().unwrap().to_string(),
                a["value"]["stringValue"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    assert!(
        attrs.contains(&("treeship.artifact_id".into(), id.clone())),
        "{attrs:?}"
    );
    assert!(
        attrs.contains(&("treeship.actor".into(), "agent://ci".into())),
        "{attrs:?}"
    );
    let service = &payload["resourceSpans"][0]["resource"]["attributes"][0];
    assert_eq!(service["key"], "service.name");
    assert_eq!(service["value"]["stringValue"], "ci-suite");
}

#[test]
fn unreachable_collector_never_fails_session_close() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ci"]);
    assert!(ok, "{out}");
    // A port nothing listens on: the connection is refused at once, and a
    // black-holed endpoint is bounded by the exporter's five-second timeout.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", dead.local_addr().unwrap());
    drop(dead);
    let started = Instant::now();
    let (ok, out) = ws.run_env(
        &["session", "close", "--summary", "done", "--format", "json"],
        &[("TREESHIP_OTEL_ENDPOINT", &endpoint)],
    );
    assert!(ok, "close must succeed with the collector down: {out}");
    assert_eq!(first_json(&out)["status"], "ok");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "close took {:?} with the collector down",
        started.elapsed()
    );
}
