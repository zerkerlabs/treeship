//! Receipts carried the machine's hostname as `host_<hostname>` on every
//! event and in the hosts table, outside the path redaction (0.31.11
//! re-test, N-41). The id is a random per-install value now (a hostname
//! digest reverses from a guess list), minted once by `init` or by the first
//! session, unless TREESHIP_HOST_ID names the host.

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

fn receipt_after_a_session(home: &std::path::Path, host_id_env: Option<&str>) -> String {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let project = home.join(format!(
        "proj{}",
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    receipt_after_a_session_at(home, &project, host_id_env)
}

fn receipt_after_a_session_in(home: &std::path::Path, project: &std::path::Path) -> String {
    receipt_after_a_session_at(home, project, None)
}

fn receipt_after_a_session_at(
    home: &std::path::Path,
    project: &std::path::Path,
    host_id_env: Option<&str>,
) -> String {
    let project = project.to_path_buf();
    std::fs::create_dir_all(&project).unwrap();
    let cfg = project.join(".treeship/config.json");
    let run = |args: &[&str]| -> Output {
        let mut cmd = Command::new(cli_path());
        cmd.current_dir(&project)
            .env("HOME", home)
            .env_remove("TREESHIP_CONFIG")
            .env_remove("TREESHIP_HOST_ID");
        if let Some(h) = host_id_env {
            cmd.env("TREESHIP_HOST_ID", h);
        }
        cmd.args(args)
            .arg("--config")
            .arg(&cfg)
            .output()
            .expect("run treeship")
    };
    let out = run(&["init", "--name", "t"]);
    assert!(
        out.status.success(),
        "init in {}: {}",
        project.display(),
        text(&out)
    );
    assert!(run(&["session", "start", "--name", "s"]).status.success());
    let out = run(&["wrap", "--", "true"]);
    assert!(out.status.success(), "{}", text(&out));
    let out = run(&[
        "session",
        "close",
        "--receipt-dir",
        project.join("r").to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let pkg = std::fs::read_dir(project.join("r"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "treeship").unwrap_or(false))
        .expect("no package written");
    std::fs::read_to_string(pkg.join("receipt.json")).unwrap()
}

#[test]
fn the_host_id_is_random_per_install_not_the_hostname() {
    let hostname = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|h| !h.is_empty())
        .expect("hostname");
    let home = tempfile::tempdir().unwrap();
    let receipt = receipt_after_a_session(home.path(), None);
    let doc: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    let mut ids: Vec<String> = Vec::new();
    fn walk(v: &serde_json::Value, ids: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    if k == "host_id" {
                        if let Some(s) = x.as_str() {
                            ids.push(s.to_string());
                        }
                    }
                    walk(x, ids);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, ids)),
            _ => {}
        }
    }
    walk(&doc, &mut ids);
    assert!(!ids.is_empty(), "no host_id in the receipt:\n{receipt}");
    for id in &ids {
        assert!(
            id.len() == 21
                && id.starts_with("host_")
                && id[5..].chars().all(|c| c.is_ascii_hexdigit()),
            "host_id is not host_ plus 16 hex: {id}"
        );
    }
    let short = hostname.split('.').next().unwrap_or(&hostname);
    assert!(
        !receipt.to_lowercase().contains(&short.to_lowercase()),
        "the receipt carries the machine name {short}:\n{receipt}"
    );

    // Stable within an install: the id is kept at ~/.treeship/host_id, and
    // a second session says the same one.
    let kept = std::fs::read_to_string(home.path().join(".treeship/host_id")).unwrap();
    assert_eq!(kept.trim(), ids[0], "the receipt's id is not the kept one");
    let again = receipt_after_a_session(home.path(), None);
    assert!(
        again.contains(&format!("\"host_id\": \"{}\"", ids[0])),
        "{again}"
    );
    // Unrelated to the machine: another install gets another id.
    let other = tempfile::tempdir().unwrap();
    let elsewhere = receipt_after_a_session(other.path(), None);
    assert!(!elsewhere.contains(&ids[0]), "two installs share a host id");

    // TREESHIP_HOST_ID still names the host outright.
    let receipt = receipt_after_a_session(home.path(), Some("host_build-runner-7"));
    assert!(
        receipt.contains("\"host_id\": \"host_build-runner-7\""),
        "{receipt}"
    );
}

fn host_ids_in_events(project: &std::path::Path) -> Vec<String> {
    let sessions = project.join(".treeship/sessions");
    let mut ids = Vec::new();
    for dir in std::fs::read_dir(sessions).unwrap().flatten() {
        let log = std::fs::read_to_string(dir.path().join("events.jsonl")).unwrap_or_default();
        for line in log.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(h) = v["host_id"].as_str() {
                    ids.push(h.to_string());
                }
            }
        }
    }
    ids
}

/// `init` mints the id, and six sessions starting at once on an install
/// without one agree on a single id (the exclusive create decides).
#[test]
fn init_mints_the_id_and_concurrent_first_use_agrees_on_one() {
    let home = tempfile::tempdir().unwrap();
    let mk = |name: &str| {
        let project = home.path().join(name);
        std::fs::create_dir_all(&project).unwrap();
        let cfg = project.join(".treeship/config.json");
        let out = Command::new(cli_path())
            .current_dir(&project)
            .env("HOME", home.path())
            .env_remove("TREESHIP_CONFIG")
            .env_remove("TREESHIP_HOST_ID")
            .args(["init", "--name", name, "--config"])
            .arg(&cfg)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", text(&out));
        (project, cfg)
    };
    let projects: Vec<_> = (0..6).map(|i| mk(&format!("p{i}"))).collect();
    let file = home.path().join(".treeship/host_id");
    let minted = std::fs::read_to_string(&file).expect("init did not mint ~/.treeship/host_id");
    assert!(
        minted.trim().starts_with("host_") && minted.trim().len() == 21,
        "{minted}"
    );

    // A legacy install: no file. Six sessions start at once.
    std::fs::remove_file(&file).unwrap();
    let children: Vec<_> = projects
        .iter()
        .map(|(project, cfg)| {
            Command::new(cli_path())
                .current_dir(project)
                .env("HOME", home.path())
                .env_remove("TREESHIP_CONFIG")
                .env_remove("TREESHIP_HOST_ID")
                .args(["session", "start", "--name", "race", "--config"])
                .arg(cfg)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for mut c in children {
        assert!(c.wait().unwrap().success());
    }
    let kept = std::fs::read_to_string(&file).unwrap().trim().to_string();
    let mut seen: Vec<String> = projects
        .iter()
        .flat_map(|(p, _)| host_ids_in_events(p))
        .collect();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen,
        vec![kept.clone()],
        "concurrent first use produced several host ids"
    );
}

/// A planted link at ~/.treeship/host_id is never followed: not to a file
/// holding a plausible id, and not to a device that never ends.
#[cfg(unix)]
#[test]
fn a_linked_host_id_file_is_refused() {
    for (target, label) in [("/dev/zero".to_string(), "device"), (String::new(), "file")] {
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join("proj");
        std::fs::create_dir_all(home.path().join(".treeship")).unwrap();
        let target = if target.is_empty() {
            let f = home.path().join("planted");
            std::fs::write(&f, "host_aaaaaaaaaaaaaaaa\n").unwrap();
            f.to_string_lossy().to_string()
        } else {
            target
        };
        std::os::unix::fs::symlink(&target, home.path().join(".treeship/host_id")).unwrap();
        let receipt = receipt_after_a_session_in(home.path(), &project);
        assert!(
            !receipt.contains("host_aaaaaaaaaaaaaaaa"),
            "{label}: the planted id was adopted"
        );
        assert!(
            receipt.contains("\"host_id\": \"host_unknown\""),
            "{label}: {receipt}"
        );
    }
}
