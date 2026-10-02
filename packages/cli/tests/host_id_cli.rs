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
    let project = home.path().join("stable");
    let receipt = receipt_after_a_session_in(home.path(), &project);
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

    // The id is kept beside the config this session used, not in ~/.treeship
    // just because HOME is set. A second session on that config says the same one.
    let kept = std::fs::read_to_string(project.join(".treeship/host_id")).unwrap();
    assert_eq!(kept.trim(), ids[0], "the receipt's id is not the kept one");
    assert!(
        !home.path().join(".treeship/host_id").exists(),
        "an explicit project config still wrote ~/.treeship/host_id"
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

/// `init` mints the id beside the config, and six inits of one config
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
    let (project, cfg) = mk("shared");
    let file = project.join(".treeship/host_id");
    let minted =
        std::fs::read_to_string(&file).expect("init did not mint host_id beside the config");
    assert!(
        minted.trim().starts_with("host_") && minted.trim().len() == 21,
        "{minted}"
    );
    assert!(
        !home.path().join(".treeship/host_id").exists(),
        "init --config still wrote ~/.treeship/host_id"
    );

    // No workspace yet. Six inits of this one config race the exclusive
    // create. One wins; the file beside the config holds a single id.
    std::fs::remove_dir_all(project.join(".treeship")).unwrap();
    let children: Vec<_> = (0..6)
        .map(|_| {
            Command::new(cli_path())
                .current_dir(&project)
                .env("HOME", home.path())
                .env_remove("TREESHIP_CONFIG")
                .env_remove("TREESHIP_HOST_ID")
                .args(["init", "--name", "race", "--config"])
                .arg(&cfg)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    let mut wins = 0;
    for mut c in children {
        if c.wait().unwrap().success() {
            wins += 1;
        }
    }
    assert!(wins >= 1, "every racing init failed");
    let kept = std::fs::read_to_string(&file).unwrap();
    let kept = kept.trim();
    assert!(
        kept.starts_with("host_") && kept.len() == 21,
        "racing inits did not leave one host id: {kept}"
    );
}

/// A planted link at the config's host_id is never followed: not to a file
/// holding a plausible id, and not to a device that never ends.
#[cfg(unix)]
#[test]
fn a_linked_host_id_file_is_refused() {
    for (target, label) in [("/dev/zero".to_string(), "device"), (String::new(), "file")] {
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join("proj");
        std::fs::create_dir_all(project.join(".treeship")).unwrap();
        let target = if target.is_empty() {
            let f = home.path().join("planted");
            std::fs::write(&f, "host_aaaaaaaaaaaaaaaa\n").unwrap();
            f.to_string_lossy().to_string()
        } else {
            target
        };
        std::os::unix::fs::symlink(&target, project.join(".treeship/host_id")).unwrap();
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
