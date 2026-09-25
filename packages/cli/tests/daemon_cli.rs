//! The daemon round trip: start (backgrounds), status (twice, and never
//! kills it), stop. Through 0.31.9 the pid file "<pid> <epoch>" was parsed
//! as one number, so `status` said "stopped", deleted the file, and the
//! daemon exited; and `start` never backgrounded (0.31.9 full test, CLI-8).

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
        let out = ship.run(&["init", "--name", "daemon"]);
        assert!(
            out.status.success(),
            "init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ship
    }

    fn run(&self, args: &[&str]) -> Output {
        let config = self.work.path().join(".treeship/config.json");
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .arg("--config")
            .arg(config)
            .output()
            .expect("run treeship")
    }

    fn status(&self) -> serde_json::Value {
        let out = self.run(&["daemon", "status", "--format", "json"]);
        assert!(
            out.status.success(),
            "status: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "status is not JSON: {e}\n{}",
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }
}

#[cfg(unix)]
fn alive(pid: u64) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(unix)]
#[test]
fn start_status_status_stop_round_trip() {
    let ship = Ship::init();
    let pid_file = ship.work.path().join(".treeship/daemon.pid");

    // start returns promptly: the daemon is a detached child, not this call.
    let t0 = std::time::Instant::now();
    let out = ship.run(&["daemon", "start"]);
    assert!(
        out.status.success(),
        "start: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(10),
        "start did not return: it ran the daemon in the foreground"
    );
    assert!(pid_file.exists(), "no pid file after start");
    let raw = std::fs::read_to_string(&pid_file).unwrap();
    assert_eq!(
        raw.split_whitespace().count(),
        2,
        "pid file is `<pid> <epoch>`: {raw:?}"
    );

    // status, twice: running both times, pid file untouched, process alive.
    let s1 = ship.status();
    assert_eq!(s1["running"], true, "{s1}");
    let pid = s1["pid"].as_u64().expect("pid");
    assert!(alive(pid), "daemon {pid} is not alive after status");
    let s2 = ship.status();
    assert_eq!(s2["running"], true, "second status killed it: {s2}");
    assert!(pid_file.exists(), "status deleted a live pid file");
    assert!(alive(pid), "daemon {pid} died of a status check");

    // stop: pid file gone, process gone.
    let out = ship.run(&["daemon", "stop"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while alive(pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(!alive(pid), "daemon {pid} still alive after stop");
    assert!(!pid_file.exists(), "pid file survives stop");
    let s3 = ship.status();
    assert_eq!(s3["running"], false, "{s3}");
}

#[test]
fn a_stale_pid_file_is_reported_and_removed_but_an_unreadable_one_is_kept() {
    let ship = Ship::init();
    let pid_file = ship.work.path().join(".treeship/daemon.pid");

    // A pid that cannot be alive.
    std::fs::write(&pid_file, "4194304 1700000000").unwrap();
    let s = ship.status();
    assert_eq!(s["running"], false, "{s}");
    assert!(!pid_file.exists(), "stale pid file kept");

    // A file this build cannot read: never deleted, reported.
    std::fs::write(&pid_file, "not a pid").unwrap();
    let s = ship.status();
    assert_eq!(s["running"], false, "{s}");
    assert_eq!(s["status"], "unknown", "{s}");
    assert!(
        pid_file.exists(),
        "status deleted a pid file it could not read"
    );
}

/// Two starts at once: exactly one daemon, and it can be stopped. Before
/// the lock-then-write fix, the loser truncated the winner's pid file, so
/// `status` said stopped and `stop` could not reach a live daemon.
#[cfg(unix)]
#[test]
fn two_concurrent_starts_leave_one_stoppable_daemon() {
    let ship = Ship::init();
    let pid_file = ship.work.path().join(".treeship/daemon.pid");

    let outs: Vec<Output> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| ship.run(&["daemon", "start"])))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let ok = outs.iter().filter(|o| o.status.success()).count();
    assert_eq!(
        ok,
        1,
        "exactly one start must win; got {ok}:\n{}",
        outs.iter()
            .map(|o| format!(
                "exit {:?}: {}{}",
                o.status.code(),
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ))
            .collect::<Vec<_>>()
            .join("\n---\n")
    );

    let s = ship.status();
    assert_eq!(s["running"], true, "{s}");
    let pid = s["pid"]
        .as_u64()
        .expect("the winner's pid, not a wiped file");
    assert!(alive(pid), "daemon {pid} is not alive");
    let raw = std::fs::read_to_string(&pid_file).unwrap();
    assert_eq!(
        raw.split_whitespace()
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap(),
        pid,
        "pid file was wiped or rewritten by the loser: {raw:?}"
    );

    let out = ship.run(&["daemon", "stop"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while alive(pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(!alive(pid), "daemon {pid} still alive after stop");
    assert_eq!(ship.status()["running"], false);
}
