//! The CLI contract (T3 in the 0.31.9 full test).
//!
//! Two promises a script or an agent relies on without reading prose:
//!
//! 1. Every command answers `--help` with exit 0. The command tree is walked
//!    from the binary's own help output, so a new subcommand is covered the
//!    day it is added.
//! 2. Every failure exits nonzero, with the code the docs promise
//!    (cli/overview, "Exit codes"). The table below is the contract; each
//!    row was a real exit-0 failure in 0.31.9 or a code that must not drift.
//!
//! State is isolated: a scratch HOME and an explicit `--config` under a
//! scratch workspace. Nothing reaches the network except one connection to a
//! closed local port.

use std::path::PathBuf;
use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Ship {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
    config: PathBuf,
}

impl Ship {
    fn init() -> Self {
        let home = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let config = work.path().join(".treeship/config.json");
        let ship = Self { home, work, config };
        let out = ship.run(&["init", "--name", "contract"]);
        assert!(
            out.status.success(),
            "init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ship
    }

    /// Run with `--config` pointing at this ship. Global flags such as
    /// `--config` are accepted after the subcommand too, and that is where
    /// the table puts them.
    fn run(&self, args: &[&str]) -> Output {
        self.run_env(args, &[])
    }

    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(cli_path());
        cmd.current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .env_remove("TREESHIP_OTEL_ENDPOINT")
            .args(args)
            .arg("--config")
            .arg(&self.config);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().expect("run treeship")
    }

    /// Run without `--config`: for cases whose point is the config itself.
    fn run_bare(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .output()
            .expect("run treeship")
    }
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

// ---------------------------------------------------------------------------
// 1. Every command answers --help
// ---------------------------------------------------------------------------

/// Subcommand names listed under "Commands:" in a help screen.
fn subcommands_in(help: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_commands = false;
    for line in help.lines() {
        if line == "Commands:" {
            in_commands = true;
            continue;
        }
        if !in_commands {
            continue;
        }
        if line.trim().is_empty() {
            break;
        }
        // "  name    description". Continuation lines of a long description
        // are indented deeper and start with a lowercase word; a command
        // name sits at exactly two spaces.
        if !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        if let Some(name) = line.split_whitespace().next() {
            if name != "help" {
                names.push(name.to_string());
            }
        }
    }
    names
}

fn help_of(ship: &Ship, path: &[String], all: bool) -> Output {
    let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
    if all {
        args.push("--help-all");
    } else {
        args.push("--help");
    }
    ship.run_bare(&args)
}

fn walk(ship: &Ship, path: Vec<String>, seen: &mut Vec<Vec<String>>) {
    // The top level lists its hidden commands only under --help-all.
    let out = help_of(ship, &path, path.is_empty());
    assert_eq!(
        code(&out),
        0,
        "`treeship {} --help` exited {}:\n{}",
        path.join(" "),
        code(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    seen.push(path.clone());
    for sub in subcommands_in(&help) {
        let mut next = path.clone();
        next.push(sub);
        walk(ship, next, seen);
    }
}

#[test]
fn every_command_answers_help() {
    let ship = Ship::init();
    let mut seen = Vec::new();
    walk(&ship, Vec::new(), &mut seen);
    let leaves: Vec<String> = seen.iter().map(|p| p.join(" ")).collect();
    // A floor, not a count: the walk must have found the tree, not just the
    // root. 0.31.9 has 71 public paths and more hidden ones.
    assert!(
        seen.len() > 80,
        "help walk found only {} command paths: {leaves:?}",
        seen.len()
    );
    for must in [
        "verify",
        "session close",
        "attest action",
        "approval status",
        "otel export",
        "verify-proof",
        "judge",
        "halt",
    ] {
        assert!(
            leaves.iter().any(|l| l == must),
            "help walk did not reach `{must}`; found {leaves:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Every failure exits nonzero, with the documented code
// ---------------------------------------------------------------------------

/// Exit codes the docs promise (cli/overview, "Exit codes").
const EXIT_ERROR: i32 = 1;
const EXIT_USAGE_CLAP: i32 = 2;
const EXIT_NOT_INITIALIZED: i32 = 3;
const EXIT_USAGE_COMMAND: i32 = 4;
// Only the feature-gated rows use it; a build with every feature on has none.
#[allow(dead_code)]
const EXIT_NOT_IN_BUILD: i32 = 5;
const EXIT_NOT_PINNED: i32 = 6;

struct Case {
    name: &'static str,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
    expect: i32,
}

/// A closed port: nothing listens on TCP 1 (tcpmux) on a developer machine
/// or a CI runner, so a connection is refused at once.
// Only the otel cases use it; a --no-default-features build has none.
#[cfg(feature = "otel")]
const DEAD_COLLECTOR: &str = "http://127.0.0.1:1";

const CASES: &[Case] = &[
    // --- 0.31.9 exit-0 failures (CLI-6) ------------------------------------
    Case {
        name: "approval status on a grant nobody has heard of",
        args: &["approval", "status", "grn_0000000000000000"],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        name: "approval uses on a grant nobody has heard of",
        args: &["approval", "uses", "art_0000000000000000"],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        name: "resolve an agent with no card",
        args: &["resolve", "agent://ghost"],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        name: "resolve an agent with no card, JSON mode",
        args: &["resolve", "agent://ghost", "--format", "json"],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        // The agent's name contains "required", and "treeship init" could
        // appear in any hint. The code must come from the error's type, not
        // from words in its message (exit 4 through the first review of
        // this change).
        name: "resolve an agent whose name contains a code-picking word",
        args: &["resolve", "agent://required-bot"],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        name: "wrap with no command",
        args: &["wrap"],
        env: &[],
        expect: EXIT_USAGE_CLAP,
    },
    Case {
        name: "grant issue with no scope",
        args: &[
            "grant",
            "issue",
            "--audience",
            "agent://x",
            "--expiry",
            "30d",
        ],
        env: &[],
        expect: EXIT_USAGE_CLAP,
    },
    Case {
        // A usage error the command itself raises, past the parser.
        name: "judge --resolve without --by",
        args: &["judge", "--resolve", "art_0000000000000000"],
        env: &[],
        expect: EXIT_USAGE_COMMAND,
    },
    // (The dead-collector otel case needs a real artifact id; it is built in
    // the test body.)
    #[cfg(feature = "otel")]
    Case {
        name: "otel export of an artifact that does not exist",
        args: &["otel", "export", "art_0000000000000000"],
        env: &[("TREESHIP_OTEL_ENDPOINT", DEAD_COLLECTOR)],
        expect: EXIT_ERROR,
    },
    #[cfg(feature = "otel")]
    Case {
        name: "otel export with no endpoint configured",
        args: &["otel", "export", "last"],
        env: &[],
        expect: EXIT_ERROR,
    },
    #[cfg(not(feature = "otel"))]
    Case {
        name: "otel on a build without the feature",
        args: &["otel", "status"],
        env: &[],
        expect: EXIT_NOT_IN_BUILD,
    },
    #[cfg(not(feature = "zk"))]
    Case {
        name: "verify-proof on a build without zk",
        args: &["verify-proof", "/nope.zkproof"],
        env: &[],
        expect: EXIT_NOT_IN_BUILD,
    },
    #[cfg(not(feature = "zk"))]
    Case {
        name: "prove on a build without zk",
        args: &[
            "prove",
            "--circuit",
            "policy-checker",
            "--artifact",
            "art_0000000000000000",
        ],
        env: &[],
        expect: EXIT_NOT_IN_BUILD,
    },
    #[cfg(not(feature = "zk"))]
    Case {
        name: "prove-chain on a build without zk",
        args: &["prove-chain", "ssn_0000000000000000"],
        env: &[],
        expect: EXIT_NOT_IN_BUILD,
    },
    #[cfg(feature = "zk")]
    Case {
        name: "verify-proof on a file that does not exist",
        args: &["verify-proof", "/nope.zkproof"],
        env: &[],
        expect: EXIT_ERROR,
    },
    // --- codes that must not drift -----------------------------------------
    Case {
        name: "verify an artifact that does not exist",
        args: &["verify", "art_0000000000000000"],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        name: "verify a garbage target",
        args: &["verify", "not-an-id-or-path"],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        name: "verify with no target",
        args: &["verify"],
        env: &[],
        expect: EXIT_USAGE_CLAP,
    },
    Case {
        name: "attest action with no arguments",
        args: &["attest", "action"],
        env: &[],
        expect: EXIT_USAGE_CLAP,
    },
    Case {
        name: "an unknown command",
        args: &["frobnicate"],
        env: &[],
        expect: EXIT_USAGE_CLAP,
    },
    Case {
        name: "grant issue with an expiry in the past",
        args: &[
            "grant",
            "issue",
            "--scope",
            "x",
            "--audience",
            "agent://x",
            "--expiry",
            "2020-01-01T00:00:00Z",
            "--grantee-self",
        ],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        name: "session close with no session open",
        args: &["session", "close"],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        name: "session status --check with no session open",
        args: &["session", "status", "--check"],
        env: &[],
        expect: EXIT_ERROR,
    },
    Case {
        name: "bundle import of a file that is not a bundle",
        args: &["bundle", "import", "/etc/hosts"],
        env: &[],
        expect: EXIT_ERROR,
    },
];

#[test]
fn every_failure_exits_with_its_documented_code() {
    let ship = Ship::init();
    // One real artifact so `last` resolves and the otel case fails on the
    // collector, not on the id.
    let out = ship.run(&[
        "attest",
        "action",
        "--actor",
        "agent://c",
        "--action",
        "probe",
    ]);
    assert!(
        out.status.success(),
        "attest: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut wrong = Vec::new();
    let mut check = |name: &str, args: &[&str], env: &[(&str, &str)], expect: i32| {
        let out = ship.run_env(args, env);
        let got = code(&out);
        if got != expect {
            wrong.push(format!(
                "{name}: `treeship {}` exited {got}, expected {expect}\n  stdout: {}\n  stderr: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim(),
            ));
        }
    };
    for case in CASES {
        check(case.name, case.args, case.env, case.expect);
    }
    // otel export reaches the collector only with a real artifact id, so the
    // dead-collector case (0.31.9 printed "export failed" and exited 0) is
    // built here from the artifact attested above.
    #[cfg(feature = "otel")]
    {
        let out = ship.run(&[
            "attest",
            "action",
            "--actor",
            "agent://c",
            "--action",
            "otel",
            "--format",
            "json",
        ]);
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let id = v["id"]
            .as_str()
            .unwrap_or_else(|| panic!("no artifact id in attest JSON: {v}"))
            .to_string();
        check(
            "otel export to a collector that refuses the connection",
            &["otel", "export", &id],
            &[("TREESHIP_OTEL_ENDPOINT", DEAD_COLLECTOR)],
            EXIT_ERROR,
        );
    }
    assert!(
        wrong.is_empty(),
        "exit-code contract broken:\n{}",
        wrong.join("\n")
    );
}

/// `merkle verify` on a ship's own fresh proof: the signature and the
/// inclusion proof hold, the checkpoint signer is not pinned (6); pinned, it
/// verifies (0); a broken proof is still 1, pinned or not (CLI-5).
#[test]
fn merkle_verify_not_pinned_exits_6() {
    let ship = Ship::init();
    let out = ship.run(&[
        "attest",
        "action",
        "--actor",
        "agent://c",
        "--action",
        "x",
        "--format",
        "json",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(ship.run(&["checkpoint"]).status.success());
    assert!(ship.run(&["merkle", "proof", &id]).status.success());
    let proof = format!("{id}.proof.json");

    let out = ship.run(&["merkle", "verify", &proof, "--format", "json"]);
    assert_eq!(
        code(&out),
        EXIT_NOT_PINNED,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["outcome"], "not_pinned", "{v}");
    let (key_id, public_key) = (
        v["key_id"].as_str().unwrap().to_string(),
        v["public_key"].as_str().unwrap().to_string(),
    );

    // A proof whose path was tampered with is invalid, not "not pinned".
    let mut bad: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ship.work.path().join(&proof)).unwrap()).unwrap();
    bad["inclusion_proof"]["leaf_hash"] = serde_json::Value::String("00".repeat(32));
    std::fs::write(ship.work.path().join("bad.proof.json"), bad.to_string()).unwrap();
    assert_eq!(
        code(&ship.run(&["merkle", "verify", "bad.proof.json"])),
        EXIT_ERROR
    );

    let pubkey = format!("ed25519:{public_key}");
    let out = ship.run(&[
        "trust",
        "add",
        &key_id,
        &pubkey,
        "--kind",
        "hub_checkpoint",
        "--yes",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = ship.run(&["merkle", "verify", &proof]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        code(&ship.run(&["merkle", "verify", "bad.proof.json"])),
        EXIT_ERROR
    );
}

#[test]
fn not_initialized_exits_3() {
    let ship = Ship::init();
    let other = ship.work.path().join("elsewhere/config.json");
    let out = ship.run_bare(&["status", "--config", other.to_str().unwrap()]);
    assert_eq!(
        code(&out),
        EXIT_NOT_INITIALIZED,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = ship.run_bare(&["status", "--config", "/nonexistent/treeship/config.json"]);
    assert_eq!(
        code(&out),
        EXIT_NOT_INITIALIZED,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The controls: the same commands on inputs that exist exit 0. A contract
/// that only lists failures would also be satisfied by a binary that fails
/// everything.
#[test]
fn the_same_commands_succeed_on_real_input() {
    let ship = Ship::init();
    let out = ship.run(&[
        "grant",
        "issue",
        "--scope",
        "payments.refund",
        "--audience",
        "agent://x",
        "--expiry",
        "30d",
        "--grantee-self",
        "--format",
        "json",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let grant = v["grant_id"].as_str().unwrap().to_string();

    for args in [
        vec!["approval", "status", grant.as_str()],
        vec!["approval", "uses", grant.as_str()],
        vec!["approval", "status", grant.as_str(), "--format", "json"],
    ] {
        let out = ship.run(&args);
        assert_eq!(
            code(&out),
            0,
            "`treeship {}`: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let out = ship.run(&[
        "attest",
        "action",
        "--actor",
        "agent://c",
        "--action",
        "probe",
    ]);
    assert!(out.status.success());
    let out = ship.run(&["verify", "last"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
}
