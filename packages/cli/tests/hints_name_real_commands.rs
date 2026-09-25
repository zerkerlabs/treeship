//! Every `treeship …` a hint or template prints must name a command that
//! exists. In 0.31.9 hints named `treeship open`, `treeship share last` and
//! `treeship zk-tls notary setup`, none of which is a command (0.31.9 full
//! test, CLI-15). The command tree comes from the binary's own
//! `__dump-cli`, so a renamed command fails this test until its hints
//! follow.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

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

/// top-level command -> its subcommand names (empty when it has none),
/// read from the binary's own help (`--help-all` lists hidden commands).
fn command_tree() -> BTreeMap<String, BTreeSet<String>> {
    let out = Command::new(cli_path()).arg("--help-all").output().unwrap();
    let top = subcommands_in(&String::from_utf8_lossy(&out.stdout));
    let mut map = BTreeMap::new();
    for name in top {
        let out = Command::new(cli_path())
            .args([name.as_str(), "--help"])
            .output()
            .unwrap();
        let subs = subcommands_in(&String::from_utf8_lossy(&out.stdout))
            .into_iter()
            .collect();
        map.insert(name, subs);
    }
    map
}

fn source_files() -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, out);
            } else if matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("rs") | Some("yaml")
            ) {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut out,
    );
    out
}

fn is_word(t: &str) -> bool {
    !t.is_empty()
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[test]
fn every_treeship_invocation_in_hints_and_templates_names_a_real_command() {
    let tree = command_tree();
    assert!(tree.len() > 40, "dump-cli returned {} commands", tree.len());
    let mut wrong = Vec::new();
    for file in source_files() {
        let text = std::fs::read_to_string(&file).unwrap();
        for (lineno, line) in text.lines().enumerate() {
            // Rust: only what a hint prints (`printer.hint(...)`); prose in
            // messages and comments says "treeship" in sentences. Templates:
            // every line, since their onboarding text is shown verbatim.
            let is_rust = file.extension().and_then(|e| e.to_str()) == Some("rs");
            if is_rust && !line.contains("hint(") {
                continue;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('#') {
                continue;
            }
            let mut rest = line;
            while let Some(i) = rest.find("treeship ") {
                let after = &rest[i + "treeship ".len()..];
                let tokens: Vec<&str> = after
                    .split(|c: char| {
                        c.is_whitespace()
                            || c == '"'
                            || c == '`'
                            || c == '\''
                            || c == ')'
                            || c == ','
                            || c == '\\'
                    })
                    .collect();
                rest = after;
                let Some(first) = tokens.first().copied() else {
                    continue;
                };
                if !is_word(first) || first.starts_with("--") {
                    continue; // a placeholder like <cmd>, a flag, or prose
                }
                let Some(subs) = tree.get(first) else {
                    if first != "help" {
                        wrong.push(format!(
                            "{}:{}: `treeship {first}` is not a command",
                            file.display(),
                            lineno + 1
                        ));
                    }
                    continue;
                };
                if subs.is_empty() {
                    continue;
                }
                let second = tokens.get(1).copied().unwrap_or("");
                if is_word(second) && !second.starts_with("--") && !subs.contains(second) {
                    wrong.push(format!(
                        "{}:{}: `treeship {first} {second}` is not a command ({first} has: {})",
                        file.display(),
                        lineno + 1,
                        subs.iter().cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "hints or templates name commands that do not exist:\n{}",
        wrong.join("\n")
    );
}
