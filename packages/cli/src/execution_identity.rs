//! Execution identity: what actually ran, and under whose authority.
//!
//! A receipt says a command was run and what it produced. It does not say
//! *which* binary ran or what the process could reach. Two invocations with
//! byte-identical argv -- one as a service user in a container against a
//! read-only mount, one as your login shell in `$HOME` -- produce
//! indistinguishable receipts today. Replaying the first under the second's
//! authority is not a replay, and nothing in the artifact says so.
//!
//! `git` is `git` only until `PATH` says otherwise.
//!
//! What this records:
//!
//! | field | why it matters |
//! |---|---|
//! | `executable_path`  | which `git` -- the resolved one, not the word typed |
//! | `executable_sha256`| the bytes that ran; a swapped binary changes this |
//! | `argv`             | the real argument vector, not a re-joined string |
//! | `cwd`              | relative paths in argv mean nothing without it |
//! | `uid` / `gid`      | the authority the mutation ran under |
//! | `env_allowlist_digest` | which env names were present, never values |
//!
//! ## What this deliberately does not record
//!
//! Environment *values*, ever. The digest covers the sorted list of variable
//! **names** that were set, so a receipt can prove two runs saw the same
//! environment shape without disclosing a single secret. Same discipline as
//! `args_hash` elsewhere: prove without revealing.
//!
//! Absence is recorded as absence. A field we could not read is omitted
//! rather than defaulted -- a `uid` of `0` because the lookup failed reads
//! identically to a genuine root run, and that is the confusion this module
//! exists to prevent.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Environment variables whose *names* are recorded in the allowlist digest.
///
/// Names only, and only ones that change how a command behaves: toolchain
/// resolution, proxy routing, config location. Deliberately excludes anything
/// whose presence is itself a secret (`*_TOKEN`, `*_KEY`, `AWS_*`) -- a
/// digest that changes when a credential is present leaks that a credential
/// is present.
const ENV_SHAPE_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "SHELL",
    "LANG",
    "CI",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "RUSTUP_TOOLCHAIN",
    "CARGO_HOME",
    "NODE_ENV",
    "NVM_BIN",
    "PYTHONPATH",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "KUBECONFIG",
    "DOCKER_HOST",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "TREESHIP_CONFIG",
    "TREESHIP_HOME",
];

/// Identity of the process that produced a receipt.
///
/// Every field is optional: this is best-effort capture across platforms, and
/// a missing field must read as "not observed" rather than as a value.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionIdentity {
    /// Absolute path of the executable actually run, after `PATH` resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,

    /// `sha256:<hex>` of the executable's bytes. Absent when the file could
    /// not be read -- which is itself worth seeing, so it is not faked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,

    /// The argument vector as a list. A joined string cannot distinguish
    /// `rm "a b"` from `rm a b`, and that distinction is the whole command.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,

    /// Working directory the command ran in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,

    /// Real user id (unix only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,

    /// Real group id (unix only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,

    /// `sha256:<hex>` over the sorted NAMES of the env-shape variables that
    /// were set. Never values. Two runs with the same digest saw the same
    /// environment shape; a differing digest is a reason to look closer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_allowlist_digest: Option<String>,
}

impl ExecutionIdentity {
    /// True when nothing at all could be observed -- callers should omit the
    /// block entirely rather than attach an empty one that implies capture.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Capture identity for `argv` as it is about to be executed.
    ///
    /// `redact` is applied to every argument before it is stored. Callers
    /// MUST pass the same redactor used for any other rendering of the same
    /// command: a receipt that scrubs `command` while recording a verbatim
    /// `argv` has not protected anything, it has just moved the secret one
    /// field over. Resolution and digesting use the real values; only what
    /// is written down is redacted.
    pub fn capture(argv: &[String], redact: impl Fn(&str) -> String) -> Self {
        let program = argv.first().map(String::as_str).unwrap_or_default();
        let executable_path = resolve_executable(program);
        let executable_sha256 = executable_path.as_deref().and_then(digest_file);

        Self {
            executable_path: executable_path.map(|p| p.to_string_lossy().into_owned()),
            executable_sha256,
            argv: argv.iter().map(|a| redact(a)).collect(),
            cwd: std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().into_owned()),
            uid: current_uid(),
            gid: current_gid(),
            env_allowlist_digest: Some(env_shape_digest()),
        }
    }
}

/// Resolve a program name to the absolute path that would actually run:
/// a path containing a separator is used as given (after canonicalizing),
/// otherwise `PATH` is walked in order, exactly as the OS would.
fn resolve_executable(program: &str) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    let direct = Path::new(program);
    if program.contains(std::path::MAIN_SEPARATOR) {
        return std::fs::canonicalize(direct).ok();
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
        .and_then(|p| std::fs::canonicalize(p).ok())
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// `sha256:<hex>` of a file's contents, or `None` when it cannot be read.
/// Streamed rather than slurped: a receipt should not need to hold a
/// multi-hundred-megabyte binary in memory to name it.
fn digest_file(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Digest over the sorted names of env-shape variables that are set.
/// Names only -- see the module docs on why values never appear.
fn env_shape_digest() -> String {
    let mut present: Vec<&str> = ENV_SHAPE_KEYS
        .iter()
        .copied()
        .filter(|k| std::env::var_os(k).is_some())
        .collect();
    present.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(present.join("\n").as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    // SAFETY: getuid() is always successful and takes no arguments.
    Some(unsafe { libc::getuid() })
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

#[cfg(unix)]
fn current_gid() -> Option<u32> {
    // SAFETY: getgid() is always successful and takes no arguments.
    Some(unsafe { libc::getgid() })
}

#[cfg(not(unix))]
fn current_gid() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// argv is written into a signed, publishable artifact. `wrap` already
    /// scrubs the `command` string; recording a verbatim argv beside it would
    /// not protect anything, it would move the secret one field over.
    ///
    /// This regression exists because that is exactly what the first version
    /// of this module did.
    #[test]
    fn argv_is_redacted_by_the_caller_supplied_redactor() {
        let argv = vec![
            "deploy".to_string(),
            "--token=sk-live-SECRET".into(),
            "--env".into(),
            "prod".into(),
        ];
        let redact = |a: &str| {
            if a.to_uppercase().contains("TOKEN=") {
                "[REDACTED]".to_string()
            } else {
                a.to_string()
            }
        };
        let id = ExecutionIdentity::capture(&argv, redact);
        let serialized = serde_json::to_string(&id).unwrap();
        assert!(
            !serialized.contains("sk-live-SECRET"),
            "secret survived into the receipt: {serialized}"
        );
        assert_eq!(id.argv[1], "[REDACTED]");
        // Non-secret arguments must survive intact, or the field is useless.
        assert_eq!(id.argv[0], "deploy");
        assert_eq!(id.argv[3], "prod");
    }

    #[test]
    fn resolves_a_program_on_path_to_an_absolute_path() {
        let id = ExecutionIdentity::capture(&["sh".to_string(), "-c".into(), "true".into()], |a| {
            a.to_string()
        });
        let path = id.executable_path.expect("sh should resolve on PATH");
        assert!(
            Path::new(&path).is_absolute(),
            "expected an absolute path, got {path}"
        );
        assert!(path.ends_with("sh"), "resolved to {path}");
    }

    #[test]
    fn digests_the_binary_that_would_run() {
        let id = ExecutionIdentity::capture(&["sh".to_string()], |a| a.to_string());
        let digest = id.executable_sha256.expect("sh should be readable");
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
    }

    /// The point of the whole module: same command, different binary ->
    /// different receipt. A shell script named `git` earlier on PATH than
    /// the real one is the attack this makes visible.
    #[test]
    fn a_different_binary_changes_the_identity() {
        let dir = std::env::temp_dir().join(format!("ts-execid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("tsfake");
        std::fs::write(&fake, b"#!/bin/sh\necho impostor\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let first =
            ExecutionIdentity::capture(&[fake.to_string_lossy().into_owned()], |a| a.to_string());
        std::fs::write(&fake, b"#!/bin/sh\necho impostor v2\n").unwrap();
        let second =
            ExecutionIdentity::capture(&[fake.to_string_lossy().into_owned()], |a| a.to_string());

        assert_eq!(first.executable_path, second.executable_path);
        assert_ne!(
            first.executable_sha256, second.executable_sha256,
            "swapping the binary at the same path must change the digest"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// argv must stay a vector. A joined string cannot tell `rm "a b"`
    /// from `rm a b`, and that difference is the entire command.
    #[test]
    fn argv_preserves_argument_boundaries() {
        let id = ExecutionIdentity::capture(&["sh".to_string(), "a b".into(), "c".into()], |a| {
            a.to_string()
        });
        assert_eq!(id.argv, vec!["sh", "a b", "c"]);
    }

    #[test]
    fn env_digest_covers_names_and_never_values() {
        let before = env_shape_digest();
        // Changing a VALUE must not change the digest: the receipt records
        // environment shape, not contents.
        std::env::set_var(
            "PATH",
            std::env::var("PATH").unwrap_or_default() + ":/tmp/ts-nonexist",
        );
        assert_eq!(
            before,
            env_shape_digest(),
            "digest changed when only a value changed -- values are leaking in"
        );
    }

    #[test]
    fn unresolvable_program_yields_no_path_rather_than_a_guess() {
        let id =
            ExecutionIdentity::capture(&["ts-definitely-not-a-real-binary-xyz".to_string()], |a| {
                a.to_string()
            });
        assert!(id.executable_path.is_none());
        assert!(id.executable_sha256.is_none());
        // argv and cwd are still worth recording.
        assert_eq!(id.argv.len(), 1);
        assert!(id.cwd.is_some());
    }

    #[test]
    fn default_identity_reports_itself_empty() {
        assert!(ExecutionIdentity::default().is_empty());
        assert!(!ExecutionIdentity::capture(&["sh".to_string()], |a| a.to_string()).is_empty());
    }
}
