//! Writes under a workspace that never follow a symlink.
//!
//! A repository controls what is inside its `.treeship/` directory, and it
//! can make any of it a symlink into the user's home. Every write to that
//! directory therefore goes through here: the path is checked component by
//! component from `.treeship` down, and the file is opened with
//! O_NOFOLLOW so a link that appears between the check and the open still
//! cannot be followed.

use std::io;
use std::path::{Component, Path, PathBuf};

/// Refuse when the `.treeship` directory, or anything beneath it on the
/// way to `path`, is a symlink. Components above `.treeship` are the user's
/// own environment (a symlinked home is theirs) and are not checked.
pub fn refuse_symlinks_under_treeship(path: &Path) -> io::Result<()> {
    let mut prefix = PathBuf::new();
    let mut checking = false;
    for component in path.components() {
        prefix.push(component);
        if !checking {
            if let Component::Normal(name) = component {
                if name == ".treeship" {
                    checking = true;
                } else {
                    continue;
                }
            } else {
                continue;
            }
        }
        match std::fs::symlink_metadata(&prefix) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to write through a symlink at {} (a repository's .treeship must not point outside itself)",
                        prefix.display()
                    ),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Create or replace `path` with `bytes`, mode `mode`, never following a
/// symlink at the final component. Existing regular files are truncated.
pub fn write_nofollow(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    refuse_symlinks_under_treeship(path)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = opts.open(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "refusing to write {} ({e}); is it a symlink?",
                path.display()
            ),
        )
    })?;
    use std::io::Write as _;
    file.write_all(bytes)?;
    file.flush()
}

/// `create_dir_all`, refusing when any component from `.treeship` down is a
/// symlink (an existing `.treeship -> elsewhere` counts).
pub fn create_dir_all_nofollow(dir: &Path) -> io::Result<()> {
    refuse_symlinks_under_treeship(dir)?;
    std::fs::create_dir_all(dir)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_linked_treeship_dir_is_refused_and_its_target_untouched() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("docker");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("config.json"), b"{\"auths\":{}}").unwrap();
        let ws = root.path().join("repo");
        std::fs::create_dir_all(&ws).unwrap();
        std::os::unix::fs::symlink(&elsewhere, ws.join(".treeship")).unwrap();
        let target = ws.join(".treeship").join("config.json");
        assert!(refuse_symlinks_under_treeship(&target).is_err());
        assert!(write_nofollow(&target, b"{}", 0o600).is_err());
        assert!(create_dir_all_nofollow(&ws.join(".treeship").join("keys")).is_err());
        assert_eq!(
            std::fs::read(elsewhere.join("config.json")).unwrap(),
            b"{\"auths\":{}}"
        );
        assert!(!elsewhere.join("keys").exists());
    }

    #[test]
    fn a_linked_file_inside_treeship_is_refused_even_without_the_check() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("authorized_keys");
        std::fs::write(&victim, b"ssh-ed25519 AAAA").unwrap();
        let ts = root.path().join("repo").join(".treeship");
        std::fs::create_dir_all(&ts).unwrap();
        std::os::unix::fs::symlink(&victim, ts.join("config.yaml")).unwrap();
        assert!(write_nofollow(&ts.join("config.yaml"), b"treeship: 1", 0o600).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"ssh-ed25519 AAAA");
        // A regular file is replaced in place with the requested mode.
        let ok = ts.join("plain.yaml");
        write_nofollow(&ok, b"a", 0o600).unwrap();
        write_nofollow(&ok, b"b", 0o600).unwrap();
        assert_eq!(std::fs::read(&ok).unwrap(), b"b");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&ok).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn components_above_treeship_are_not_checked() {
        let root = tempfile::tempdir().unwrap();
        let real_home = root.path().join("real-home");
        std::fs::create_dir_all(real_home.join(".treeship")).unwrap();
        let linked_home = root.path().join("home");
        std::os::unix::fs::symlink(&real_home, &linked_home).unwrap();
        let target = linked_home.join(".treeship").join("config.json");
        assert!(refuse_symlinks_under_treeship(&target).is_ok());
        write_nofollow(&target, b"{}", 0o600).unwrap();
    }
}
