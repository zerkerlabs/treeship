//! Writes under a workspace that never follow a symlink. The primitives live
//! in `treeship_core::fs_safe` (one implementation for the CLI and core);
//! this module adds the `.treeship` anchor the CLI works from: a repository
//! controls what is inside its `.treeship/` directory, so every component
//! from there down is judged, while the user's own path above it is not.

use std::io;
use std::path::Path;

pub use treeship_core::fs_safe::{
    open_append_nofollow, open_rw_nofollow, refuse_symlink, write_atomic,
};

/// Refuse when the `.treeship` directory, or anything beneath it on the
/// way to `path`, is a symlink.
pub fn refuse_symlinks_under_treeship(path: &Path) -> io::Result<()> {
    treeship_core::fs_safe::refuse_symlinks_from(path, ".treeship")
}

/// Create or replace `path` with `bytes` at `mode`, never through a link at
/// the file or under `.treeship` on the way to it.
pub fn write_nofollow(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    refuse_symlinks_under_treeship(path)?;
    treeship_core::fs_safe::write_nofollow(path, bytes, mode)
}

/// `create_dir_all`, refusing when any component from `.treeship` down is a
/// symlink (an existing `.treeship -> elsewhere` counts).
pub fn create_dir_all_nofollow(dir: &Path) -> io::Result<()> {
    refuse_symlinks_under_treeship(dir)?;
    std::fs::create_dir_all(dir)
}

/// A file written into the working directory (a proof, a package, a
/// credential): created or replaced in place, refusing a link at the path.
pub fn write_in_cwd(path: &Path, bytes: &[u8]) -> io::Result<()> {
    refuse_symlink(path)?;
    treeship_core::fs_safe::write_nofollow(path, bytes, 0o644)
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

    #[test]
    fn a_cwd_file_is_never_a_link_target() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let link = root.path().join("out.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(write_in_cwd(&link, b"x").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        write_in_cwd(&root.path().join("fresh.json"), b"x").unwrap();
    }
}
