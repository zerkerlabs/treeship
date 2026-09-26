//! Writes under a workspace that never follow a symlink and never land in
//! a hard link. The primitives live in `treeship_core::fs_safe` (one
//! implementation for the CLI and core); this module adds the `.treeship`
//! anchor the CLI works from: a repository controls what is inside its
//! `.treeship/` directory, so every component from there down is judged,
//! while the user's own path above it is not.
//!
//! Three kinds of destination:
//! * under `.treeship` (config, keys, sessions, queues, `.last`):
//!   [`write_under_treeship`], [`create_dir_all_nofollow`],
//!   [`open_lock_under_treeship`], [`open_event_log`];
//! * a path the user chose (`--out`, a package directory, a proof in the
//!   working directory): [`write_user_path`], which refuses only an
//!   existing link at the file itself;
//! * a file in the user's own home (a shell rc file, trust roots, saved
//!   templates): [`write_home_path`], which follows the user's own links
//!   (dotfiles are routinely symlinked) and writes the target atomically;
//!   the same path outside the home is treated as a user-chosen path;
//! * a mode change: [`set_mode_nofollow`], through a handle, never chmod on
//!   a path that might be a link.

use std::io;
use std::path::Path;

use treeship_core::session::event_log::{EventLog, EventLogError};

pub use treeship_core::fs_safe::{
    copy_nofollow, open_append_nofollow, open_rw_nofollow, refuse_symlink, set_mode_nofollow,
    write_atomic,
};

/// Refuse when the `.treeship` directory, or anything beneath it on the
/// way to `path`, is a symlink. Every component from the anchor down is
/// judged, so `.treeship/sessions -> elsewhere` or `.treeship/sub -> ~`
/// with `keys_dir = sub/keys` is caught, not only a link at the file.
pub fn refuse_symlinks_under_treeship(path: &Path) -> io::Result<()> {
    treeship_core::fs_safe::refuse_symlinks_from(path, ".treeship")
}

/// Create or replace `path` with `bytes` at `mode`: never through a link at
/// the file or under `.treeship` on the way to it, and never into a hard
/// link (the file is written fresh and renamed into place).
pub fn write_under_treeship(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    refuse_symlinks_under_treeship(path)?;
    write_atomic(path, bytes, mode)
}

/// `create_dir_all`, refusing when any component from `.treeship` down is a
/// symlink (an existing `.treeship -> elsewhere` counts).
pub fn create_dir_all_nofollow(dir: &Path) -> io::Result<()> {
    refuse_symlinks_under_treeship(dir)?;
    std::fs::create_dir_all(dir)
}

/// A lock file under `.treeship`: opened read-write without truncation and
/// without following a link anywhere from the anchor down.
pub fn open_lock_under_treeship(path: &Path) -> io::Result<std::fs::File> {
    refuse_symlinks_under_treeship(path)?;
    open_rw_nofollow(path, 0o600)
}

/// Open a session's event log only when nothing from `.treeship` down to
/// its directory is a link (`.treeship/sessions -> elsewhere` would put
/// every event, lock and counter there).
pub fn open_event_log(dir: &Path) -> Result<EventLog, EventLogError> {
    refuse_symlinks_under_treeship(dir).map_err(EventLogError::from)?;
    EventLog::open(dir)
}

/// A file written where the user asked (a proof, a package, a credential,
/// a shell rc file): created fresh and renamed into place, refusing a link
/// at the path. An existing file keeps its mode; a new one is 0644.
pub fn write_user_path(path: &Path, bytes: &[u8]) -> io::Result<()> {
    refuse_symlink(path)?;
    let mode = existing_mode(path).unwrap_or(0o644);
    write_atomic(path, bytes, mode)
}

/// Where a home-directory file really lives. For the fixed set of files
/// Treeship keeps in the user's home (shell rc files, `~/.treeship`'s
/// trust roots, templates and merkle records) a link is the user's own
/// (dotfiles) and is followed to its target, a link whose target does not
/// exist yet included (the target is created); anywhere else, a
/// repository cloned under the home included, a link at the file is
/// refused, as for any user-chosen path. Missing trailing components are
/// kept, so a file that does not exist yet resolves to its future place.
pub fn resolve_home_link(path: &Path) -> io::Result<std::path::PathBuf> {
    if !is_user_home_file(path) {
        refuse_symlink(path)?;
        return Ok(path.to_path_buf());
    }
    resolve_following(path, 0)
}

fn resolve_following(path: &Path, depth: u8) -> io::Result<std::path::PathBuf> {
    // A dangling link at the file: follow what it names (relative to its
    // own directory) so the target gets created, up to a small depth.
    if depth < 8
        && path
            .symlink_metadata()
            .map(|m| m.is_symlink())
            .unwrap_or(false)
    {
        if let Ok(target) = std::fs::read_link(path) {
            let target = if target.is_absolute() {
                target
            } else {
                path.parent().unwrap_or(Path::new(".")).join(target)
            };
            if !target.exists() {
                return resolve_following(&target, depth + 1);
            }
        }
    }
    let mut prefix = path.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canonical) = prefix.canonicalize() {
            let mut out = canonical;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return Ok(out);
        }
        match prefix.file_name() {
            Some(name) => rest.push(name.to_os_string()),
            None => return Ok(path.to_path_buf()),
        }
        if !prefix.pop() {
            return Ok(path.to_path_buf());
        }
    }
}

/// A file in the user's own home: the link at it (if any) is followed to
/// its target, which is then written fresh and renamed into place. An
/// existing target keeps its mode; a new file gets `default_mode`.
pub fn write_home_path(path: &Path, bytes: &[u8], default_mode: u32) -> io::Result<()> {
    let target = resolve_home_link(path)?;
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mode = existing_mode(&target).unwrap_or(default_mode);
    write_atomic(&target, bytes, mode)
}

/// The files Treeship keeps in the user's own home, by fixed path: the
/// shell rc files `install` edits, and `~/.treeship`'s trust roots,
/// templates and merkle records. Judged by the path as given (and its
/// canonical directory), never by where a link at the file points, so a
/// link inside a repository, cloned under the home or not, never counts.
fn is_user_home_file(path: &Path) -> bool {
    let Some(home) = home::home_dir() else {
        return false;
    };
    let in_home = |p: &Path| -> bool {
        let files = [
            home.join(".zshrc"),
            home.join(".bashrc"),
            home.join(".config").join("fish").join("config.fish"),
            home.join(".treeship").join("trust_roots.json"),
        ];
        let dirs = [
            home.join(".treeship").join("templates"),
            home.join(".treeship").join("merkle"),
        ];
        files.iter().any(|f| f == p) || dirs.iter().any(|d| p.starts_with(d))
    };
    if in_home(path) {
        return true;
    }
    // The same place spelled through a canonical home (/private/var on
    // macOS, a linked home directory): compare the file's directory.
    match (
        home.canonicalize(),
        path.parent().and_then(|p| p.canonicalize().ok()),
    ) {
        (Ok(h), Some(p)) if h != home => {
            let Ok(rel) = p.strip_prefix(&h) else {
                return false;
            };
            let respelled = home.join(rel).join(path.file_name().unwrap_or_default());
            in_home(&respelled)
        }
        _ => false,
    }
}

#[cfg(unix)]
fn existing_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|m| m.file_type().is_file())
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn existing_mode(_path: &Path) -> Option<u32> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Tests that point $HOME at a temp dir must not overlap.
    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn set_home(
        home: &Path,
    ) -> (
        std::sync::MutexGuard<'static, ()>,
        Option<std::ffi::OsString>,
    ) {
        let guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("HOME");
        std::env::set_var("HOME", home);
        (guard, saved)
    }

    fn restore_home(saved: Option<std::ffi::OsString>) {
        match saved {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }

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
        assert!(write_under_treeship(&target, b"{}", 0o600).is_err());
        assert!(create_dir_all_nofollow(&ws.join(".treeship").join("keys")).is_err());
        assert!(open_lock_under_treeship(&ws.join(".treeship").join("x.lock")).is_err());
        assert!(open_event_log(&ws.join(".treeship").join("sessions").join("s")).is_err());
        assert_eq!(
            std::fs::read(elsewhere.join("config.json")).unwrap(),
            b"{\"auths\":{}}"
        );
        assert!(!elsewhere.join("keys").exists());
        assert!(!elsewhere.join("x.lock").exists());
        assert!(!elsewhere.join("sessions").exists());
    }

    #[test]
    fn a_linked_directory_below_treeship_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("outside");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let ts = root.path().join("repo").join(".treeship");
        std::fs::create_dir_all(&ts).unwrap();
        std::os::unix::fs::symlink(&elsewhere, ts.join("sessions")).unwrap();
        let evt = ts.join("sessions").join("ssn_1");
        assert!(open_event_log(&evt).is_err());
        assert!(create_dir_all_nofollow(&ts.join("sessions").join("ssn_1.treeship")).is_err());
        assert!(write_under_treeship(&ts.join("sessions").join("x"), b"x", 0o600).is_err());
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    #[test]
    fn a_home_file_follows_the_users_own_link_but_a_repo_file_does_not() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let dotfiles = home.join("dotfiles");
        std::fs::create_dir_all(&dotfiles).unwrap();
        std::fs::write(dotfiles.join("zshrc"), b"# mine\n").unwrap();
        std::fs::set_permissions(
            dotfiles.join("zshrc"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::os::unix::fs::symlink(dotfiles.join("zshrc"), home.join(".zshrc")).unwrap();
        // `home` is what the process treats as $HOME for this test.
        let (_guard, saved) = set_home(&home);
        let result = write_home_path(&home.join(".zshrc"), b"# mine\n# hook\n", 0o644);
        let missing = resolve_home_link(&home.join(".config").join("fish").join("config.fish"));
        let repo_link = root.path().join("repo").join("out.json");
        std::fs::create_dir_all(repo_link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(dotfiles.join("zshrc"), &repo_link).unwrap();
        let outside = write_home_path(&repo_link, b"x", 0o644);
        restore_home(saved);
        result.unwrap();
        assert_eq!(
            std::fs::read(dotfiles.join("zshrc")).unwrap(),
            b"# mine\n# hook\n"
        );
        assert!(
            home.join(".zshrc").is_symlink(),
            "the user's link was replaced"
        );
        assert_eq!(
            std::fs::metadata(dotfiles.join("zshrc"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(missing
            .unwrap()
            .ends_with(std::path::Path::new(".config/fish/config.fish")));
        assert!(outside.is_err(), "a link outside the home was followed");
        assert_eq!(
            std::fs::read(dotfiles.join("zshrc")).unwrap(),
            b"# mine\n# hook\n"
        );
    }

    #[test]
    fn only_fixed_home_files_follow_links_and_a_dangling_one_is_created() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir_all(home.join(".treeship")).unwrap();
        let (_guard, saved) = set_home(&home);
        // A repository cloned under the home is not a home file.
        let repo_file = home
            .join("src")
            .join("repo")
            .join(".treeship")
            .join("trust_roots.json");
        std::fs::create_dir_all(repo_file.parent().unwrap()).unwrap();
        let victim = home.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, &repo_file).unwrap();
        let repo_write = write_home_path(&repo_file, b"x", 0o600);
        // ~/.treeship/trust_roots.json is, and a dangling link there is
        // followed and its target created.
        let roots = home.join(".treeship").join("trust_roots.json");
        let target = home
            .join("dotfiles")
            .join("treeship")
            .join("trust_roots.json");
        std::os::unix::fs::symlink(&target, &roots).unwrap();
        let roots_write = write_home_path(&roots, b"{}", 0o600);
        // A random file under the home is not a home file either.
        let other = home.join("notes.txt");
        std::os::unix::fs::symlink(&victim, &other).unwrap();
        let other_write = write_home_path(&other, b"x", 0o644);
        restore_home(saved);
        assert!(
            repo_write.is_err(),
            "a repository link under the home was followed"
        );
        assert!(
            other_write.is_err(),
            "an arbitrary home file followed its link"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        roots_write.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"{}");
        assert!(roots.is_symlink());
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
        write_under_treeship(&target, b"{}", 0o600).unwrap();
    }

    #[test]
    fn a_user_path_is_never_a_link_target_and_keeps_its_mode() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let link = root.path().join("out.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(write_user_path(&link, b"x").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        // A hard link to the victim is replaced, not written through.
        let hard = root.path().join("hard.json");
        std::fs::hard_link(&victim, &hard).unwrap();
        write_user_path(&hard, b"x").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert_eq!(std::fs::read(&hard).unwrap(), b"x");
        // An existing file keeps its mode.
        use std::os::unix::fs::PermissionsExt;
        let rc = root.path().join(".zshrc");
        std::fs::write(&rc, b"old").unwrap();
        std::fs::set_permissions(&rc, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_user_path(&rc, b"new").unwrap();
        assert_eq!(
            std::fs::metadata(&rc).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_user_path(&root.path().join("fresh.json"), b"x").unwrap();
    }
}
