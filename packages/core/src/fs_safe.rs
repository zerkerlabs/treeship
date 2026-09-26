//! Filesystem writes that never follow a symlink.
//!
//! A repository controls its own `.treeship/` directory, and a keystore,
//! journal, store or session directory can be pointed anywhere by a link
//! inside it. Every write to those places goes through here: the final
//! path component is opened with O_NOFOLLOW, the components below a store
//! root are checked one by one, temporary files get random names and are
//! created exclusively, and directories are created only when nothing on
//! the way is a link. Components above a store root are the user's own
//! environment (a linked home directory is theirs) and are not judged.
#![cfg(not(target_family = "wasm"))]

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Is `path` itself a symlink? (False when it does not exist.)
pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn refused(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "refusing to write through a symlink at {} (nothing under a Treeship store may point elsewhere)",
            path.display()
        ),
    )
}

/// Refuse when `path`'s final component is a symlink.
pub fn refuse_symlink(path: &Path) -> io::Result<()> {
    if is_symlink(path) {
        return Err(refused(path));
    }
    Ok(())
}

/// Refuse when `root`, or any component of `path` below `root`, is a
/// symlink. `path` need not exist yet; components that do not exist are
/// fine. When `path` is not under `root`, only `path` itself is judged.
pub fn refuse_symlinks_below(root: &Path, path: &Path) -> io::Result<()> {
    refuse_symlink(root)?;
    let Ok(rest) = path.strip_prefix(root) else {
        return refuse_symlink(path);
    };
    let mut prefix = root.to_path_buf();
    for component in rest.components() {
        prefix.push(component);
        refuse_symlink(&prefix)?;
    }
    Ok(())
}

/// Refuse when the component named `anchor` (for example `.treeship`), or
/// anything beneath it on the way to `path`, is a symlink. Components
/// before the anchor are not judged. Without an anchor in the path, only
/// the final component is judged.
pub fn refuse_symlinks_from(path: &Path, anchor: &str) -> io::Result<()> {
    let mut prefix = PathBuf::new();
    let mut checking = false;
    for component in path.components() {
        prefix.push(component);
        if !checking {
            match component {
                Component::Normal(name) if name == anchor => checking = true,
                _ => continue,
            }
        }
        refuse_symlink(&prefix)?;
    }
    if !checking {
        refuse_symlink(path)?;
    }
    Ok(())
}

/// `create_dir_all` for `dir` under `root`, refusing links on the way.
pub fn create_dir_all_below(root: &Path, dir: &Path) -> io::Result<()> {
    refuse_symlinks_below(root, dir)?;
    fs::create_dir_all(dir)
}

fn open_options(mode: u32, exclusive: bool) -> fs::OpenOptions {
    let mut opts = fs::OpenOptions::new();
    opts.write(true);
    if exclusive {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts
}

/// Open `path` for writing (create or truncate) with `mode` set at
/// creation, never following a link at the final component.
pub fn open_nofollow(path: &Path, mode: u32) -> io::Result<fs::File> {
    open_options(mode, false).open(path).map_err(
        |e| {
            if is_symlink(path) {
                refused(path)
            } else {
                e
            }
        },
    )
}

/// Open `path` for read and write without truncation (a lock file), with
/// `mode` at creation and no link following.
pub fn open_rw_nofollow(path: &Path, mode: u32) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)
        .map_err(|e| if is_symlink(path) { refused(path) } else { e })
}

/// Open for append (a log), with `mode` at creation and no link following.
pub fn open_append_nofollow(path: &Path, mode: u32) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)
        .map_err(|e| if is_symlink(path) { refused(path) } else { e })
}

/// Write `bytes` to `path` in place, never through a link.
pub fn write_nofollow(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    let mut f = open_nofollow(path, mode)?;
    f.write_all(bytes)?;
    f.flush()
}

/// Write `bytes` to `path` atomically: an exclusively created, randomly
/// named temp file in the same directory, then rename. A link at `path`
/// is refused rather than replaced; a link planted at any predictable
/// temp name cannot be hit, because the name is not predictable.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    refuse_symlink(path)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let mut last_err = None;
    for _ in 0..16 {
        let tmp = dir.join(format!(".{stem}.{}.tmp", random_hex(8)));
        match open_options(mode, true).open(&tmp) {
            Ok(mut f) => {
                let result = f
                    .write_all(bytes)
                    .and_then(|_| f.sync_all())
                    .and_then(|_| fs::rename(&tmp, path));
                if let Err(e) = result {
                    let _ = fs::remove_file(&tmp);
                    return Err(e);
                }
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("could not create a temp file")))
}

fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_linked_final_component_is_refused_everywhere() {
        let d = tmp();
        let victim = d.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(write_nofollow(&link, b"x", 0o600).is_err());
        assert!(write_atomic(&link, b"x", 0o600).is_err());
        assert!(open_rw_nofollow(&link, 0o600).is_err());
        assert!(open_append_nofollow(&link, 0o600).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(link.is_symlink(), "the link itself was replaced");
    }

    #[test]
    fn links_below_a_root_are_refused_but_the_root_may_sit_under_a_link() {
        let d = tmp();
        let real = d.path().join("real");
        fs::create_dir_all(real.join("store")).unwrap();
        let linked_home = d.path().join("home");
        std::os::unix::fs::symlink(&real, &linked_home).unwrap();
        let root = linked_home.join("store");
        // Above the root: fine.
        assert!(refuse_symlinks_below(&root, &root.join("a.json")).is_ok());
        // The root itself a link: refused.
        let linked_root = d.path().join("store-link");
        std::os::unix::fs::symlink(real.join("store"), &linked_root).unwrap();
        assert!(refuse_symlinks_below(&linked_root, &linked_root.join("a.json")).is_err());
        // A link below the root: refused, whether it exists as a dir link or file link.
        std::os::unix::fs::symlink(&real, real.join("store").join("sub")).unwrap();
        assert!(refuse_symlinks_below(&root, &root.join("sub").join("x")).is_err());
        assert!(create_dir_all_below(&root, &root.join("sub").join("deeper")).is_err());
        assert!(create_dir_all_below(&root, &root.join("ok").join("deeper")).is_ok());
    }

    #[test]
    fn anchor_form_checks_from_the_anchor_only() {
        let d = tmp();
        let real = d.path().join("real");
        fs::create_dir_all(real.join(".treeship")).unwrap();
        let home = d.path().join("home");
        std::os::unix::fs::symlink(&real, &home).unwrap();
        assert!(
            refuse_symlinks_from(&home.join(".treeship").join("config.json"), ".treeship").is_ok()
        );
        let elsewhere = d.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let repo = d.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        std::os::unix::fs::symlink(&elsewhere, repo.join(".treeship")).unwrap();
        assert!(
            refuse_symlinks_from(&repo.join(".treeship").join("config.json"), ".treeship").is_err()
        );
    }

    #[test]
    fn atomic_writes_replace_files_and_ignore_planted_temp_links() {
        let d = tmp();
        let target = d.path().join("data.json");
        let victim = d.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, d.path().join("data.json.tmp")).unwrap();
        write_atomic(&target, b"one", 0o600).unwrap();
        write_atomic(&target, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"two");
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let leftovers: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp") && n != "data.json.tmp")
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }
}
