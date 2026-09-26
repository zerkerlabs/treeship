//! Filesystem writes that never follow a symlink and never write into a
//! hard link.
//!
//! A repository controls its own `.treeship/` directory, and a keystore,
//! journal, store or session directory can be pointed anywhere by a link
//! inside it. Every write to those places goes through here: files are
//! written by creating an exclusively named, randomly named temp file in
//! the same directory and renaming it over the target (so a link or a
//! hard link at the target is replaced, never written through), logs are
//! opened for append with O_NOFOLLOW and refused when the inode has more
//! than one name, the components below a store root are checked one by
//! one, and directories are created only when nothing on the way is a
//! link. Components above a store root are the user's own environment (a
//! linked home directory is theirs) and are not judged.
//!
//! Residual: intermediate directories are checked and then used, not
//! opened with `openat`; a link planted between the check and the write
//! is not caught. Non-Unix targets have no O_NOFOLLOW and rely on the
//! checks alone. On wasm there is no filesystem to protect; the shim
//! below keeps the call sites compiling.

pub use imp::*;

#[cfg(not(target_family = "wasm"))]
mod imp {
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

    fn refused_hardlink(path: &Path) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to write to {}: the file has more than one name (a hard link), so the write would land elsewhere too",
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

    /// Refuse when the open file has more than one directory entry. A hard
    /// link to a victim file shares its inode, so an in-place write or an
    /// append would reach the victim through our own name.
    fn refuse_hardlinked(file: &fs::File, path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if file.metadata()?.nlink() > 1 {
                return Err(refused_hardlink(path));
            }
        }
        #[cfg(not(unix))]
        let _ = (file, path);
        Ok(())
    }

    fn exclusive_options(mode: u32) -> fs::OpenOptions {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(not(unix))]
        let _ = mode;
        opts
    }

    /// Open `path` for read and write without truncation (a lock file), with
    /// `mode` at creation and no link following. Nothing is ever written
    /// through the handle, so a hard link here is harmless.
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

    /// Open for append (a log), with `mode` at creation, no link following,
    /// and refused when the file is hard-linked elsewhere.
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
        let file = opts
            .open(path)
            .map_err(|e| if is_symlink(path) { refused(path) } else { e })?;
        refuse_hardlinked(&file, path)?;
        Ok(file)
    }

    /// Write `bytes` to `path` atomically: an exclusively created, randomly
    /// named temp file in the same directory, then rename. A link at `path`
    /// is refused rather than replaced; a hard link at `path` is replaced by
    /// a fresh inode, so the other name keeps its old bytes; a link planted
    /// at any predictable temp name cannot be hit, because the name is not
    /// predictable. This is the only way a whole file is written.
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
            match exclusive_options(mode).open(&tmp) {
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

    /// Copy a regular file to `to` without following a link at either end:
    /// the source is read through its own name only when it is not a link,
    /// and the destination is written atomically.
    pub fn copy_nofollow(from: &Path, to: &Path, mode: u32) -> io::Result<()> {
        refuse_symlink(from)?;
        let bytes = fs::read(from)?;
        write_atomic(to, &bytes, mode)
    }

    /// `chmod` that never follows a link: the path is opened read-only with
    /// O_NOFOLLOW (a directory opens fine that way) and the mode is set on
    /// the handle. No-op off Unix.
    pub fn set_mode_nofollow(path: &Path, mode: u32) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(|e| if is_symlink(path) { refused(path) } else { e })?;
            file.set_permissions(fs::Permissions::from_mode(mode))
        }
        #[cfg(not(unix))]
        {
            let _ = (path, mode);
            Ok(())
        }
    }

    fn random_hex(n: usize) -> String {
        use rand::RngCore;
        let mut b = vec![0u8; n];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

/// wasm has no filesystem to protect (the browser and Node builds only
/// verify); these keep the shared call sites compiling and behave like the
/// plain `std::fs` calls, which fail at runtime on that target anyway.
#[cfg(target_family = "wasm")]
mod imp {
    use std::fs;
    use std::io;
    use std::path::Path;

    pub fn is_symlink(_path: &Path) -> bool {
        false
    }
    pub fn refuse_symlink(_path: &Path) -> io::Result<()> {
        Ok(())
    }
    pub fn refuse_symlinks_below(_root: &Path, _path: &Path) -> io::Result<()> {
        Ok(())
    }
    pub fn refuse_symlinks_from(_path: &Path, _anchor: &str) -> io::Result<()> {
        Ok(())
    }
    pub fn create_dir_all_below(_root: &Path, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)
    }
    pub fn open_rw_nofollow(path: &Path, _mode: u32) -> io::Result<fs::File> {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
    }
    pub fn open_append_nofollow(path: &Path, _mode: u32) -> io::Result<fs::File> {
        fs::OpenOptions::new().append(true).create(true).open(path)
    }
    pub fn write_atomic(path: &Path, bytes: &[u8], _mode: u32) -> io::Result<()> {
        fs::write(path, bytes)
    }
    pub fn copy_nofollow(from: &Path, to: &Path, _mode: u32) -> io::Result<()> {
        fs::copy(from, to).map(|_| ())
    }
    pub fn set_mode_nofollow(_path: &Path, _mode: u32) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

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
        assert!(write_atomic(&link, b"x", 0o600).is_err());
        assert!(open_rw_nofollow(&link, 0o600).is_err());
        assert!(open_append_nofollow(&link, 0o600).is_err());
        assert!(set_mode_nofollow(&link, 0o600).is_err());
        assert!(copy_nofollow(&victim, &link, 0o600).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(link.is_symlink(), "the link itself was replaced");
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o600,
            "chmod reached the victim through the link"
        );
    }

    #[test]
    fn a_hard_link_is_replaced_by_atomic_writes_and_refused_by_appends() {
        let d = tmp();
        let victim = d.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        let ours = d.path().join("ours");
        fs::hard_link(&victim, &ours).unwrap();
        // Append: refused, the victim untouched.
        assert!(open_append_nofollow(&ours, 0o600).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        // Whole-file write: our name gets a new inode, the victim keeps its bytes.
        write_atomic(&ours, b"new", 0o600).unwrap();
        assert_eq!(fs::read(&ours).unwrap(), b"new");
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&victim).unwrap().nlink(), 1);
        // A fresh log with one name appends fine.
        let log = d.path().join("log");
        open_append_nofollow(&log, 0o600).unwrap();
        open_append_nofollow(&log, 0o600).unwrap();
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
        // A linked directory further down (sessions, sub/keys) is refused too.
        let repo2 = d.path().join("repo2");
        fs::create_dir_all(repo2.join(".treeship")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, repo2.join(".treeship").join("sessions")).unwrap();
        assert!(refuse_symlinks_from(
            &repo2
                .join(".treeship")
                .join("sessions")
                .join("ssn_x")
                .join("events.jsonl"),
            ".treeship"
        )
        .is_err());
        assert!(refuse_symlinks_from(
            &repo2.join(".treeship").join("keys").join("manifest.json"),
            ".treeship"
        )
        .is_ok());
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

    #[test]
    fn set_mode_nofollow_works_on_directories_and_files() {
        let d = tmp();
        let dir = d.path().join("keys");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("k.json");
        fs::write(&file, b"{}").unwrap();
        set_mode_nofollow(&dir, 0o700).unwrap();
        set_mode_nofollow(&file, 0o600).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
