use std::path::PathBuf;

use treeship_core::{keys::Store as KeyStore, storage::Store as ArtifactStore};

use crate::config::{self, Config, ConfigError, ConfigSource};

/// Everything a command needs, opened and ready.
pub struct Ctx {
    pub config: Config,
    pub config_path: PathBuf,
    pub config_source: ConfigSource,
    pub keys: KeyStore,
    pub storage: ArtifactStore,
}

#[derive(Debug)]
pub enum CtxError {
    Config(ConfigError),
    Keys(treeship_core::keys::KeyError),
    Storage(treeship_core::storage::StorageError),
}

impl std::fmt::Display for CtxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{e}"),
            Self::Keys(e) => write!(f, "keys: {e}"),
            Self::Storage(e) => write!(f, "storage: {e}"),
        }
    }
}

impl std::error::Error for CtxError {}
impl From<ConfigError> for CtxError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}
impl From<treeship_core::keys::KeyError> for CtxError {
    fn from(e: treeship_core::keys::KeyError) -> Self {
        Self::Keys(e)
    }
}
impl From<treeship_core::storage::StorageError> for CtxError {
    fn from(e: treeship_core::storage::StorageError) -> Self {
        Self::Storage(e)
    }
}

impl Ctx {
    /// Where the Approval Use Journal lives for this workspace: beside the
    /// keystore, not beside the config file that was resolved. See
    /// [`journal_dir_for`].
    pub fn journal_dir(&self) -> PathBuf {
        journal_dir_for(&self.config, &self.config_path)
    }
}

/// The Approval Use Journal follows the keystore. A project stub
/// (`{"extends": <global config>, "project": true}`) shares the global ship,
/// its key, its grants and its artifact store, so it must share the journal
/// too: with one journal per stub, a `--max-uses 1` grant could be spent once
/// from every directory on the same machine that resolved to a different
/// config, and each use verified clean as `use 1/1` (film findings
/// 2026-09-22, #11). A workspace with its own keystore under its own
/// `.treeship/` is unchanged, because there the two locations coincide.
///
/// A journal written at the old location beside a stub is moved once, so
/// uses recorded before this rule keep counting against the grant.
pub fn journal_dir_for(cfg: &Config, config_path: &std::path::Path) -> PathBuf {
    let beside_config = config_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("journals")
        .join("approval-use");
    let owner = match std::path::Path::new(&cfg.keys_dir).parent() {
        Some(p) => p.to_path_buf(),
        None => return beside_config,
    };
    let primary = owner.join("journals").join("approval-use");
    if primary != beside_config && beside_config.is_dir() && !primary.is_dir() {
        if let Some(parent) = primary.parent() {
            let _ = crate::safe_fs::create_dir_all_nofollow(parent);
        }
        if crate::safe_fs::refuse_symlinks_under_treeship(&primary).is_ok() {
            let _ = std::fs::rename(&beside_config, &primary);
        }
    }
    primary
}

/// The keystore and the artifact store are judged from the `.treeship`
/// anchor down, not only at their own directory: `keys_dir = sub/keys`
/// with `.treeship/sub -> elsewhere` would otherwise create both stores
/// wherever the link points.
fn refuse_linked_store_dirs(cfg: &Config) -> Result<(), CtxError> {
    for dir in [&cfg.keys_dir, &cfg.storage_dir] {
        crate::safe_fs::refuse_symlinks_under_treeship(std::path::Path::new(dir)).map_err(|e| {
            CtxError::Config(ConfigError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "{e}. If this link is deliberate (dotfiles), point --config at a config whose keys_dir and storage_dir are the real directories"
                ),
            )))
        })?;
    }
    Ok(())
}

pub fn open(config_path_override: Option<&str>) -> Result<Ctx, CtxError> {
    let (config_path, config_source) = match config_path_override {
        Some(p) => (PathBuf::from(p), ConfigSource::Explicit),
        None => config::resolve_config_path()?,
    };

    let cfg = config::load(&config_path)?;
    config::refuse_store_dirs_outside_project(&cfg, &config_path, config_source)?;
    refuse_linked_store_dirs(&cfg)?;
    let keys = KeyStore::open(&cfg.keys_dir)?;
    let storage = ArtifactStore::open(&cfg.storage_dir)?;

    Ok(Ctx {
        config: cfg,
        config_path,
        config_source,
        keys,
        storage,
    })
}
