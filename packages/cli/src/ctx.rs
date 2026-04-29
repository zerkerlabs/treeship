use std::path::PathBuf;

use treeship_core::{keys::Store as KeyStore, storage::Store as ArtifactStore};

use crate::config::{self, Config, ConfigError, ConfigSource};

/// Everything a command needs, opened and ready.
pub struct Ctx {
    pub config:        Config,
    pub config_path:   PathBuf,
    pub config_source: ConfigSource,
    pub keys:          KeyStore,
    pub storage:       ArtifactStore,
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
            Self::Config(e)  => write!(f, "{e}"),
            Self::Keys(e)    => write!(f, "keys: {e}"),
            Self::Storage(e) => write!(f, "storage: {e}"),
        }
    }
}

impl std::error::Error for CtxError {}
impl From<ConfigError>                          for CtxError { fn from(e: ConfigError)                          -> Self { Self::Config(e) } }
impl From<treeship_core::keys::KeyError>        for CtxError { fn from(e: treeship_core::keys::KeyError)        -> Self { Self::Keys(e) } }
impl From<treeship_core::storage::StorageError> for CtxError { fn from(e: treeship_core::storage::StorageError) -> Self { Self::Storage(e) } }

pub fn open(config_path_override: Option<&str>) -> Result<Ctx, CtxError> {
    let (config_path, config_source) = match config_path_override {
        Some(p) => (PathBuf::from(p), ConfigSource::Explicit),
        None    => config::resolve_config_path()?,
    };

    let cfg     = config::load(&config_path)?;
    let keys    = KeyStore::open(&cfg.keys_dir)?;
    let storage = ArtifactStore::open(&cfg.storage_dir)?;

    Ok(Ctx { config: cfg, config_path, config_source, keys, storage })
}
