use std::{fs, path::{Path, PathBuf}};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ship_id:       String,
    pub name:          Option<String>,
    pub storage_dir:   String,
    pub keys_dir:      String,
    pub default_key_id: String,
    pub hub:           HubConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    pub status:          String,   // "docked" | "undocked"
    pub endpoint:        Option<String>,
    pub workspace_id:    Option<String>,
    pub dock_id:         Option<String>,
    pub sync_mode:       Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dock_public_key: Option<String>,  // hex encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dock_secret_key: Option<String>,  // hex encoded
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            status:          "undocked".into(),
            endpoint:        None,
            workspace_id:    None,
            dock_id:         None,
            sync_mode:       None,
            dock_public_key: None,
            dock_secret_key: None,
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Json(serde_json::Error),
    NotFound(PathBuf),
    NoHome,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)         => write!(f, "config io: {e}"),
            Self::Json(e)       => write!(f, "config json: {e}"),
            Self::NotFound(p)   => write!(f, "treeship not initialized at {} — run 'treeship init'", p.display()),
            Self::NoHome        => write!(f, "cannot determine home directory"),
        }
    }
}

impl std::error::Error for ConfigError {}
impl From<std::io::Error>    for ConfigError { fn from(e: std::io::Error)    -> Self { Self::Io(e) } }
impl From<serde_json::Error> for ConfigError { fn from(e: serde_json::Error) -> Self { Self::Json(e) } }

pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    let home = home::home_dir().ok_or(ConfigError::NoHome)?;
    Ok(home.join(".treeship").join("config.json"))
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::NotFound(path.to_path_buf()));
    }
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn save(cfg: &Config, path: &Path) -> Result<(), ConfigError> {
    let dir = path.parent().unwrap_or(path);
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let json = serde_json::to_vec_pretty(cfg)?;
    fs::write(path, &json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Build a Config for a freshly-initialized ship.
/// All paths are derived from the config file's parent directory.
pub fn new_config(config_path: &Path, ship_id: &str, default_key_id: &str, name: Option<String>) -> Config {
    let dir = config_path.parent().unwrap_or(Path::new("."));
    Config {
        ship_id:        ship_id.to_string(),
        name,
        storage_dir:    dir.join("artifacts").to_string_lossy().into_owned(),
        keys_dir:       dir.join("keys").to_string_lossy().into_owned(),
        default_key_id: default_key_id.to_string(),
        hub:            HubConfig::default(),
    }
}
