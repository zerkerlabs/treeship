use std::{collections::HashMap, fs, path::{Path, PathBuf}};
use serde::{Deserialize, Serialize};

// ── v0.3.0 Config ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ship_id:        String,
    pub name:           Option<String>,
    pub storage_dir:    String,
    pub keys_dir:       String,
    pub default_key_id: String,

    /// Named dock connections (v0.3+).
    #[serde(default)]
    pub docks:       HashMap<String, DockEntry>,

    /// Currently active dock name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_dock: Option<String>,

    /// Legacy v0.1/v0.2 hub config -- read for migration, never written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub: Option<LegacyHubConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockEntry {
    pub dock_id:    String,
    pub key_id:     String,
    pub endpoint:   String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_push:  Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dock_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dock_secret_key: Option<String>,
}

/// Legacy config from v0.1/v0.2 -- only used for migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyHubConfig {
    #[serde(default)]
    pub status:          Option<String>,
    #[serde(default)]
    pub endpoint:        Option<String>,
    #[serde(default)]
    pub workspace_id:    Option<String>,
    #[serde(default)]
    pub dock_id:         Option<String>,
    #[serde(default)]
    pub sync_mode:       Option<String>,
    #[serde(default)]
    pub dock_public_key: Option<String>,
    #[serde(default)]
    pub dock_secret_key: Option<String>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

impl Config {
    /// Returns true if there is an active dock.
    pub fn is_docked(&self) -> bool {
        self.active_dock.is_some()
            && self.active_dock.as_deref().map_or(false, |name| self.docks.contains_key(name))
    }

    /// Get the active dock entry, if any.
    pub fn active_dock_entry(&self) -> Option<(&str, &DockEntry)> {
        let name = self.active_dock.as_deref()?;
        let entry = self.docks.get(name)?;
        Some((name, entry))
    }

    /// Resolve a dock by --dock flag (name or dock_id), falling back to active_dock.
    pub fn resolve_dock(&self, flag: Option<&str>) -> Result<(&str, &DockEntry), String> {
        let name = match flag {
            Some(f) => {
                // Try by name first
                if self.docks.contains_key(f) {
                    f.to_string()
                } else {
                    // Try by dock_id
                    self.docks.iter()
                        .find(|(_, v)| v.dock_id == f)
                        .map(|(k, _)| k.clone())
                        .ok_or_else(|| format!("dock {:?} not found\n  Run: treeship dock ls", f))?
                }
            }
            None => {
                self.active_dock.clone()
                    .ok_or_else(|| "no active dock\n  Run: treeship dock login".to_string())?
            }
        };

        let entry = self.docks.get(name.as_str())
            .ok_or_else(|| format!("dock {:?} not found in config", name))?;

        // SAFETY: name exists in self.docks, so we can get a &str with the same lifetime
        let name_ref = self.docks.get_key_value(name.as_str()).unwrap().0.as_str();
        Ok((name_ref, entry))
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

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
            Self::NotFound(p)   => write!(f, "treeship not initialized at {} -- run 'treeship init'", p.display()),
            Self::NoHome        => write!(f, "cannot determine home directory"),
        }
    }
}

impl std::error::Error for ConfigError {}
impl From<std::io::Error>    for ConfigError { fn from(e: std::io::Error)    -> Self { Self::Io(e) } }
impl From<serde_json::Error> for ConfigError { fn from(e: serde_json::Error) -> Self { Self::Json(e) } }

// ── Load / Save / Migrate ────────────────────────────────────────────────────

pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    let home = home::home_dir().ok_or(ConfigError::NoHome)?;
    Ok(home.join(".treeship").join("config.json"))
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::NotFound(path.to_path_buf()));
    }
    let bytes = fs::read(path)?;
    let mut cfg: Config = serde_json::from_slice(&bytes)?;

    // Auto-migrate v0.1/v0.2 hub config to v0.3 docks format.
    if migrate_legacy_hub(&mut cfg) {
        let _ = save(&cfg, path);
    }

    Ok(cfg)
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

/// Migrate v0.1/v0.2 flat `hub` config to v0.3 `docks` map.
/// Returns true if migration occurred.
fn migrate_legacy_hub(cfg: &mut Config) -> bool {
    let hub = match cfg.hub.take() {
        Some(h) => h,
        None => return false,
    };

    // Only migrate if docks is empty (first run after upgrade).
    if !cfg.docks.is_empty() {
        return false;
    }

    let status = hub.status.as_deref().unwrap_or("undocked");
    if status != "docked" {
        return true; // Clear the hub field but don't create a dock entry
    }

    let dock_id  = match hub.dock_id {
        Some(d) => d,
        None => return true,
    };
    let endpoint = hub.endpoint.unwrap_or_else(|| "https://api.treeship.dev".into());

    let now = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{}Z", secs)
    };

    cfg.docks.insert("default".to_string(), DockEntry {
        dock_id,
        key_id:          cfg.default_key_id.clone(),
        endpoint,
        created_at:      now,
        last_push:       None,
        dock_public_key: hub.dock_public_key,
        dock_secret_key: hub.dock_secret_key,
    });
    cfg.active_dock = Some("default".to_string());

    true
}

/// Build a Config for a freshly-initialized ship.
pub fn new_config(config_path: &Path, ship_id: &str, default_key_id: &str, name: Option<String>) -> Config {
    let dir = config_path.parent().unwrap_or(Path::new("."));
    Config {
        ship_id:        ship_id.to_string(),
        name,
        storage_dir:    dir.join("artifacts").to_string_lossy().into_owned(),
        keys_dir:       dir.join("keys").to_string_lossy().into_owned(),
        default_key_id: default_key_id.to_string(),
        docks:          HashMap::new(),
        active_dock:    None,
        hub:            None,
    }
}
