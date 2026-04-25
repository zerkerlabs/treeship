use std::{collections::HashMap, fs, path::{Path, PathBuf}};
use serde::{Deserialize, Serialize};

// -- v0.4.0 Config ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ship_id:        String,
    pub name:           Option<String>,
    pub storage_dir:    String,
    pub keys_dir:       String,
    pub default_key_id: String,

    /// Named hub connections (v0.4+).
    #[serde(default, alias = "docks")]
    pub hub_connections: HashMap<String, HubConnection>,

    /// Currently active hub connection name.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "active_dock")]
    pub active_hub: Option<String>,

    /// Legacy v0.1/v0.2 hub config -- read for migration, never written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub: Option<LegacyHubConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConnection {
    #[serde(alias = "dock_id")]
    pub hub_id:    String,
    pub key_id:     String,
    pub endpoint:   String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_push:  Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "dock_public_key")]
    pub hub_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "dock_secret_key")]
    pub hub_secret_key: Option<String>,
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

// -- Helpers ------------------------------------------------------------------

impl Config {
    /// Returns true if there is an active hub connection.
    pub fn is_attached(&self) -> bool {
        self.active_hub.is_some()
            && self.active_hub.as_deref().map_or(false, |name| self.hub_connections.contains_key(name))
    }

    /// Get the active hub connection entry, if any.
    pub fn active_hub_connection(&self) -> Option<(&str, &HubConnection)> {
        let name = self.active_hub.as_deref()?;
        let entry = self.hub_connections.get(name)?;
        Some((name, entry))
    }

    /// Resolve a hub connection by --hub flag (name or hub_id), falling back to active_hub.
    pub fn resolve_hub(&self, flag: Option<&str>) -> Result<(&str, &HubConnection), String> {
        let name = match flag {
            Some(f) => {
                // Try by name first
                if self.hub_connections.contains_key(f) {
                    f.to_string()
                } else {
                    // Try by hub_id
                    self.hub_connections.iter()
                        .find(|(_, v)| v.hub_id == f)
                        .map(|(k, _)| k.clone())
                        .ok_or_else(|| format!("hub connection {:?} not found\n  Run: treeship hub ls", f))?
                }
            }
            None => {
                self.active_hub.clone()
                    .ok_or_else(|| "no active hub connection\n  Run: treeship hub attach".to_string())?
            }
        };

        let entry = self.hub_connections.get(name.as_str())
            .ok_or_else(|| format!("hub connection {:?} not found in config", name))?;

        // SAFETY: name exists in self.hub_connections, so we can get a &str with the same lifetime
        let name_ref = self.hub_connections.get_key_value(name.as_str()).unwrap().0.as_str();
        Ok((name_ref, entry))
    }
}

// -- Errors -------------------------------------------------------------------

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

// -- Load / Save / Migrate ----------------------------------------------------

/// Resolve the config-file path, honoring `TREESHIP_CONFIG` first.
///
/// Order of precedence (highest first):
///   1. The `--config <path>` CLI flag (handled by the caller).
///   2. The `TREESHIP_CONFIG` environment variable.
///   3. `~/.treeship/config.json`.
///
/// The env-var hook exists so SDK consumers and CI runners can target an
/// isolated keystore without forcing every SDK to add a per-call config
/// option. Setting `TREESHIP_CONFIG=/tmp/scratch/config.json` then invoking
/// `treeship` from any caller (TS SDK, Python SDK, raw shell) is sufficient
/// to redirect every read and write into the scratch directory.
///
/// **Security model.** This env var is caller convenience, not a security
/// boundary. Treeship has no privileged execution context: every CLI
/// invocation runs as the local user, the keystore is owner-only files at
/// `~/.treeship/keys/`, and an attacker who can set environment variables
/// for the treeship process can already read or replace the user's
/// keystore directly. There is no setuid binary, no system service, and
/// no installed hook that escalates privilege. The env var widens the
/// caller's options for choosing WHICH user-owned keystore to use; it
/// does not give a caller access to a keystore they couldn't already
/// touch. Don't add owner-checks or symlink-resolution rejection here
/// without first explaining what privilege boundary they would defend.
pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    if let Some(env) = std::env::var_os("TREESHIP_CONFIG") {
        // Empty string is interpreted as "unset" -- avoids a footgun where a
        // shell exports `TREESHIP_CONFIG=` and silently retargets every
        // CLI invocation at the working directory.
        if !env.is_empty() {
            return Ok(PathBuf::from(env));
        }
    }
    let home = home::home_dir().ok_or(ConfigError::NoHome)?;
    Ok(home.join(".treeship").join("config.json"))
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::NotFound(path.to_path_buf()));
    }
    let bytes = fs::read(path)?;
    let mut cfg: Config = serde_json::from_slice(&bytes)?;

    // Auto-migrate v0.1/v0.2 hub config to v0.4 hub_connections format.
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

/// Migrate v0.1/v0.2 flat `hub` config to v0.4 `hub_connections` map.
/// Returns true if migration occurred.
fn migrate_legacy_hub(cfg: &mut Config) -> bool {
    let hub = match cfg.hub.take() {
        Some(h) => h,
        None => return false,
    };

    // Only migrate if hub_connections is empty (first run after upgrade).
    if !cfg.hub_connections.is_empty() {
        return false;
    }

    let status = hub.status.as_deref().unwrap_or("undocked");
    if status != "docked" {
        return true; // Clear the hub field but don't create a hub connection entry
    }

    let hub_id  = match hub.dock_id {
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

    cfg.hub_connections.insert("default".to_string(), HubConnection {
        hub_id,
        key_id:          cfg.default_key_id.clone(),
        endpoint,
        created_at:      now,
        last_push:       None,
        hub_public_key: hub.dock_public_key,
        hub_secret_key: hub.dock_secret_key,
    });
    cfg.active_hub = Some("default".to_string());

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
        hub_connections: HashMap::new(),
        active_hub:     None,
        hub:            None,
    }
}
