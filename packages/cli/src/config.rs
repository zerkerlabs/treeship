use std::{collections::{HashMap, HashSet}, fs, path::{Path, PathBuf}};
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

/// Where the resolved config path came from. Surfaced by `doctor` so users
/// debugging "wrong config" can see which lookup tier won.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// Caller passed `--config <path>`.
    Explicit,
    /// `TREESHIP_CONFIG` environment variable.
    Env,
    /// `.treeship/config.json` discovered by walking up from cwd. Picked over
    /// the global config so that a user inside a project workspace can keep a
    /// project-local keystore even when their home `~/.treeship` is broken.
    ProjectLocal,
    /// Fallback: `~/.treeship/config.json`.
    Global,
}

impl ConfigSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Explicit     => "explicit (--config)",
            Self::Env          => "env (TREESHIP_CONFIG)",
            Self::ProjectLocal => "project-local",
            Self::Global       => "global",
        }
    }
}

/// Resolve the config-file path, honoring `TREESHIP_CONFIG` first.
///
/// Order of precedence (highest first):
///   1. The `--config <path>` CLI flag (handled by the caller).
///   2. The `TREESHIP_CONFIG` environment variable.
///   3. `.treeship/config.json` discovered by walking up from cwd.
///   4. `~/.treeship/config.json`.
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
    Ok(resolve_config_path()?.0)
}

/// Returns ONLY the global config path (`~/.treeship/config.json`),
/// ignoring any project-local `.treeship/config.json` in the cwd
/// chain.
///
/// Use this when you specifically need the user-level config — most
/// notably from `init`'s project-stub writer, which would otherwise
/// resolve `default_config_path()` to the project stub it is about to
/// create and produce a self-referencing `extends:` value.
pub fn global_config_path() -> Result<PathBuf, ConfigError> {
    if let Some(env) = std::env::var_os("TREESHIP_CONFIG") {
        if !env.is_empty() {
            return Ok(PathBuf::from(env));
        }
    }
    let home = home::home_dir().ok_or(ConfigError::NoHome)?;
    Ok(home.join(".treeship").join("config.json"))
}

/// Like `default_config_path` but also returns where the path came from.
/// `doctor` uses the source label to explain unexpected resolution.
pub fn resolve_config_path() -> Result<(PathBuf, ConfigSource), ConfigError> {
    if let Some(env) = std::env::var_os("TREESHIP_CONFIG") {
        if !env.is_empty() {
            return Ok((PathBuf::from(env), ConfigSource::Env));
        }
    }

    let home = home::home_dir().ok_or(ConfigError::NoHome)?;
    let global_path = home.join(".treeship").join("config.json");

    if let Ok(cwd) = std::env::current_dir() {
        if let Some(found) = walk_up_for_project_config(&cwd, &global_path, |p| p.is_file()) {
            return Ok((found, ConfigSource::ProjectLocal));
        }
    }

    Ok((global_path, ConfigSource::Global))
}

/// Walk up from `start`, returning the first `.treeship/config.json` that
/// passes `exists` and is not the global config. Pure so unit tests can drive
/// it without chdir'ing.
///
/// Skipping `global_path` is what keeps `~/.treeship/config.json` from being
/// labelled project-local for a user running from `$HOME` -- a real footgun
/// because the keystore would then claim project-local provenance even though
/// it's the same global config.
fn walk_up_for_project_config<F: Fn(&Path) -> bool>(
    start: &Path,
    global_path: &Path,
    exists: F,
) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        let candidate = dir.join(".treeship").join("config.json");
        if exists(&candidate) && candidate != global_path {
            return Some(candidate);
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn fake_exists(present: &[&str]) -> impl Fn(&Path) -> bool {
        let set: HashSet<PathBuf> = present.iter().map(PathBuf::from).collect();
        move |p: &Path| set.contains(p)
    }

    #[test]
    fn walk_up_finds_nearest_project_config() {
        // /home/u/work/proj/sub  →  finds /home/u/work/proj/.treeship/config.json
        let global = PathBuf::from("/home/u/.treeship/config.json");
        let found = walk_up_for_project_config(
            Path::new("/home/u/work/proj/sub"),
            &global,
            fake_exists(&["/home/u/work/proj/.treeship/config.json"]),
        );
        assert_eq!(found, Some(PathBuf::from("/home/u/work/proj/.treeship/config.json")));
    }

    #[test]
    fn walk_up_skips_when_only_match_is_global() {
        // Running from a subdir of $HOME with no project config -- the only
        // match in the walk is $HOME/.treeship/config.json itself, which is
        // the global. Must NOT label that as project-local.
        let global = PathBuf::from("/home/u/.treeship/config.json");
        let found = walk_up_for_project_config(
            Path::new("/home/u/Documents"),
            &global,
            fake_exists(&["/home/u/.treeship/config.json"]),
        );
        assert_eq!(found, None);
    }

    #[test]
    fn walk_up_returns_none_when_nothing_matches() {
        let global = PathBuf::from("/home/u/.treeship/config.json");
        let found = walk_up_for_project_config(
            Path::new("/home/u/work/proj"),
            &global,
            fake_exists(&[]),
        );
        assert_eq!(found, None);
    }

    #[test]
    fn walk_up_prefers_nearest_over_ancestor() {
        // Both /a/b/.treeship/config.json and /a/.treeship/config.json exist
        // -- prefer the nearest.
        let global = PathBuf::from("/home/u/.treeship/config.json");
        let found = walk_up_for_project_config(
            Path::new("/a/b/c"),
            &global,
            fake_exists(&[
                "/a/b/.treeship/config.json",
                "/a/.treeship/config.json",
            ]),
        );
        assert_eq!(found, Some(PathBuf::from("/a/b/.treeship/config.json")));
    }

    // --- extends-chain handling (PR 5.B) ------------------------------------

    fn write_real_config(dir: &Path, ship_id: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join("config.json");
        let json = serde_json::json!({
            "ship_id":        ship_id,
            "name":           null,
            "storage_dir":    dir.join("artifacts").to_string_lossy(),
            "keys_dir":       dir.join("keys").to_string_lossy(),
            "default_key_id": "key_test",
            "hub_connections": {},
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        path
    }

    fn write_stub(dir: &Path, extends_path: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join("config.json");
        let json = serde_json::json!({
            "extends": extends_path.to_string_lossy(),
            "project": true,
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        path
    }

    fn temp_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut b = [0u8; 8];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut b);
        p.push(format!("treeship-cfgtest-{}", hex::encode(b)));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn extends_resolves_parent_ship_id() {
        let root = temp_dir();
        let parent_dir = root.join("global");
        let parent = write_real_config(&parent_dir, "ship_parent_xyz");

        let project_dir = root.join("project");
        let stub = write_stub(&project_dir, &parent);

        let cfg = load(&stub).expect("stub with extends should resolve");
        assert_eq!(cfg.ship_id, "ship_parent_xyz");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn extends_self_reference_caught_by_cycle_detection() {
        let root = temp_dir();
        let project_dir = root.join("project");
        std::fs::create_dir_all(&project_dir).unwrap();
        let stub = project_dir.join("config.json");
        // Self-reference: extends path == own path.
        std::fs::write(
            &stub,
            serde_json::to_vec_pretty(&serde_json::json!({
                "extends": stub.to_string_lossy(),
                "project": true,
            }))
            .unwrap(),
        )
        .unwrap();

        let err = load(&stub).expect_err("self-referential stub must error");
        let msg = err.to_string();
        assert!(
            msg.contains("cycle") || msg.contains("loops back"),
            "expected cycle error, got: {msg}",
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn extends_chain_too_deep_caught() {
        let root = temp_dir();
        // Build a chain longer than EXTENDS_MAX_DEPTH.
        let mut paths: Vec<PathBuf> = Vec::new();
        // Innermost: a real Config so the chain has a proper terminal.
        let real_dir = root.join("real");
        let real = write_real_config(&real_dir, "ship_terminal");
        paths.push(real);

        for i in 0..(EXTENDS_MAX_DEPTH as usize + 2) {
            let dir = root.join(format!("stub-{}", i));
            let stub = write_stub(&dir, paths.last().unwrap());
            paths.push(stub);
        }

        let outermost = paths.last().unwrap();
        let err = load(outermost).expect_err("over-deep chain must error");
        assert!(err.to_string().contains("chain exceeded"));

        std::fs::remove_dir_all(&root).ok();
    }

    // --- global_config_path (PR 5.C) ----------------------------------------

    #[test]
    fn global_config_path_ignores_project_local_walk() {
        // Even when cwd has a project-local stub, global_config_path
        // must return the user-level path. The test relies on the
        // function ignoring cwd entirely; we don't actually need to
        // chdir to confirm that.
        let p = global_config_path().expect("home should be resolvable in CI");
        assert!(
            p.ends_with(".treeship/config.json"),
            "expected ~/.treeship/config.json, got {}",
            p.display(),
        );
    }
}

/// Maximum depth of `extends:` chain. Caught separately from the
/// visited-set cycle check: a chain of distinct paths longer than this
/// is almost certainly a misconfiguration rather than legitimate use.
const EXTENDS_MAX_DEPTH: u8 = 5;

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let mut visited: HashSet<PathBuf> = HashSet::new();
    load_with_depth(path, 0, &mut visited)
}

fn load_with_depth(
    path: &Path,
    depth: u8,
    visited: &mut HashSet<PathBuf>,
) -> Result<Config, ConfigError> {
    if depth > EXTENDS_MAX_DEPTH {
        return Err(ConfigError::Json(serde_json::Error::io(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "config `extends:` chain exceeded {} levels at {}",
                    EXTENDS_MAX_DEPTH,
                    path.display(),
                ),
            ),
        )));
    }
    if !path.exists() {
        return Err(ConfigError::NotFound(path.to_path_buf()));
    }

    // Canonicalize to detect cycles even when paths are written with
    // different shapes (relative vs absolute, /Users/... vs ~/, etc.).
    // Falls back to the as-given path on canonicalize failure -- the
    // visited check still works against either shape consistently.
    let canon = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canon.clone()) {
        return Err(ConfigError::Json(serde_json::Error::io(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "config `extends:` cycle: {} extends a file that loops back to it. \
                     Edit the file and remove the self-reference, or run `treeship init --force` \
                     in a directory that should be project-local.",
                    canon.display(),
                ),
            ),
        )));
    }

    let bytes = fs::read(path)?;

    // Project-local stub configs use the shape:
    //   {"extends": "/abs/or/relative/path", "project": true, "<override>": ...}
    // We resolve that by loading the parent first, then layering this
    // file's other fields on top. The keystore and storage stay where
    // the parent points unless the project explicitly overrides them.
    //
    // Detect the stub by parsing as a generic Value first -- the full
    // Config deserializer requires ship_id, which is absent in stubs.
    let raw: serde_json::Value = serde_json::from_slice(&bytes)?;
    if let Some(extends_value) = raw.get("extends") {
        let extends_path = extends_value
            .as_str()
            .ok_or_else(|| ConfigError::Json(serde_json::Error::io(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "config `extends` must be a string path",
                ),
            )))?;
        let parent_path = resolve_extends(path, extends_path);
        let mut cfg = load_with_depth(&parent_path, depth + 1, visited)?;
        apply_overrides(&mut cfg, &raw);

        if migrate_legacy_hub(&mut cfg) {
            // Don't write back into the project stub; only the parent.
            let _ = save(&cfg, &parent_path);
        }
        return Ok(cfg);
    }

    let mut cfg: Config = serde_json::from_slice(&bytes)?;
    if migrate_legacy_hub(&mut cfg) {
        let _ = save(&cfg, path);
    }
    Ok(cfg)
}

/// Resolve an `extends` path. Absolute paths are returned as-is;
/// relative paths are joined against the *directory* containing the
/// referring config so `{"extends": "../base.json"}` works the way an
/// editor user expects.
fn resolve_extends(referrer: &Path, extends: &str) -> PathBuf {
    let p = Path::new(extends);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        referrer
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(p)
    }
}

/// Layer non-empty / non-default fields from the project stub onto the
/// resolved parent. Today only `name` is overridable from a stub; the
/// keystore-pointing fields (`storage_dir`, `keys_dir`,
/// `default_key_id`) intentionally stay with the parent so two
/// projects sharing a parent don't accidentally fork keystores.
fn apply_overrides(cfg: &mut Config, raw: &serde_json::Value) {
    if let Some(name) = raw.get("name").and_then(|v| v.as_str()) {
        if !name.is_empty() {
            cfg.name = Some(name.to_string());
        }
    }
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
