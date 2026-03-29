use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Config structs -- deserialized from .treeship/config.yaml
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProjectConfig {
    pub treeship: TreeshipMeta,
    pub session: SessionConfig,
    pub attest: AttestConfig,
    #[serde(default)]
    pub approvals: Option<ApprovalConfig>,
    #[serde(default)]
    pub hub: Option<HubConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TreeshipMeta {
    pub version: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    pub actor: String,
    #[serde(default)]
    pub auto_start: bool,
    #[serde(default)]
    pub auto_checkpoint: bool,
    #[serde(default)]
    pub auto_push: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestConfig {
    #[serde(default)]
    pub commands: Vec<CommandRule>,
    #[serde(default)]
    pub paths: Vec<PathRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandRule {
    pub pattern: String,
    pub label: String,
    #[serde(default)]
    pub require_approval: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathRule {
    pub path: String,
    pub on: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub alert: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalConfig {
    #[serde(default)]
    pub require_for: Vec<LabelRef>,
    #[serde(default)]
    pub auto_approve: Vec<LabelRef>,
    #[serde(default)]
    pub timeout: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LabelRef {
    pub label: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HubConfig {
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub auto_push: bool,
    #[serde(default)]
    pub push_on: Vec<String>,
}

// ---------------------------------------------------------------------------
// Match result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub should_attest: bool,
    pub label: String,
    pub require_approval: bool,
}

// ---------------------------------------------------------------------------
// Simple wildcard matching
// ---------------------------------------------------------------------------

/// Match a value against a simple wildcard pattern.
///
/// Supports three forms:
///   "prefix*"  -- value must start with prefix
///   "*suffix"  -- value must end with suffix
///   "exact"    -- value must equal the pattern exactly
fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern.ends_with('*') && !pattern.starts_with('*') {
        // prefix match
        let prefix = &pattern[..pattern.len() - 1];
        value.starts_with(prefix)
    } else if pattern.starts_with('*') && !pattern.ends_with('*') {
        // suffix match
        let suffix = &pattern[1..];
        value.ends_with(suffix)
    } else if pattern.starts_with('*') && pattern.ends_with('*') {
        // contains match (both ends have wildcard)
        let inner = &pattern[1..pattern.len() - 1];
        value.contains(inner)
    } else {
        // exact match
        pattern == value
    }
}

// ---------------------------------------------------------------------------
// ProjectConfig implementation
// ---------------------------------------------------------------------------

impl ProjectConfig {
    /// Load from a YAML file path.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file {}: {}", path.display(), e))?;
        Self::from_yaml(&contents)
    }

    /// Parse from a YAML string (useful for tests and embedding).
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("failed to parse YAML config: {}", e))
    }

    /// Generate a sensible default config for a given project type.
    ///
    /// Supported project types: "node", "rust", "python", "general".
    pub fn default_for(project_type: &str, actor: &str) -> Self {
        let test_commands: Vec<CommandRule> = match project_type {
            "node" => vec![
                CommandRule { pattern: "npm test*".into(), label: "test suite".into(), require_approval: false },
                CommandRule { pattern: "npx jest*".into(), label: "test suite".into(), require_approval: false },
            ],
            "rust" => vec![
                CommandRule { pattern: "cargo test*".into(), label: "test suite".into(), require_approval: false },
                CommandRule { pattern: "cargo clippy*".into(), label: "lint".into(), require_approval: false },
            ],
            "python" => vec![
                CommandRule { pattern: "pytest*".into(), label: "test suite".into(), require_approval: false },
                CommandRule { pattern: "python -m pytest*".into(), label: "test suite".into(), require_approval: false },
            ],
            _ => vec![],
        };

        let mut commands = test_commands;
        // Common commands for every project type
        commands.extend(vec![
            CommandRule { pattern: "git commit*".into(), label: "code commit".into(), require_approval: false },
            CommandRule { pattern: "git push*".into(), label: "code push".into(), require_approval: false },
            CommandRule { pattern: "kubectl apply*".into(), label: "deployment".into(), require_approval: true },
            CommandRule { pattern: "fly deploy*".into(), label: "deployment".into(), require_approval: true },
        ]);

        let paths = vec![
            PathRule { path: "src/**".into(), on: "write".into(), label: None, alert: false },
            PathRule { path: "*lock*".into(), on: "change".into(), label: Some("dependency change".into()), alert: false },
            PathRule { path: "*.env*".into(), on: "access".into(), label: Some("env file access".into()), alert: true },
        ];

        let approvals = ApprovalConfig {
            require_for: vec![LabelRef { label: "deployment".into() }],
            auto_approve: vec![
                LabelRef { label: "test suite".into() },
                LabelRef { label: "code commit".into() },
            ],
            timeout: Some("5m".into()),
        };

        ProjectConfig {
            treeship: TreeshipMeta { version: 1 },
            session: SessionConfig {
                actor: actor.to_string(),
                auto_start: true,
                auto_checkpoint: true,
                auto_push: false,
            },
            attest: AttestConfig { commands, paths },
            approvals: Some(approvals),
            hub: None,
        }
    }

    /// Match a command string against the configured rules.
    ///
    /// Returns `Some(MatchResult)` when the command matches a rule,
    /// `None` when no rule matches.
    pub fn match_command(&self, command: &str) -> Option<MatchResult> {
        for rule in &self.attest.commands {
            if wildcard_match(&rule.pattern, command) {
                let mut require_approval = rule.require_approval;

                // Check approval overrides
                if let Some(ref approvals) = self.approvals {
                    // If the label is in require_for, force approval required
                    if approvals.require_for.iter().any(|r| r.label == rule.label) {
                        require_approval = true;
                    }
                    // If the label is in auto_approve, override to false
                    if approvals.auto_approve.iter().any(|r| r.label == rule.label) {
                        require_approval = false;
                    }
                }

                return Some(MatchResult {
                    should_attest: true,
                    label: rule.label.clone(),
                    require_approval,
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r#"
treeship:
  version: 1

session:
  actor: agent://test-coder
  auto_start: true
  auto_checkpoint: true

attest:
  commands:
    - pattern: "npm test*"
      label: test suite
    - pattern: "cargo test*"
      label: test suite
    - pattern: "git commit*"
      label: code commit
    - pattern: "git push*"
      label: code push
    - pattern: "kubectl apply*"
      label: deployment
      require_approval: true
    - pattern: "fly deploy*"
      label: deployment
      require_approval: true
    - pattern: "stripe*"
      label: payment
      require_approval: true
  paths:
    - path: "src/**"
      on: write
    - path: "*lock*"
      on: change
      label: dependency change
    - path: "*.env*"
      on: access
      label: env file access
      alert: true

approvals:
  require_for:
    - label: deployment
    - label: payment
  auto_approve:
    - label: test suite
    - label: code commit
  timeout: 5m

hub:
  endpoint: https://api.treeship.dev
  auto_push: true
  push_on:
    - session_close
    - approval_required
"#;

    fn load_sample() -> ProjectConfig {
        ProjectConfig::from_yaml(SAMPLE_YAML).expect("sample YAML should parse")
    }

    #[test]
    fn test_load_from_yaml_string() {
        let cfg = load_sample();
        assert_eq!(cfg.treeship.version, 1);
        assert_eq!(cfg.session.actor, "agent://test-coder");
        assert!(cfg.session.auto_start);
        assert_eq!(cfg.attest.commands.len(), 7);
        assert_eq!(cfg.attest.paths.len(), 3);
        assert!(cfg.approvals.is_some());
        assert!(cfg.hub.is_some());
    }

    #[test]
    fn test_command_match_prefix_wildcard() {
        let cfg = load_sample();
        let m = cfg.match_command("npm test").expect("should match");
        assert_eq!(m.label, "test suite");
        assert!(m.should_attest);
    }

    #[test]
    fn test_command_match_prefix_wildcard_with_args() {
        let cfg = load_sample();
        let m = cfg.match_command("npm test --coverage").expect("should match");
        assert_eq!(m.label, "test suite");
        assert!(m.should_attest);
    }

    #[test]
    fn test_command_match_cargo_test() {
        let cfg = load_sample();
        let m = cfg.match_command("cargo test -p treeship-core").expect("should match");
        assert_eq!(m.label, "test suite");
    }

    #[test]
    fn test_no_match_returns_none() {
        let cfg = load_sample();
        assert!(cfg.match_command("echo hello").is_none());
        assert!(cfg.match_command("ls -la").is_none());
        assert!(cfg.match_command("").is_none());
    }

    #[test]
    fn test_require_approval_from_rule() {
        let cfg = load_sample();
        let m = cfg.match_command("kubectl apply -f deploy.yaml").expect("should match");
        assert_eq!(m.label, "deployment");
        assert!(m.require_approval);
    }

    #[test]
    fn test_auto_approve_overrides_require() {
        // "test suite" is in both require_for (it's not, actually) and
        // auto_approve. Since it's in auto_approve, require_approval should
        // be false even though the rule itself does not set it.
        let cfg = load_sample();
        let m = cfg.match_command("npm test").expect("should match");
        assert!(!m.require_approval, "test suite is auto-approved");
    }

    #[test]
    fn test_require_for_forces_approval() {
        // "payment" label is in require_for. Even though the rule already
        // has require_approval: true, the approval config confirms it.
        let cfg = load_sample();
        let m = cfg.match_command("stripe charge create").expect("should match");
        assert_eq!(m.label, "payment");
        assert!(m.require_approval);
    }

    #[test]
    fn test_auto_approve_beats_require_for() {
        // Build a config where a label appears in both require_for AND
        // auto_approve. auto_approve should win (it's checked second).
        let yaml = r#"
treeship:
  version: 1
session:
  actor: agent://test
attest:
  commands:
    - pattern: "deploy*"
      label: ops
approvals:
  require_for:
    - label: ops
  auto_approve:
    - label: ops
"#;
        let cfg = ProjectConfig::from_yaml(yaml).unwrap();
        let m = cfg.match_command("deploy production").unwrap();
        assert!(!m.require_approval, "auto_approve should override require_for");
    }

    #[test]
    fn test_no_approvals_section() {
        let yaml = r#"
treeship:
  version: 1
session:
  actor: agent://test
attest:
  commands:
    - pattern: "npm test*"
      label: test suite
"#;
        let cfg = ProjectConfig::from_yaml(yaml).unwrap();
        let m = cfg.match_command("npm test").unwrap();
        assert!(!m.require_approval);
    }

    #[test]
    fn test_missing_optional_fields() {
        // Minimal config -- no hub, no approvals, no paths
        let yaml = r#"
treeship:
  version: 1
session:
  actor: agent://minimal
attest:
  commands: []
"#;
        let cfg = ProjectConfig::from_yaml(yaml).unwrap();
        assert!(cfg.hub.is_none());
        assert!(cfg.approvals.is_none());
        assert!(cfg.attest.paths.is_empty());
        assert!(cfg.attest.commands.is_empty());
    }

    #[test]
    fn test_default_for_node() {
        let cfg = ProjectConfig::default_for("node", "agent://my-coder");
        assert_eq!(cfg.treeship.version, 1);
        assert_eq!(cfg.session.actor, "agent://my-coder");
        assert!(cfg.session.auto_start);

        // Should have npm test pattern
        let m = cfg.match_command("npm test --watch").expect("should match npm test");
        assert_eq!(m.label, "test suite");
        assert!(!m.require_approval, "tests are auto-approved by default");

        // Should have deployment rules
        let m = cfg.match_command("kubectl apply -f x.yaml").expect("should match kubectl");
        assert!(m.require_approval);
    }

    #[test]
    fn test_default_for_rust() {
        let cfg = ProjectConfig::default_for("rust", "agent://builder");
        let m = cfg.match_command("cargo test -p core").expect("should match cargo test");
        assert_eq!(m.label, "test suite");
    }

    #[test]
    fn test_default_for_python() {
        let cfg = ProjectConfig::default_for("python", "agent://py");
        let m = cfg.match_command("pytest -v").expect("should match pytest");
        assert_eq!(m.label, "test suite");
    }

    #[test]
    fn test_default_for_general() {
        let cfg = ProjectConfig::default_for("general", "agent://dev");
        // General has no test commands but still has git/deploy rules
        let m = cfg.match_command("git commit -m 'init'").expect("should match git commit");
        assert_eq!(m.label, "code commit");
    }

    #[test]
    fn test_wildcard_suffix_match() {
        // Test suffix matching with * at the start
        let yaml = r#"
treeship:
  version: 1
session:
  actor: agent://test
attest:
  commands:
    - pattern: "*.rs"
      label: rust file
"#;
        let cfg = ProjectConfig::from_yaml(yaml).unwrap();
        let m = cfg.match_command("compile main.rs").unwrap();
        assert_eq!(m.label, "rust file");
        assert!(cfg.match_command("main.py").is_none());
    }

    #[test]
    fn test_wildcard_exact_match() {
        let yaml = r#"
treeship:
  version: 1
session:
  actor: agent://test
attest:
  commands:
    - pattern: "make"
      label: build
"#;
        let cfg = ProjectConfig::from_yaml(yaml).unwrap();
        assert!(cfg.match_command("make").is_some());
        assert!(cfg.match_command("make install").is_none());
        assert!(cfg.match_command("cmake").is_none());
    }

    #[test]
    fn test_first_matching_rule_wins() {
        let yaml = r#"
treeship:
  version: 1
session:
  actor: agent://test
attest:
  commands:
    - pattern: "npm test*"
      label: test suite
    - pattern: "npm*"
      label: npm command
"#;
        let cfg = ProjectConfig::from_yaml(yaml).unwrap();
        let m = cfg.match_command("npm test --ci").unwrap();
        assert_eq!(m.label, "test suite", "first matching rule should win");
    }

    #[test]
    fn test_hub_config_fields() {
        let cfg = load_sample();
        let hub = cfg.hub.as_ref().unwrap();
        assert_eq!(hub.endpoint.as_deref(), Some("https://api.treeship.dev"));
        assert!(hub.auto_push);
        assert_eq!(hub.push_on, vec!["session_close", "approval_required"]);
    }

    #[test]
    fn test_path_rules_parsed() {
        let cfg = load_sample();
        assert_eq!(cfg.attest.paths.len(), 3);
        let env_rule = &cfg.attest.paths[2];
        assert_eq!(env_rule.path, "*.env*");
        assert_eq!(env_rule.on, "access");
        assert!(env_rule.alert);
        assert_eq!(env_rule.label.as_deref(), Some("env file access"));
    }
}
