/// Template registry -- embedded YAML templates that ship with the binary.
///
/// Templates are loaded at compile time via `include_str!()`.
/// No runtime file access required. Works offline.

pub struct Template {
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub yaml: &'static str,
}

static TEMPLATES: &[Template] = &[
    Template {
        name: "github-contributor",
        description: "Commit and test provenance for OSS contributors",
        category: "Development",
        yaml: include_str!("github_contributor.yaml"),
    },
    Template {
        name: "ci-cd-pipeline",
        description: "Software delivery: test -> build -> deploy chain",
        category: "Development",
        yaml: include_str!("ci_cd_pipeline.yaml"),
    },
    Template {
        name: "research-agent",
        description: "Multi-step research with source provenance",
        category: "Development",
        yaml: include_str!("research_agent.yaml"),
    },
    Template {
        name: "mcp-agent",
        description: "MCP tool call attestation (one import change)",
        category: "Development",
        yaml: include_str!("mcp_agent.yaml"),
    },
    Template {
        name: "claude-code-session",
        description: "Full AI coding session audit trail",
        category: "Development",
        yaml: include_str!("claude_code_session.yaml"),
    },
    Template {
        name: "openclaw-agent",
        description: "OpenClaw workflow attestation",
        category: "Development",
        yaml: include_str!("openclaw_agent.yaml"),
    },
];

/// List all available templates.
pub fn list() -> &'static [Template] {
    TEMPLATES
}

/// Look up a template by name (slug).
pub fn get(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name == name)
}

/// Group templates by category, returning (category, templates) pairs
/// in the order categories first appear.
pub fn by_category() -> Vec<(&'static str, Vec<&'static Template>)> {
    let mut categories: Vec<(&'static str, Vec<&'static Template>)> = Vec::new();
    for t in TEMPLATES {
        if let Some(group) = categories.iter_mut().find(|(c, _)| *c == t.category) {
            group.1.push(t);
        } else {
            categories.push((t.category, vec![t]));
        }
    }
    categories
}
