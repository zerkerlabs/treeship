//! Render configuration for Explorer Session Reports.
//!
//! Lightweight hints embedded in the .treeship package that tell
//! Explorer how to present the session receipt visually.

use serde::{Deserialize, Serialize};

/// Render configuration for the session report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RenderConfig {
    /// Display title for the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Theme name (e.g., "default", "dark", "minimal").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,

    /// Which sections to render and in what order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<RenderSection>,

    /// Whether to generate a preview.html in the package.
    #[serde(default = "default_true")]
    pub generate_preview: bool,
}

fn default_true() -> bool { true }

/// A section in the rendered report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderSection {
    /// Section identifier.
    pub id: String,

    /// Human-readable section label.
    pub label: String,

    /// Whether this section is visible by default.
    #[serde(default = "default_true")]
    pub visible: bool,
}

impl RenderConfig {
    /// Default sections matching the spec's Explorer UX.
    pub fn default_sections() -> Vec<RenderSection> {
        vec![
            RenderSection { id: "summary".into(), label: "Session Summary".into(), visible: true },
            RenderSection { id: "participants".into(), label: "Participant Strip".into(), visible: true },
            RenderSection { id: "agent_graph".into(), label: "Delegation & Collaboration Graph".into(), visible: true },
            RenderSection { id: "timeline".into(), label: "Mission Timeline".into(), visible: true },
            RenderSection { id: "side_effects".into(), label: "Side-Effect Ledger".into(), visible: true },
            RenderSection { id: "proofs".into(), label: "Proofs Panel".into(), visible: true },
        ]
    }
}
