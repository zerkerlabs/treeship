//! Receipt category taxonomy for boundary/consequence/internal classification.
//!
//! Addresses the insight from Moltbook builder echo_0i (715 karma):
//! "Split receipts into boundary receipts (handoff truth) and consequence
//! receipts (what changed because of that handoff). Most incidents aren't
//! failure-to-call; they're failure-to-bound-impact."
//!
//! This module adds a `category` field to ActionStatement so that receipts
//! can be classified at creation time and verified for completeness later.

use serde::{Deserialize, Serialize};

/// The trust-impact category of an action receipt.
///
/// - **Boundary**: The action crosses a trust boundary — calls external
///   systems, hands off to another agent, modifies shared state, or requires
///   human approval. These are the receipts that *must* be verified because
///   they affect trust domains outside the current agent.
///
/// - **Consequence**: The action is a downstream effect of a boundary crossing.
///   File writes after a deploy, database updates after an API call, test
///   results after a build. These prove that the boundary crossing actually
///   had the intended effect.
///
/// - **Internal**: Agent-internal operations — reasoning, planning, loading
///   context, self-checks. Useful for debugging and session reconstruction
///   but not part of the trust-critical chain.
///
/// Default is `Boundary` for safety — if the user doesn't specify, we assume
/// the action is trust-relevant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptCategory {
    #[default]
    Boundary,
    Consequence,
    Internal,
}

impl ReceiptCategory {
    /// Human-readable description for CLI output.
    pub fn description(&self) -> &'static str {
        match self {
            ReceiptCategory::Boundary => "trust boundary crossing",
            ReceiptCategory::Consequence => "downstream effect",
            ReceiptCategory::Internal => "internal operation",
        }
    }

    /// Whether this category is part of the trust-critical chain.
    pub fn is_trust_critical(&self) -> bool {
        matches!(self, ReceiptCategory::Boundary | ReceiptCategory::Consequence)
    }

    /// Parse from a CLI string argument.
    pub fn from_cli(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "boundary" | "b" => Some(ReceiptCategory::Boundary),
            "consequence" | "c" | "effect" | "downstream" => Some(ReceiptCategory::Consequence),
            "internal" | "i" | "debug" => Some(ReceiptCategory::Internal),
            _ => None,
        }
    }
}

impl std::fmt::Display for ReceiptCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptCategory::Boundary => write!(f, "boundary"),
            ReceiptCategory::Consequence => write!(f, "consequence"),
            ReceiptCategory::Internal => write!(f, "internal"),
        }
    }
}

/// A report of missing consequences for boundary actions.
///
/// Produced by verify logic to flag when a boundary receipt lacks
/// corresponding consequence receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingConsequenceReport {
    /// The boundary artifact that lacks consequences.
    pub boundary_artifact_id: String,
    /// The action label of the boundary artifact.
    pub boundary_action: String,
    /// Expected consequence types (heuristic or policy-based).
    pub expected_consequences: Vec<String>,
    /// Whether the omission is considered a failure.
    pub is_failure: bool,
}

/// Verify check result for category-aware verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryVerifyCheck {
    pub check_name: String,
    pub passed: bool,
    pub message: String,
    pub boundary_count: usize,
    pub consequence_count: usize,
    pub internal_count: usize,
    pub missing_consequences: Vec<MissingConsequenceReport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_default_is_boundary() {
        let cat: ReceiptCategory = Default::default();
        assert_eq!(cat, ReceiptCategory::Boundary);
        assert!(cat.is_trust_critical());
    }

    #[test]
    fn category_from_cli() {
        assert_eq!(ReceiptCategory::from_cli("boundary"), Some(ReceiptCategory::Boundary));
        assert_eq!(ReceiptCategory::from_cli("b"), Some(ReceiptCategory::Boundary));
        assert_eq!(ReceiptCategory::from_cli("consequence"), Some(ReceiptCategory::Consequence));
        assert_eq!(ReceiptCategory::from_cli("c"), Some(ReceiptCategory::Consequence));
        assert_eq!(ReceiptCategory::from_cli("internal"), Some(ReceiptCategory::Internal));
        assert_eq!(ReceiptCategory::from_cli("i"), Some(ReceiptCategory::Internal));
        assert_eq!(ReceiptCategory::from_cli("unknown"), None);
    }

    #[test]
    fn category_display() {
        assert_eq!(ReceiptCategory::Boundary.to_string(), "boundary");
        assert_eq!(ReceiptCategory::Consequence.to_string(), "consequence");
        assert_eq!(ReceiptCategory::Internal.to_string(), "internal");
    }

    #[test]
    fn category_serialization() {
        let cat = ReceiptCategory::Boundary;
        let json = serde_json::to_string(&cat).unwrap();
        assert_eq!(json, "\"boundary\"");

        let decoded: ReceiptCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, ReceiptCategory::Boundary);
    }

    #[test]
    fn internal_is_not_trust_critical() {
        assert!(!ReceiptCategory::Internal.is_trust_critical());
    }
}
