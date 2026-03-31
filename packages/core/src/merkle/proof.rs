use serde::{Deserialize, Serialize};

use super::checkpoint::Checkpoint;
use super::tree::InclusionProof;

// Re-export Direction and ProofStep from tree module for convenience.
pub use super::tree::{Direction, ProofStep};

/// A self-contained proof file that can be exported and verified offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofFile {
    pub artifact_id: String,
    pub artifact_summary: ArtifactSummary,
    pub inclusion_proof: InclusionProof,
    pub checkpoint: Checkpoint,
}

/// Summary of the artifact being proved (human-readable context).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub actor: String,
    pub action: String,
    pub timestamp: String,
    pub key_id: String,
}
