//! Pure workflow conformance reduction.
//!
//! This module does not verify signatures, checkpoints, or trust roots. It
//! consumes observations whose provenance has already been graded by the
//! verifier and compares them with a validated `workflow.v1` declaration.
//! Keeping that boundary explicit prevents a runtime's self-reported edge from
//! becoming "checked" merely because it reached this reducer.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::attestation::{Envelope, Verifier};
use crate::merkle::{
    verify_consistency, Checkpoint, CheckpointVerifyOutcome, MerkleTree, ProofFile,
};
use crate::statements::{action_in_scope, payload_type, ActionStatement, ReceiptStatement};
use crate::trust::TrustRootStore;

/// Minimal signed authorization graph for workflow conformance v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDeclaration {
    pub kind: String,
    pub schema_version: String,
    pub workflow_id: String,
    pub authority: String,
    pub entry_node: String,
    pub terminal_nodes: Vec<String>,
    pub nodes: Vec<WorkflowNode>,
    pub edges: Vec<WorkflowEdge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loops: Vec<WorkflowLoop>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNode {
    pub id: String,
    pub executor: ExecutorConstraint,
    pub allowed_tools: Vec<String>,
}

/// Exactly one field must be present. Validation rejects neither or both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorConstraint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEdge {
    pub from: String,
    pub to: String,
    pub when: EdgeCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeCondition {
    Always,
    OnPass,
    OnFail,
    OnRefused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLoop {
    pub id: String,
    pub back_edge: EdgeRef,
    pub max_iterations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<WorkflowBudget>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeRef {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_actions: Option<u32>,
}

/// Provenance accepted by the reducer. `Checked` is strongest and `Asserted`
/// weakest. Aggregates always inherit the weakest required evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGrade {
    Checked,
    Captured,
    Asserted,
}

impl EvidenceGrade {
    fn weakest(self, other: Self) -> Self {
        use EvidenceGrade::{Asserted, Captured, Checked};
        match (self, other) {
            (Asserted, _) | (_, Asserted) => Asserted,
            (Captured, _) | (_, Captured) => Captured,
            (Checked, Checked) => Checked,
        }
    }
}

/// Normalized, already-verified input for one workflow run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedWorkflowRun {
    pub run_id: String,
    pub status: WorkflowRunStatus,
    pub workflow_ref: String,
    pub pre_existence: PreExistenceEvidence,
    pub attempts: Vec<ObservedNodeAttempt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowRunStatus {
    Completed,
    Incomplete,
    Failed,
    Abandoned,
}

/// The upstream verifier's result for declaration ordering. The reducer checks
/// that a `checked` grade carries the required basis, but does not re-verify
/// checkpoint signatures or consistency proofs itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreExistenceEvidence {
    pub grade: EvidenceGrade,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration_checkpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration_tree_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_run_leaf_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration_signed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_run_signed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedNodeAttempt {
    pub node_id: String,
    pub iteration: u32,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    pub outcome: NodeOutcome,
    pub grade: EvidenceGrade,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Verified signed action artifact references attributed to this attempt.
    /// Loop action budgets count these references, never tool labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action_evidence: Vec<String>,
    /// Optional precise receipt references per tool. When absent, a finding
    /// references all evidence for the attempt rather than inventing a tighter
    /// binding than the input supports.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tool_evidence: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeOutcome {
    Completed,
    Pass,
    Fail,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowConformanceReport {
    pub run_id: String,
    pub workflow_ref: String,
    pub pre_existence: PreExistenceReport,
    pub path: PathReport,
    pub authority: WorkflowAuthorityReport,
    pub loops: Vec<LoopReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreExistenceReport {
    pub grade: EvidenceGrade,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathReport {
    pub grade: EvidenceGrade,
    pub deviations: Vec<PathDeviation>,
    pub gaps: Vec<PathGap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asserted_edges: Vec<ObservedEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathDeviation {
    pub from: String,
    pub to: String,
    pub reason: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathGap {
    pub node_id: String,
    pub reason: String,
    pub after: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedEdge {
    pub from: String,
    pub to: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowAuthorityReport {
    pub grade: EvidenceGrade,
    pub deviations: Vec<AuthorityDeviation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDeviation {
    pub node_id: String,
    pub kind: String,
    pub value: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopReport {
    pub id: String,
    pub grade: EvidenceGrade,
    pub iterations: u32,
    pub max_iterations: u32,
    pub limit_exceeded: bool,
    pub budget_exceeded: bool,
}

/// Real Merkle evidence that the workflow declaration was in an earlier tree
/// prefix than the first run artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPreExistenceProof {
    pub declaration: ProofFile,
    pub first_run: ProofFile,
    pub consistency_proof: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowPreExistenceError {
    ArtifactMismatch {
        expected: String,
        actual: String,
    },
    CheckpointNotTrusted {
        which: String,
        detail: String,
    },
    LogIdentityMismatch {
        declaration_signer: String,
        first_run_signer: String,
    },
    VersionMismatch {
        declaration: u8,
        first_run: u8,
    },
    InvalidRoot {
        which: String,
    },
    InvalidInclusion {
        which: String,
    },
    InvalidOrder {
        detail: String,
    },
    InvalidConsistency,
}

impl fmt::Display for WorkflowPreExistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactMismatch { expected, actual } => {
                write!(f, "proof artifact mismatch: expected {expected}, got {actual}")
            }
            Self::CheckpointNotTrusted { which, detail } => {
                write!(f, "{which} checkpoint is not trusted: {detail}")
            }
            Self::LogIdentityMismatch {
                declaration_signer,
                first_run_signer,
            } => write!(
                f,
                "checkpoints belong to different log identities: declaration signer {declaration_signer}, first run signer {first_run_signer}"
            ),
            Self::VersionMismatch {
                declaration,
                first_run,
            } => write!(
                f,
                "checkpoint merkle versions differ: declaration v{declaration}, first run v{first_run}"
            ),
            Self::InvalidRoot { which } => {
                write!(f, "{which} checkpoint root is not sha256:<hex>")
            }
            Self::InvalidInclusion { which } => {
                write!(f, "{which} artifact inclusion proof is invalid")
            }
            Self::InvalidOrder { detail } => write!(f, "invalid workflow/run order: {detail}"),
            Self::InvalidConsistency => write!(
                f,
                "later checkpoint does not cryptographically extend the declaration checkpoint"
            ),
        }
    }
}

impl std::error::Error for WorkflowPreExistenceError {}

/// Failure to establish that the first signed run artifact selected a specific
/// workflow declaration. This is separate from checkpoint ordering: inclusion
/// proves when two artifacts entered a log, while this check proves the run
/// itself names the declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowRunBindingError {
    Signature(String),
    ArtifactMismatch { expected: String, actual: String },
    WrongPayloadType { actual: String },
    InvalidAction(String),
    NotSessionStart { actual: String },
    MissingWorkflowRef,
    WorkflowMismatch { expected: String, actual: String },
}

impl fmt::Display for WorkflowRunBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature(detail) => write!(f, "first run signature is not trusted: {detail}"),
            Self::ArtifactMismatch { expected, actual } => write!(
                f,
                "first run artifact mismatch: expected {expected}, verified {actual}"
            ),
            Self::WrongPayloadType { actual } => write!(
                f,
                "first run artifact has payload type `{actual}`, expected `{}`",
                payload_type("action")
            ),
            Self::InvalidAction(detail) => {
                write!(f, "first run artifact is not an action statement: {detail}")
            }
            Self::NotSessionStart { actual } => write!(
                f,
                "first run action is `{actual}`, expected `session.start`"
            ),
            Self::MissingWorkflowRef => {
                write!(
                    f,
                    "first run session.start action has no workflow_ref binding"
                )
            }
            Self::WorkflowMismatch { expected, actual } => write!(
                f,
                "first run workflow mismatch: expected {expected}, action binds {actual}"
            ),
        }
    }
}

impl std::error::Error for WorkflowRunBindingError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowValidationError {
    pub field: String,
    pub detail: String,
}

impl fmt::Display for WorkflowValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.detail)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowConformanceError {
    InvalidDeclaration(Vec<WorkflowValidationError>),
    InvalidRun(String),
}

impl fmt::Display for WorkflowConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeclaration(errors) => write!(
                f,
                "invalid workflow declaration: {}",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::InvalidRun(detail) => write!(f, "invalid observed workflow run: {detail}"),
        }
    }
}

impl std::error::Error for WorkflowConformanceError {}

impl WorkflowDeclaration {
    pub fn validate(&self) -> Result<(), Vec<WorkflowValidationError>> {
        let mut errors = Vec::new();
        if self.kind != "workflow.v1" {
            invalid(&mut errors, "kind", "must be workflow.v1");
        }
        if self.schema_version != "1" {
            invalid(&mut errors, "schema_version", "must be 1");
        }
        if self.workflow_id.trim().is_empty() {
            invalid(&mut errors, "workflow_id", "must not be empty");
        }
        if self.authority.trim().is_empty() {
            invalid(&mut errors, "authority", "must not be empty");
        }
        if self.nodes.is_empty() {
            invalid(&mut errors, "nodes", "must contain at least one node");
        }

        let mut node_ids = BTreeSet::new();
        for (index, node) in self.nodes.iter().enumerate() {
            if node.id.trim().is_empty() {
                invalid(
                    &mut errors,
                    &format!("nodes[{index}].id"),
                    "must not be empty",
                );
            } else if !node_ids.insert(node.id.clone()) {
                invalid(
                    &mut errors,
                    &format!("nodes[{index}].id"),
                    "duplicates an earlier node id",
                );
            }
            if node.executor.actor.is_some() == node.executor.capability.is_some() {
                invalid(
                    &mut errors,
                    &format!("nodes[{index}].executor"),
                    "must contain exactly one of actor or capability",
                );
            }
            if node
                .executor
                .actor
                .as_deref()
                .is_some_and(|actor| actor.trim().is_empty())
                || node
                    .executor
                    .capability
                    .as_deref()
                    .is_some_and(|capability| capability.trim().is_empty())
            {
                invalid(
                    &mut errors,
                    &format!("nodes[{index}].executor"),
                    "actor or capability must not be empty",
                );
            }
            let mut tools = BTreeSet::new();
            for tool in &node.allowed_tools {
                if tool.trim().is_empty() {
                    invalid(
                        &mut errors,
                        &format!("nodes[{index}].allowed_tools"),
                        "must not contain an empty tool",
                    );
                } else if !tools.insert(tool) {
                    invalid(
                        &mut errors,
                        &format!("nodes[{index}].allowed_tools"),
                        &format!("contains duplicate tool {tool}"),
                    );
                }
            }
        }

        if !node_ids.contains(&self.entry_node) {
            invalid(&mut errors, "entry_node", "must name a declared node");
        }
        if self.terminal_nodes.is_empty() {
            invalid(
                &mut errors,
                "terminal_nodes",
                "must contain at least one terminal",
            );
        }
        let mut terminals = BTreeSet::new();
        for terminal in &self.terminal_nodes {
            if !node_ids.contains(terminal) {
                invalid(
                    &mut errors,
                    "terminal_nodes",
                    &format!("unknown node {terminal}"),
                );
            }
            if !terminals.insert(terminal) {
                invalid(
                    &mut errors,
                    "terminal_nodes",
                    &format!("duplicate terminal {terminal}"),
                );
            }
        }

        let mut edge_keys = BTreeSet::new();
        for (index, edge) in self.edges.iter().enumerate() {
            if !node_ids.contains(&edge.from) {
                invalid(
                    &mut errors,
                    &format!("edges[{index}].from"),
                    "must name a declared node",
                );
            }
            if !node_ids.contains(&edge.to) {
                invalid(
                    &mut errors,
                    &format!("edges[{index}].to"),
                    "must name a declared node",
                );
            }
            if !edge_keys.insert((edge.from.clone(), edge.to.clone(), edge.when)) {
                invalid(
                    &mut errors,
                    &format!("edges[{index}]"),
                    "duplicates an earlier edge and condition",
                );
            }
        }

        let declared_edge_refs: BTreeSet<EdgeRef> = self
            .edges
            .iter()
            .map(|edge| EdgeRef {
                from: edge.from.clone(),
                to: edge.to.clone(),
            })
            .collect();
        let mut loop_ids = BTreeSet::new();
        let mut loop_edges = BTreeSet::new();
        for (index, workflow_loop) in self.loops.iter().enumerate() {
            if workflow_loop.id.trim().is_empty() {
                invalid(
                    &mut errors,
                    &format!("loops[{index}].id"),
                    "must not be empty",
                );
            } else if !loop_ids.insert(workflow_loop.id.clone()) {
                invalid(
                    &mut errors,
                    &format!("loops[{index}].id"),
                    "duplicates an earlier loop id",
                );
            }
            if !declared_edge_refs.contains(&workflow_loop.back_edge) {
                invalid(
                    &mut errors,
                    &format!("loops[{index}].back_edge"),
                    "must reference a declared edge",
                );
            }
            if self
                .edges
                .iter()
                .filter(|edge| {
                    edge.from == workflow_loop.back_edge.from
                        && edge.to == workflow_loop.back_edge.to
                })
                .count()
                > 1
            {
                invalid(
                    &mut errors,
                    &format!("loops[{index}].back_edge"),
                    "is ambiguous because multiple conditions use this edge",
                );
            }
            if !loop_edges.insert(workflow_loop.back_edge.clone()) {
                invalid(
                    &mut errors,
                    &format!("loops[{index}].back_edge"),
                    "is already claimed by another loop",
                );
            }
            if workflow_loop.max_iterations == 0 {
                invalid(
                    &mut errors,
                    &format!("loops[{index}].max_iterations"),
                    "must be greater than zero",
                );
            }
            if matches!(
                workflow_loop.budget.as_ref().and_then(|b| b.max_actions),
                Some(0)
            ) {
                invalid(
                    &mut errors,
                    &format!("loops[{index}].budget.max_actions"),
                    "must be greater than zero",
                );
            }
        }

        for (index, workflow_loop) in self.loops.iter().enumerate() {
            if !edge_closes_cycle(
                &workflow_loop.back_edge,
                &node_ids,
                &self.edges,
                &loop_edges,
            ) {
                invalid(
                    &mut errors,
                    &format!("loops[{index}].back_edge"),
                    "must close a path through non-loop edges",
                );
            }
        }
        if contains_unbounded_cycle(&node_ids, &self.edges, &loop_edges) {
            invalid(
                &mut errors,
                "edges",
                "contains a cycle not declared as a bounded loop back edge",
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Verify that a trusted, signed `session.start` action is the claimed first
/// run artifact and binds that run to `expected_workflow_ref`.
///
/// The workflow reference lives inside `ActionStatement::meta`, which is part
/// of the DSSE payload. Mutating it changes the PAE digest and invalidates the
/// signature. This function deliberately requires the caller's verifier rather
/// than treating the envelope's key id as trust by itself.
pub fn verify_first_run_workflow_binding(
    expected_workflow_ref: &str,
    expected_first_run_artifact: &str,
    envelope: &Envelope,
    verifier: &Verifier,
) -> Result<(), WorkflowRunBindingError> {
    let verified = verifier
        .verify(envelope)
        .map_err(|e| WorkflowRunBindingError::Signature(e.to_string()))?;
    if verified.artifact_id != expected_first_run_artifact {
        return Err(WorkflowRunBindingError::ArtifactMismatch {
            expected: expected_first_run_artifact.to_string(),
            actual: verified.artifact_id,
        });
    }

    let expected_payload_type = payload_type("action");
    if verified.payload_type != expected_payload_type {
        return Err(WorkflowRunBindingError::WrongPayloadType {
            actual: verified.payload_type,
        });
    }

    let action: ActionStatement = envelope
        .unmarshal_statement()
        .map_err(|e| WorkflowRunBindingError::InvalidAction(e.to_string()))?;
    if action.action != "session.start" {
        return Err(WorkflowRunBindingError::NotSessionStart {
            actual: action.action,
        });
    }
    let actual_workflow_ref = action
        .meta
        .as_ref()
        .and_then(|meta| meta.get("workflow_ref"))
        .and_then(serde_json::Value::as_str)
        .ok_or(WorkflowRunBindingError::MissingWorkflowRef)?;
    if actual_workflow_ref != expected_workflow_ref {
        return Err(WorkflowRunBindingError::WorkflowMismatch {
            expected: expected_workflow_ref.to_string(),
            actual: actual_workflow_ref.to_string(),
        });
    }

    Ok(())
}

/// Verify that a workflow declaration was committed to the same append-only
/// log before the first run artifact.
///
/// This checks both checkpoint signatures against the caller's trust roots,
/// both inclusion proofs, leaf ordering, and the consistency proof joining the
/// checkpoints. It does not verify the declaration or run artifact envelopes;
/// callers must do that separately before treating their contents as signed.
pub fn verify_workflow_pre_existence(
    proof: &WorkflowPreExistenceProof,
    expected_workflow_ref: &str,
    expected_first_run_artifact: &str,
    trust: &TrustRootStore,
) -> Result<PreExistenceEvidence, WorkflowPreExistenceError> {
    require_artifact_id(expected_workflow_ref, &proof.declaration.artifact_id)?;
    require_artifact_id(expected_first_run_artifact, &proof.first_run.artifact_id)?;

    verify_checkpoint("declaration", &proof.declaration.checkpoint, trust)?;
    verify_checkpoint("first run", &proof.first_run.checkpoint, trust)?;

    let declaration_checkpoint = &proof.declaration.checkpoint;
    let run_checkpoint = &proof.first_run.checkpoint;
    if declaration_checkpoint.public_key != run_checkpoint.public_key {
        return Err(WorkflowPreExistenceError::LogIdentityMismatch {
            declaration_signer: declaration_checkpoint.signer.clone(),
            first_run_signer: run_checkpoint.signer.clone(),
        });
    }
    if declaration_checkpoint.merkle_version != run_checkpoint.merkle_version {
        return Err(WorkflowPreExistenceError::VersionMismatch {
            declaration: declaration_checkpoint.merkle_version,
            first_run: run_checkpoint.merkle_version,
        });
    }

    let declaration_root = checkpoint_root_hex("declaration", declaration_checkpoint)?;
    let run_root = checkpoint_root_hex("first run", run_checkpoint)?;

    if !MerkleTree::verify_proof_at_size(
        declaration_checkpoint.merkle_version,
        declaration_root,
        &proof.declaration.artifact_id,
        &proof.declaration.inclusion_proof,
        declaration_checkpoint.tree_size,
    ) {
        return Err(WorkflowPreExistenceError::InvalidInclusion {
            which: "declaration".into(),
        });
    }
    if !MerkleTree::verify_proof_at_size(
        run_checkpoint.merkle_version,
        run_root,
        &proof.first_run.artifact_id,
        &proof.first_run.inclusion_proof,
        run_checkpoint.tree_size,
    ) {
        return Err(WorkflowPreExistenceError::InvalidInclusion {
            which: "first run".into(),
        });
    }

    if declaration_checkpoint.tree_size >= run_checkpoint.tree_size {
        return Err(WorkflowPreExistenceError::InvalidOrder {
            detail: format!(
                "declaration tree size {} is not earlier than run tree size {}",
                declaration_checkpoint.tree_size, run_checkpoint.tree_size
            ),
        });
    }
    if proof.first_run.inclusion_proof.leaf_index < declaration_checkpoint.tree_size {
        return Err(WorkflowPreExistenceError::InvalidOrder {
            detail: format!(
                "first run leaf {} is inside the declaration checkpoint prefix of size {}",
                proof.first_run.inclusion_proof.leaf_index, declaration_checkpoint.tree_size
            ),
        });
    }
    if !verify_consistency(
        declaration_checkpoint.merkle_version,
        declaration_checkpoint.tree_size,
        declaration_root,
        run_checkpoint.tree_size,
        run_root,
        &proof.consistency_proof,
    ) {
        return Err(WorkflowPreExistenceError::InvalidConsistency);
    }

    Ok(PreExistenceEvidence {
        grade: EvidenceGrade::Checked,
        reason: None,
        declaration_checkpoint: Some(checkpoint_ref(declaration_checkpoint)),
        declaration_tree_size: Some(
            u64::try_from(declaration_checkpoint.tree_size)
                .expect("checkpoint tree size exceeds u64; please report a bug"),
        ),
        first_run_leaf_index: Some(
            u64::try_from(proof.first_run.inclusion_proof.leaf_index)
                .expect("leaf index exceeds u64; please report a bug"),
        ),
        consistency_to: Some(checkpoint_ref(run_checkpoint)),
        declaration_signed_at: Some(declaration_checkpoint.signed_at.clone()),
        first_run_signed_at: Some(run_checkpoint.signed_at.clone()),
    })
}

fn require_artifact_id(expected: &str, actual: &str) -> Result<(), WorkflowPreExistenceError> {
    if expected == actual {
        Ok(())
    } else {
        Err(WorkflowPreExistenceError::ArtifactMismatch {
            expected: expected.into(),
            actual: actual.into(),
        })
    }
}

fn verify_checkpoint(
    which: &str,
    checkpoint: &Checkpoint,
    trust: &TrustRootStore,
) -> Result<(), WorkflowPreExistenceError> {
    match checkpoint.verify_detailed(trust) {
        CheckpointVerifyOutcome::Valid => Ok(()),
        CheckpointVerifyOutcome::SignerNotPinned { .. } => {
            Err(WorkflowPreExistenceError::CheckpointNotTrusted {
                which: which.into(),
                detail: "signer is not pinned under hub_checkpoint".into(),
            })
        }
        CheckpointVerifyOutcome::Invalid { reason } => {
            Err(WorkflowPreExistenceError::CheckpointNotTrusted {
                which: which.into(),
                detail: reason,
            })
        }
    }
}

fn checkpoint_root_hex<'a>(
    which: &str,
    checkpoint: &'a Checkpoint,
) -> Result<&'a str, WorkflowPreExistenceError> {
    let Some(root) = checkpoint.root.strip_prefix("sha256:") else {
        return Err(WorkflowPreExistenceError::InvalidRoot {
            which: which.into(),
        });
    };
    if root.len() != 64 || hex::decode(root).is_err() {
        return Err(WorkflowPreExistenceError::InvalidRoot {
            which: which.into(),
        });
    }
    Ok(root)
}

fn checkpoint_ref(checkpoint: &Checkpoint) -> String {
    format!("{}:{}", checkpoint.signer, checkpoint.index)
}

/// Compare an already-verified observation set with a workflow declaration.
///
/// No cryptographic verification occurs here. In particular, callers must not
/// label `PreExistenceEvidence` or an attempt `checked` until the relevant
/// signatures, trust roots, and checkpoint proofs have been verified.
pub fn evaluate_workflow_conformance(
    declaration: &WorkflowDeclaration,
    run: &ObservedWorkflowRun,
) -> Result<WorkflowConformanceReport, WorkflowConformanceError> {
    declaration
        .validate()
        .map_err(WorkflowConformanceError::InvalidDeclaration)?;
    validate_run(run)?;

    let nodes: BTreeMap<&str, &WorkflowNode> = declaration
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();

    let mut path_grade = run.attempts[0].grade;
    for attempt in &run.attempts[1..] {
        path_grade = path_grade.weakest(attempt.grade);
    }

    let mut deviations = Vec::new();
    let mut gaps = Vec::new();
    let mut asserted_edges = Vec::new();

    if run.attempts[0].node_id != declaration.entry_node {
        gaps.push(PathGap {
            node_id: declaration.entry_node.clone(),
            reason: "missing_entry_node".into(),
            after: "run_start".into(),
            evidence: run.attempts[0].evidence.clone(),
        });
    }

    for (index, attempt) in run.attempts.iter().enumerate() {
        if !nodes.contains_key(attempt.node_id.as_str()) {
            deviations.push(PathDeviation {
                from: index
                    .checked_sub(1)
                    .map(|previous| run.attempts[previous].node_id.clone())
                    .unwrap_or_else(|| "run_start".into()),
                to: attempt.node_id.clone(),
                reason: "undeclared_node".into(),
                evidence: attempt.evidence.clone(),
            });
        }
    }

    for pair in run.attempts.windows(2) {
        let from = &pair[0];
        let to = &pair[1];
        let evidence = ordered_evidence(&from.evidence, &to.evidence);

        if !nodes.contains_key(from.node_id.as_str()) || !nodes.contains_key(to.node_id.as_str()) {
            continue;
        }

        let matching_pair: Vec<&WorkflowEdge> = declaration
            .edges
            .iter()
            .filter(|edge| edge.from == from.node_id && edge.to == to.node_id)
            .collect();
        let declared = matching_pair
            .iter()
            .any(|edge| condition_holds(edge.when, from.outcome));
        if !declared {
            deviations.push(PathDeviation {
                from: from.node_id.clone(),
                to: to.node_id.clone(),
                reason: if matching_pair.is_empty() {
                    "undeclared_edge".into()
                } else {
                    "edge_condition_not_met".into()
                },
                evidence: evidence.clone(),
            });
        }

        if from.grade.weakest(to.grade) == EvidenceGrade::Asserted {
            asserted_edges.push(ObservedEdge {
                from: from.node_id.clone(),
                to: to.node_id.clone(),
                evidence,
            });
        }
    }

    let last = run
        .attempts
        .last()
        .expect("validate_run rejects empty attempts; please report a bug");
    if run.status == WorkflowRunStatus::Completed
        && !declaration.terminal_nodes.contains(&last.node_id)
    {
        let expected = declaration
            .edges
            .iter()
            .find(|edge| edge.from == last.node_id && condition_holds(edge.when, last.outcome))
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| declaration.terminal_nodes[0].clone());
        gaps.push(PathGap {
            node_id: expected,
            reason: "completed_run_missing_required_terminal".into(),
            after: last.node_id.clone(),
            evidence: last.evidence.clone(),
        });
    }

    let authority = evaluate_authority(&nodes, &run.attempts, path_grade);
    let loops = declaration
        .loops
        .iter()
        .map(|workflow_loop| evaluate_loop(workflow_loop, &run.attempts, path_grade))
        .collect();

    Ok(WorkflowConformanceReport {
        run_id: run.run_id.clone(),
        workflow_ref: run.workflow_ref.clone(),
        pre_existence: PreExistenceReport {
            grade: run.pre_existence.grade,
            reason: run.pre_existence.reason.clone(),
        },
        path: PathReport {
            grade: path_grade,
            deviations,
            gaps,
            asserted_edges,
        },
        authority,
        loops,
    })
}

fn validate_run(run: &ObservedWorkflowRun) -> Result<(), WorkflowConformanceError> {
    if run.run_id.trim().is_empty() {
        return Err(WorkflowConformanceError::InvalidRun(
            "run_id must not be empty".into(),
        ));
    }
    if run.workflow_ref.trim().is_empty() {
        return Err(WorkflowConformanceError::InvalidRun(
            "workflow_ref must not be empty".into(),
        ));
    }
    if run.attempts.is_empty() {
        return Err(WorkflowConformanceError::InvalidRun(
            "at least one observed attempt is required".into(),
        ));
    }
    if let Some((index, _)) = run
        .attempts
        .iter()
        .enumerate()
        .find(|(_, attempt)| attempt.evidence.is_empty())
    {
        return Err(WorkflowConformanceError::InvalidRun(format!(
            "attempt {index} has no evidence"
        )));
    }
    for (index, attempt) in run.attempts.iter().enumerate() {
        let evidence: BTreeSet<&str> = attempt.evidence.iter().map(String::as_str).collect();
        let mut seen_actions = BTreeSet::new();
        for action in &attempt.action_evidence {
            if action.trim().is_empty() {
                return Err(WorkflowConformanceError::InvalidRun(format!(
                    "attempt {index} has an empty action evidence reference"
                )));
            }
            if !evidence.contains(action.as_str()) {
                return Err(WorkflowConformanceError::InvalidRun(format!(
                    "attempt {index} action evidence `{action}` is not present in its evidence set"
                )));
            }
            if !seen_actions.insert(action.as_str()) {
                return Err(WorkflowConformanceError::InvalidRun(format!(
                    "attempt {index} repeats action evidence `{action}`"
                )));
            }
        }
    }
    if run.pre_existence.grade == EvidenceGrade::Captured {
        return Err(WorkflowConformanceError::InvalidRun(
            "pre-existence grade must be checked or asserted; capture alone does not prove log order"
                .into(),
        ));
    }
    if run.pre_existence.grade == EvidenceGrade::Checked {
        let pre = &run.pre_existence;
        let (Some(tree_size), Some(first_leaf)) =
            (pre.declaration_tree_size, pre.first_run_leaf_index)
        else {
            return Err(WorkflowConformanceError::InvalidRun(
                "checked pre-existence requires declaration_tree_size and first_run_leaf_index"
                    .into(),
            ));
        };
        if pre.declaration_checkpoint.is_none() || pre.consistency_to.is_none() {
            return Err(WorkflowConformanceError::InvalidRun(
                "checked pre-existence requires declaration and consistency checkpoints".into(),
            ));
        }
        if first_leaf < tree_size {
            return Err(WorkflowConformanceError::InvalidRun(format!(
                "first run leaf index {first_leaf} precedes declaration checkpoint tree size {tree_size}"
            )));
        }
    }
    Ok(())
}

fn evaluate_authority(
    nodes: &BTreeMap<&str, &WorkflowNode>,
    attempts: &[ObservedNodeAttempt],
    grade: EvidenceGrade,
) -> WorkflowAuthorityReport {
    let mut deviations = Vec::new();
    for attempt in attempts {
        let Some(node) = nodes.get(attempt.node_id.as_str()) else {
            continue;
        };
        if let Some(expected_actor) = &node.executor.actor {
            if &attempt.actor != expected_actor {
                deviations.push(AuthorityDeviation {
                    node_id: attempt.node_id.clone(),
                    kind: "actor_mismatch".into(),
                    value: attempt.actor.clone(),
                    evidence: attempt.evidence.clone(),
                });
            }
        }
        if let Some(required_capability) = &node.executor.capability {
            if !attempt.capabilities.contains(required_capability) {
                deviations.push(AuthorityDeviation {
                    node_id: attempt.node_id.clone(),
                    kind: "capability_missing".into(),
                    value: required_capability.clone(),
                    evidence: attempt.evidence.clone(),
                });
            }
        }
        for tool in &attempt.tools {
            if !action_in_scope(tool, &node.allowed_tools) {
                deviations.push(AuthorityDeviation {
                    node_id: attempt.node_id.clone(),
                    kind: "tool_out_of_scope".into(),
                    value: tool.clone(),
                    evidence: attempt
                        .tool_evidence
                        .get(tool)
                        .cloned()
                        .unwrap_or_else(|| attempt.evidence.clone()),
                });
            }
        }
    }
    WorkflowAuthorityReport { grade, deviations }
}

fn evaluate_loop(
    workflow_loop: &WorkflowLoop,
    attempts: &[ObservedNodeAttempt],
    grade: EvidenceGrade,
) -> LoopReport {
    let traversals: Vec<usize> = attempts
        .windows(2)
        .enumerate()
        .filter_map(|(index, pair)| {
            (pair[0].node_id == workflow_loop.back_edge.from
                && pair[1].node_id == workflow_loop.back_edge.to)
                .then_some(index + 1)
        })
        .collect();
    let iterations =
        u32::try_from(traversals.len()).expect("attempt count exceeds u32; please report a bug");

    // V1's action budget covers retry work after the first back-edge. The
    // initial forward pass is not a loop iteration. This count comes from
    // verified signed action references, never tool labels or the adapter's
    // iteration field.
    let loop_actions = traversals
        .first()
        .map(|first_retry| {
            attempts[*first_retry..]
                .iter()
                .map(|attempt| attempt.action_evidence.len() as u64)
                .sum::<u64>()
        })
        .unwrap_or(0);
    let budget_exceeded = workflow_loop
        .budget
        .as_ref()
        .and_then(|budget| budget.max_actions)
        .is_some_and(|max| loop_actions > u64::from(max));

    LoopReport {
        id: workflow_loop.id.clone(),
        grade,
        iterations,
        max_iterations: workflow_loop.max_iterations,
        limit_exceeded: iterations > workflow_loop.max_iterations,
        budget_exceeded,
    }
}

fn edge_closes_cycle(
    back_edge: &EdgeRef,
    node_ids: &BTreeSet<String>,
    edges: &[WorkflowEdge],
    bounded_back_edges: &BTreeSet<EdgeRef>,
) -> bool {
    if !node_ids.contains(&back_edge.from) || !node_ids.contains(&back_edge.to) {
        return false;
    }
    let mut pending = vec![back_edge.to.as_str()];
    let mut visited = BTreeSet::new();
    while let Some(node) = pending.pop() {
        if node == back_edge.from {
            return true;
        }
        if !visited.insert(node) {
            continue;
        }
        for edge in edges.iter().filter(|edge| edge.from == node) {
            let edge_ref = EdgeRef {
                from: edge.from.clone(),
                to: edge.to.clone(),
            };
            if !bounded_back_edges.contains(&edge_ref) {
                pending.push(edge.to.as_str());
            }
        }
    }
    false
}

fn contains_unbounded_cycle(
    node_ids: &BTreeSet<String>,
    edges: &[WorkflowEdge],
    bounded_back_edges: &BTreeSet<EdgeRef>,
) -> bool {
    let mut indegree: BTreeMap<&str, usize> =
        node_ids.iter().map(|node| (node.as_str(), 0)).collect();
    let remaining_edges: Vec<&WorkflowEdge> = edges
        .iter()
        .filter(|edge| node_ids.contains(&edge.from) && node_ids.contains(&edge.to))
        .filter(|edge| {
            !bounded_back_edges.contains(&EdgeRef {
                from: edge.from.clone(),
                to: edge.to.clone(),
            })
        })
        .collect();

    for edge in &remaining_edges {
        if let Some(count) = indegree.get_mut(edge.to.as_str()) {
            *count += 1;
        }
    }
    let mut ready: Vec<&str> = indegree
        .iter()
        .filter_map(|(node, count)| (*count == 0).then_some(*node))
        .collect();
    let mut visited = 0usize;
    while let Some(node) = ready.pop() {
        visited += 1;
        for edge in remaining_edges.iter().filter(|edge| edge.from == node) {
            let count = indegree
                .get_mut(edge.to.as_str())
                .expect("validated edges name declared nodes; please report a bug");
            *count -= 1;
            if *count == 0 {
                ready.push(edge.to.as_str());
            }
        }
    }
    visited != node_ids.len()
}

fn condition_holds(condition: EdgeCondition, outcome: NodeOutcome) -> bool {
    match condition {
        EdgeCondition::Always => true,
        EdgeCondition::OnPass => outcome == NodeOutcome::Pass,
        EdgeCondition::OnFail => outcome == NodeOutcome::Fail,
        EdgeCondition::OnRefused => outcome == NodeOutcome::Refused,
    }
}

fn ordered_evidence(first: &[String], second: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    first
        .iter()
        .chain(second)
        .filter(|item| seen.insert((*item).clone()))
        .cloned()
        .collect()
}

fn invalid(errors: &mut Vec<WorkflowValidationError>, field: &str, detail: &str) {
    errors.push(WorkflowValidationError {
        field: field.into(),
        detail: detail.into(),
    });
}

/// Every way the composed workflow verification path can refuse before a
/// report exists. Each variant is a refusal, never a downgrade: the only
/// downgrade in this path is pre-existence, which becomes `asserted` when no
/// checkpoint proof is supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowRunVerifyError {
    /// The declaration envelope did not verify against the caller's verifier.
    DeclarationSignature(String),
    /// The declaration envelope is not a receipt.
    DeclarationWrongPayloadType { actual: String },
    /// The declaration envelope's statement did not parse.
    DeclarationMalformed(String),
    /// The receipt is signed, but it is not a `workflow.v1` declaration.
    DeclarationNotAWorkflow { actual: String },
    /// A `workflow.v1` receipt carried no payload to read a declaration from.
    DeclarationMissingPayload,
    /// The payload is not a well-formed declaration.
    InvalidDeclaration(Vec<WorkflowValidationError>),
    /// The observation set names a different workflow than the one signed.
    WorkflowRefMismatch { declaration: String, run: String },
    /// The first-run artifact did not verify, or does not bind this workflow.
    RunBinding(WorkflowRunBindingError),
    /// A pre-existence proof was supplied and did not hold.
    PreExistence(WorkflowPreExistenceError),
    /// The declaration and observations are individually sound, but the run
    /// itself is not reducible (vacuous or self-contradicting).
    Conformance(WorkflowConformanceError),
}

impl fmt::Display for WorkflowRunVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkflowRunVerifyError::DeclarationSignature(detail) => {
                write!(f, "workflow declaration did not verify: {detail}")
            }
            WorkflowRunVerifyError::DeclarationWrongPayloadType { actual } => write!(
                f,
                "workflow declaration has payload type `{actual}`, expected a receipt"
            ),
            WorkflowRunVerifyError::DeclarationMalformed(detail) => {
                write!(f, "workflow declaration statement is unreadable: {detail}")
            }
            WorkflowRunVerifyError::DeclarationNotAWorkflow { actual } => write!(
                f,
                "signed receipt is `{actual}`, not a workflow.v1 declaration"
            ),
            WorkflowRunVerifyError::DeclarationMissingPayload => {
                write!(f, "workflow.v1 receipt carries no declaration payload")
            }
            WorkflowRunVerifyError::InvalidDeclaration(errors) => {
                let detail = errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                write!(f, "workflow declaration is invalid: {detail}")
            }
            WorkflowRunVerifyError::WorkflowRefMismatch { declaration, run } => write!(
                f,
                "observation set names workflow `{run}`, but the signed declaration is `{declaration}`"
            ),
            WorkflowRunVerifyError::RunBinding(error) => {
                write!(f, "first-run binding failed: {error}")
            }
            WorkflowRunVerifyError::PreExistence(error) => {
                write!(f, "pre-existence proof failed: {error}")
            }
            WorkflowRunVerifyError::Conformance(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for WorkflowRunVerifyError {}

/// Verify one workflow run end to end and return its conformance report.
///
/// This is the fail-closed composition of the pieces above, and it exists so
/// that no caller has to remember the order. In particular it is the only
/// place that decides the `pre_existence` grade: whatever the observation set
/// claims is **discarded** and replaced with what the supplied evidence
/// actually proves. A hand-written run file that asserts `checked` therefore
/// reports `asserted`, which is the difference between a verifier and a
/// formatter.
///
/// The steps, each fatal:
///
/// 1. the declaration envelope verifies, is a receipt, and is `workflow.v1`;
/// 2. the declaration is structurally valid;
/// 3. the observation set names that same declaration;
/// 4. the first-run artifact verifies and its signed `session.start` binds
///    this workflow;
/// 5. when a proof is supplied, both checkpoints, both inclusion proofs, leaf
///    ordering, log identity, and the consistency proof hold.
///
/// Only then does the pure reducer run. Omitting the proof is allowed and
/// costs the run its `checked` pre-existence grade; it is never an error,
/// because an unproven ordering claim is a weaker report rather than a
/// malformed one.
pub fn verify_workflow_run(
    declaration_envelope: &Envelope,
    first_run_envelope: &Envelope,
    pre_existence_proof: Option<&WorkflowPreExistenceProof>,
    observed: &ObservedWorkflowRun,
    verifier: &Verifier,
    trust: &TrustRootStore,
) -> Result<WorkflowConformanceReport, WorkflowRunVerifyError> {
    let verified_declaration = verifier
        .verify(declaration_envelope)
        .map_err(|e| WorkflowRunVerifyError::DeclarationSignature(e.to_string()))?;

    let expected_receipt = payload_type("receipt");
    if verified_declaration.payload_type != expected_receipt {
        return Err(WorkflowRunVerifyError::DeclarationWrongPayloadType {
            actual: verified_declaration.payload_type,
        });
    }

    let receipt: ReceiptStatement = declaration_envelope
        .unmarshal_statement()
        .map_err(|e| WorkflowRunVerifyError::DeclarationMalformed(e.to_string()))?;
    if receipt.kind != "workflow.v1" {
        return Err(WorkflowRunVerifyError::DeclarationNotAWorkflow {
            actual: receipt.kind,
        });
    }
    let payload = receipt
        .payload
        .ok_or(WorkflowRunVerifyError::DeclarationMissingPayload)?;
    let declaration: WorkflowDeclaration = serde_json::from_value(payload)
        .map_err(|e| WorkflowRunVerifyError::DeclarationMalformed(e.to_string()))?;
    declaration
        .validate()
        .map_err(WorkflowRunVerifyError::InvalidDeclaration)?;

    // The workflow reference is the id of the artifact whose signature we just
    // checked, never a caller-supplied string.
    let workflow_ref = verified_declaration.artifact_id;
    if observed.workflow_ref != workflow_ref {
        return Err(WorkflowRunVerifyError::WorkflowRefMismatch {
            declaration: workflow_ref,
            run: observed.workflow_ref.clone(),
        });
    }

    // Same rule for the run: identify the first-run artifact by verifying it,
    // then require the inclusion proof to be about that same id.
    let first_run_artifact = verifier
        .verify(first_run_envelope)
        .map_err(|e| {
            WorkflowRunVerifyError::RunBinding(WorkflowRunBindingError::Signature(e.to_string()))
        })?
        .artifact_id;
    verify_first_run_workflow_binding(
        &workflow_ref,
        &first_run_artifact,
        first_run_envelope,
        verifier,
    )
    .map_err(WorkflowRunVerifyError::RunBinding)?;

    let pre_existence = match pre_existence_proof {
        Some(proof) => {
            verify_workflow_pre_existence(proof, &workflow_ref, &first_run_artifact, trust)
                .map_err(WorkflowRunVerifyError::PreExistence)?
        }
        None => PreExistenceEvidence {
            grade: EvidenceGrade::Asserted,
            reason: Some("no checkpoint proof supplied; declaration ordering is unproven".into()),
            declaration_checkpoint: None,
            declaration_tree_size: None,
            first_run_leaf_index: None,
            consistency_to: None,
            declaration_signed_at: None,
            first_run_signed_at: None,
        },
    };

    let mut run = observed.clone();
    run.pre_existence = pre_existence;

    evaluate_workflow_conformance(&declaration, &run).map_err(WorkflowRunVerifyError::Conformance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{sign, Ed25519Signer, Signer};
    use crate::merkle::ArtifactSummary;
    use crate::trust::{encode_ed25519_pubkey, TrustRoot, TrustRootKind};

    fn valid_declaration() -> WorkflowDeclaration {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/workflow-conformance/declaration.json"
        ))
        .expect("golden declaration parses")
    }

    fn real_pre_existence_proof() -> (WorkflowPreExistenceProof, TrustRootStore) {
        pre_existence_proof_for("art_workflow", "art_first_run")
    }

    /// Build real checkpoints, inclusion proofs, and a consistency proof over
    /// two concrete artifact ids, so a composed test can use the ids that were
    /// actually signed rather than fixture placeholders.
    fn pre_existence_proof_for(
        declaration_id: &str,
        first_run_id: &str,
    ) -> (WorkflowPreExistenceProof, TrustRootStore) {
        use ed25519_dalek::VerifyingKey;

        let signer = Ed25519Signer::generate("key_workflow_checkpoint")
            .expect("test signer generation succeeds");
        let public_key: [u8; 32] = signer
            .public_key_bytes()
            .try_into()
            .expect("Ed25519 public key is 32 bytes");
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).expect("test public key is valid");
        let trust = TrustRootStore::with_roots(vec![TrustRoot {
            key_id: signer.key_id().into(),
            public_key: encode_ed25519_pubkey(&verifying_key),
            kind: TrustRootKind::HubCheckpoint,
            label: "workflow test checkpoint".into(),
            added_at: "2026-08-17T00:00:00Z".into(),
        }]);

        let mut tree = MerkleTree::new();
        tree.append(declaration_id);
        let declaration_inclusion = tree
            .inclusion_proof(0)
            .expect("declaration inclusion proof exists");
        let declaration_checkpoint =
            Checkpoint::create(10, &tree, &signer).expect("declaration checkpoint signs");

        tree.append(first_run_id);
        let first_run_inclusion = tree
            .inclusion_proof(1)
            .expect("first-run inclusion proof exists");
        let first_run_checkpoint =
            Checkpoint::create(11, &tree, &signer).expect("run checkpoint signs");
        let consistency_proof = tree
            .consistency_proof(declaration_checkpoint.tree_size)
            .expect("consistency proof exists");

        let summary = |action: &str| ArtifactSummary {
            actor: "agent://claude-code".into(),
            action: action.into(),
            timestamp: "2026-08-17T00:00:00Z".into(),
            key_id: "key_agent".into(),
        };
        (
            WorkflowPreExistenceProof {
                declaration: ProofFile {
                    artifact_id: declaration_id.into(),
                    artifact_summary: summary("workflow.declare"),
                    inclusion_proof: declaration_inclusion,
                    checkpoint: declaration_checkpoint,
                },
                first_run: ProofFile {
                    artifact_id: first_run_id.into(),
                    artifact_summary: summary("workflow.start"),
                    inclusion_proof: first_run_inclusion,
                    checkpoint: first_run_checkpoint,
                },
                consistency_proof,
            },
            trust,
        )
    }

    fn signed_workflow_bound_run(workflow_ref: &str) -> (String, Envelope, Verifier) {
        let signer =
            Ed25519Signer::generate("key_workflow_run").expect("test signer generation succeeds");
        let mut action = ActionStatement::new("agent://claude-code", "session.start");
        action.meta = Some(serde_json::json!({
            "session_start": true,
            "workflow_ref": workflow_ref,
        }));
        let result =
            sign(&payload_type("action"), &action, &signer).expect("session start action signs");
        let verifier = Verifier::from_signer(&signer);
        (result.artifact_id, result.envelope, verifier)
    }

    #[test]
    fn signed_session_start_binds_first_run_to_workflow() {
        let workflow_ref = "art_0123456789abcdef0123456789abcdef";
        let (first_run_id, envelope, verifier) = signed_workflow_bound_run(workflow_ref);

        verify_first_run_workflow_binding(workflow_ref, &first_run_id, &envelope, &verifier)
            .expect("trusted session start binds the workflow inside signed bytes");
    }

    #[test]
    fn first_run_binding_rejects_substitution_and_untrusted_signer() {
        let workflow_ref = "art_0123456789abcdef0123456789abcdef";
        let (first_run_id, envelope, verifier) = signed_workflow_bound_run(workflow_ref);

        let substituted = verify_first_run_workflow_binding(
            "art_ffffffffffffffffffffffffffffffff",
            &first_run_id,
            &envelope,
            &verifier,
        )
        .expect_err("a run bound to one workflow cannot be relabeled as another");
        assert_eq!(
            substituted,
            WorkflowRunBindingError::WorkflowMismatch {
                expected: "art_ffffffffffffffffffffffffffffffff".into(),
                actual: workflow_ref.into(),
            }
        );

        let untrusted = verify_first_run_workflow_binding(
            workflow_ref,
            &first_run_id,
            &envelope,
            &Verifier::new(std::collections::HashMap::new()),
        )
        .expect_err("a key id in the envelope is not a verifier trust decision");
        assert!(matches!(untrusted, WorkflowRunBindingError::Signature(_)));
    }

    #[test]
    fn mutating_signed_first_run_workflow_ref_invalidates_binding() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let workflow_ref = "art_0123456789abcdef0123456789abcdef";
        let (first_run_id, mut envelope, verifier) = signed_workflow_bound_run(workflow_ref);
        let mut payload: serde_json::Value = envelope
            .unmarshal_statement()
            .expect("signed action payload is JSON");
        payload["meta"]["workflow_ref"] =
            serde_json::Value::String("art_ffffffffffffffffffffffffffffffff".into());
        envelope.payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).expect("test mutation serializes to JSON bytes"));

        let error =
            verify_first_run_workflow_binding(workflow_ref, &first_run_id, &envelope, &verifier)
                .expect_err("workflow_ref is inside signed PAE bytes and cannot be wire-edited");
        assert!(matches!(error, WorkflowRunBindingError::Signature(_)));
    }

    #[test]
    fn real_checkpoints_prove_declaration_pre_existed_first_run() {
        let (proof, trust) = real_pre_existence_proof();
        let evidence =
            verify_workflow_pre_existence(&proof, "art_workflow", "art_first_run", &trust)
                .expect("real inclusion, ordering, and consistency evidence passes");

        assert_eq!(evidence.grade, EvidenceGrade::Checked);
        assert_eq!(evidence.declaration_tree_size, Some(1));
        assert_eq!(evidence.first_run_leaf_index, Some(1));
    }

    #[test]
    fn pre_existence_rejects_checkpoints_from_different_trusted_logs() {
        let (mut proof, _) = real_pre_existence_proof();
        let second_signer = Ed25519Signer::generate("key_other_checkpoint")
            .expect("second checkpoint signer generation succeeds");
        let mut tree = MerkleTree::new();
        tree.append("art_workflow");
        tree.append("art_first_run");
        proof.first_run.checkpoint =
            Checkpoint::create(11, &tree, &second_signer).expect("second log checkpoint signs");

        let trust = TrustRootStore::with_roots(vec![
            TrustRoot {
                key_id: proof.declaration.checkpoint.signer.clone(),
                public_key: proof.declaration.checkpoint.public_key.clone(),
                kind: TrustRootKind::HubCheckpoint,
                label: "declaration log".into(),
                added_at: "2026-08-17T00:00:00Z".into(),
            },
            TrustRoot {
                key_id: proof.first_run.checkpoint.signer.clone(),
                public_key: proof.first_run.checkpoint.public_key.clone(),
                kind: TrustRootKind::HubCheckpoint,
                label: "unrelated run log".into(),
                added_at: "2026-08-17T00:00:00Z".into(),
            },
        ]);

        let error = verify_workflow_pre_existence(&proof, "art_workflow", "art_first_run", &trust)
            .expect_err("two trusted checkpoint keys do not establish one append-only log");
        assert_eq!(
            error,
            WorkflowPreExistenceError::LogIdentityMismatch {
                declaration_signer: proof.declaration.checkpoint.signer.clone(),
                first_run_signer: proof.first_run.checkpoint.signer.clone(),
            }
        );
    }

    #[test]
    fn pre_existence_fails_on_untrusted_or_inconsistent_evidence() {
        let (mut proof, trust) = real_pre_existence_proof();
        let untrusted = verify_workflow_pre_existence(
            &proof,
            "art_workflow",
            "art_first_run",
            &TrustRootStore::empty(),
        )
        .expect_err("self-signed unpinned checkpoints cannot prove ordering");
        assert!(matches!(
            untrusted,
            WorkflowPreExistenceError::CheckpointNotTrusted { .. }
        ));

        proof.consistency_proof[0].replace_range(0..2, "ff");
        let inconsistent =
            verify_workflow_pre_existence(&proof, "art_workflow", "art_first_run", &trust)
                .expect_err("tampered consistency evidence must fail");
        assert_eq!(inconsistent, WorkflowPreExistenceError::InvalidConsistency);
    }

    #[test]
    fn pre_existence_rejects_a_leaf_index_relabel() {
        let (mut proof, trust) = real_pre_existence_proof();
        proof.first_run.inclusion_proof.leaf_index = 0;

        let error = verify_workflow_pre_existence(&proof, "art_workflow", "art_first_run", &trust)
            .expect_err("a valid hash path cannot be relabeled to another leaf position");
        assert_eq!(
            error,
            WorkflowPreExistenceError::InvalidInclusion {
                which: "first run".into()
            }
        );
    }

    #[test]
    fn pre_existence_binds_both_expected_artifact_ids() {
        let (proof, trust) = real_pre_existence_proof();
        let error = verify_workflow_pre_existence(
            &proof,
            "art_different_workflow",
            "art_first_run",
            &trust,
        )
        .expect_err("a proof for another workflow cannot be substituted");
        assert!(matches!(
            error,
            WorkflowPreExistenceError::ArtifactMismatch { .. }
        ));
    }

    #[test]
    fn declaration_rejects_unknown_control_fields() {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/workflow-conformance/declaration.json"
        ))
        .expect("golden declaration parses as JSON");
        value["nodes"][0]["retry_policy"] = serde_json::json!({ "max": 99 });

        let error = serde_json::from_value::<WorkflowDeclaration>(value)
            .expect_err("an unchecked control field must not be silently ignored");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn declaration_rejects_vacuous_and_dangling_shapes() {
        let mut declaration = valid_declaration();
        declaration.nodes[0].executor.capability = Some("second.constraint".into());
        declaration.loops[0].max_iterations = 0;
        declaration.edges[0].to = "missing".into();

        let errors = declaration
            .validate()
            .expect_err("invalid shape is refused");
        assert!(errors.iter().any(|e| e.field == "nodes[0].executor"));
        assert!(errors.iter().any(|e| e.field == "edges[0].to"));
        assert!(errors.iter().any(|e| e.field == "loops[0].max_iterations"));
    }

    #[test]
    fn undeclared_cycles_are_refused_instead_of_becoming_unbounded_loops() {
        let mut declaration = valid_declaration();
        declaration.edges.push(WorkflowEdge {
            from: "finish".into(),
            to: "inspect".into(),
            when: EdgeCondition::Always,
        });

        let errors = declaration
            .validate()
            .expect_err("a cycle without a bounded loop declaration is refused");
        assert!(errors
            .iter()
            .any(|error| { error.field == "edges" && error.detail.contains("bounded loop") }));
    }

    #[test]
    fn a_loop_marker_must_name_an_edge_that_actually_closes_a_cycle() {
        let mut declaration = valid_declaration();
        declaration.loops[0].back_edge = EdgeRef {
            from: "inspect".into(),
            to: "change".into(),
        };

        let errors = declaration
            .validate()
            .expect_err("a forward edge cannot masquerade as a bounded back edge");
        assert!(errors.iter().any(|error| {
            error.field == "loops[0].back_edge" && error.detail.contains("close a path")
        }));
    }

    #[test]
    fn checked_pre_existence_requires_ordering_basis() {
        let run = ObservedWorkflowRun {
            run_id: "run".into(),
            status: WorkflowRunStatus::Completed,
            workflow_ref: "art_workflow".into(),
            pre_existence: PreExistenceEvidence {
                grade: EvidenceGrade::Checked,
                reason: None,
                declaration_checkpoint: None,
                declaration_tree_size: None,
                first_run_leaf_index: None,
                consistency_to: None,
                declaration_signed_at: None,
                first_run_signed_at: None,
            },
            attempts: vec![ObservedNodeAttempt {
                node_id: "inspect".into(),
                iteration: 0,
                actor: "agent://claude-code".into(),
                capabilities: vec![],
                tools: vec!["Read".into()],
                outcome: NodeOutcome::Completed,
                grade: EvidenceGrade::Checked,
                evidence: vec!["art_read".into()],
                action_evidence: vec!["art_read".into()],
                tool_evidence: BTreeMap::new(),
            }],
        };

        let error = evaluate_workflow_conformance(&valid_declaration(), &run)
            .expect_err("checked without checkpoint evidence is refused");
        assert!(matches!(error, WorkflowConformanceError::InvalidRun(_)));

        let mut captured = run;
        captured.pre_existence.grade = EvidenceGrade::Captured;
        let error = evaluate_workflow_conformance(&valid_declaration(), &captured)
            .expect_err("capture alone cannot prove declaration ordering");
        assert!(matches!(error, WorkflowConformanceError::InvalidRun(_)));
    }

    #[test]
    fn a_single_undeclared_attempt_is_a_path_deviation() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/workflow-conformance/valid.json"
        ))
        .expect("valid fixture parses as JSON");
        let mut run: ObservedWorkflowRun =
            serde_json::from_value(fixture["run"].clone()).expect("valid fixture run parses");
        run.status = WorkflowRunStatus::Incomplete;
        run.attempts.truncate(1);
        run.attempts[0].node_id = "undeclared".into();

        let report = evaluate_workflow_conformance(&valid_declaration(), &run)
            .expect("undeclared evidence produces a report rather than a parser error");
        assert_eq!(
            report.path.deviations,
            vec![PathDeviation {
                from: "run_start".into(),
                to: "undeclared".into(),
                reason: "undeclared_node".into(),
                evidence: vec!["art_inspect".into()],
            }]
        );
    }

    #[test]
    fn loop_action_budget_counts_signed_actions_not_tool_labels() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/workflow-conformance/loop-cap.json"
        ))
        .expect("loop fixture parses as JSON");
        let mut run: ObservedWorkflowRun =
            serde_json::from_value(fixture["run"].clone()).expect("loop fixture run parses");
        for attempt in &mut run.attempts[3..] {
            attempt.tools.clear();
            attempt.action_evidence.clear();
        }
        run.attempts[3]
            .evidence
            .extend(["art_retry_action_1".into(), "art_retry_action_2".into()]);
        run.attempts[3].action_evidence =
            vec!["art_retry_action_1".into(), "art_retry_action_2".into()];

        let mut declaration = valid_declaration();
        declaration.loops[0]
            .budget
            .as_mut()
            .expect("fixture loop has an action budget")
            .max_actions = Some(1);

        let report = evaluate_workflow_conformance(&declaration, &run)
            .expect("verified signed action references are valid loop evidence");
        assert!(
            report.loops[0].budget_exceeded,
            "two retry actions exceed one action even when no tool label is present"
        );
    }

    #[test]
    fn duplicate_or_unbound_action_evidence_is_rejected() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/workflow-conformance/valid.json"
        ))
        .expect("valid fixture parses as JSON");
        let mut run: ObservedWorkflowRun =
            serde_json::from_value(fixture["run"].clone()).expect("valid fixture run parses");
        run.attempts[0].action_evidence = vec!["art_missing".into()];
        let error = evaluate_workflow_conformance(&valid_declaration(), &run)
            .expect_err("an action reference outside the attempt evidence cannot affect a budget");
        assert!(matches!(error, WorkflowConformanceError::InvalidRun(_)));

        run.attempts[0].evidence.push("art_missing".into());
        run.attempts[0].action_evidence.push("art_missing".into());
        let error = evaluate_workflow_conformance(&valid_declaration(), &run)
            .expect_err("one signed action cannot be counted twice");
        assert!(matches!(error, WorkflowConformanceError::InvalidRun(_)));
    }

    #[test]
    fn empty_observation_set_never_passes_vacuously() {
        let run = ObservedWorkflowRun {
            run_id: "run".into(),
            status: WorkflowRunStatus::Completed,
            workflow_ref: "art_workflow".into(),
            pre_existence: PreExistenceEvidence {
                grade: EvidenceGrade::Asserted,
                reason: Some("no checkpoint".into()),
                declaration_checkpoint: None,
                declaration_tree_size: None,
                first_run_leaf_index: None,
                consistency_to: None,
                declaration_signed_at: None,
                first_run_signed_at: None,
            },
            attempts: vec![],
        };

        let error = evaluate_workflow_conformance(&valid_declaration(), &run)
            .expect_err("empty evidence cannot produce a clean report");
        assert!(matches!(error, WorkflowConformanceError::InvalidRun(_)));
    }

    // ---- composed fail-closed path (slice 2) ----

    fn observed_golden_run() -> ObservedWorkflowRun {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/workflow-conformance/valid.json"
        ))
        .expect("golden fixture parses");
        serde_json::from_value(fixture["run"].clone()).expect("golden observed run parses")
    }

    /// Sign a declaration as a `workflow.v1` receipt and return its real
    /// artifact id, envelope, and the authority signer.
    fn signed_declaration(declaration: &WorkflowDeclaration) -> (String, Envelope, Ed25519Signer) {
        let signer = Ed25519Signer::generate("key_workflow_authority")
            .expect("test signer generation succeeds");
        let mut receipt = ReceiptStatement::new("system://treeship-test", "workflow.v1");
        receipt.payload = Some(serde_json::to_value(declaration).expect("declaration serializes"));
        let result =
            sign(&payload_type("receipt"), &receipt, &signer).expect("workflow declaration signs");
        (result.artifact_id, result.envelope, signer)
    }

    fn verifier_over(signers: &[&Ed25519Signer]) -> Verifier {
        use ed25519_dalek::VerifyingKey;
        let mut verifier = Verifier::new(std::collections::HashMap::new());
        for signer in signers {
            let bytes: [u8; 32] = signer
                .public_key_bytes()
                .try_into()
                .expect("Ed25519 public key is 32 bytes");
            verifier.add_key(
                signer.key_id(),
                VerifyingKey::from_bytes(&bytes).expect("test public key is valid"),
            );
        }
        verifier
    }

    /// A whole composed case: real signed declaration, real signed
    /// `session.start`, real checkpoints over those two real artifact ids.
    struct ComposedCase {
        declaration_envelope: Envelope,
        first_run_envelope: Envelope,
        proof: WorkflowPreExistenceProof,
        trust: TrustRootStore,
        verifier: Verifier,
        workflow_ref: String,
        run: ObservedWorkflowRun,
    }

    fn composed_case() -> ComposedCase {
        let declaration = valid_declaration();
        let (workflow_ref, declaration_envelope, authority) = signed_declaration(&declaration);

        let run_signer =
            Ed25519Signer::generate("key_workflow_run").expect("test signer generation succeeds");
        let mut action = ActionStatement::new("agent://claude-code", "session.start");
        action.meta = Some(serde_json::json!({
            "session_start": true,
            "workflow_ref": workflow_ref,
        }));
        let signed_run = sign(&payload_type("action"), &action, &run_signer)
            .expect("session start action signs");

        let (proof, trust) = pre_existence_proof_for(&workflow_ref, &signed_run.artifact_id);

        let mut run = observed_golden_run();
        run.workflow_ref = workflow_ref.clone();

        ComposedCase {
            declaration_envelope,
            first_run_envelope: signed_run.envelope,
            proof,
            trust,
            verifier: verifier_over(&[&authority, &run_signer]),
            workflow_ref,
            run,
        }
    }

    #[test]
    fn composed_path_discards_a_claimed_pre_existence_grade() {
        let case = composed_case();
        // The golden run asserts `checked` pre-existence with placeholder
        // checkpoint ids. With no proof supplied, the composed path must not
        // let that claim through.
        assert_eq!(case.run.pre_existence.grade, EvidenceGrade::Checked);

        let report = verify_workflow_run(
            &case.declaration_envelope,
            &case.first_run_envelope,
            None,
            &case.run,
            &case.verifier,
            &case.trust,
        )
        .expect("a run with no checkpoint proof still produces a report");

        assert_eq!(
            report.pre_existence.grade,
            EvidenceGrade::Asserted,
            "an unproven pre-existence claim must be downgraded, not trusted"
        );
    }

    #[test]
    fn composed_path_grades_pre_existence_checked_only_with_real_proof() {
        let case = composed_case();
        let report = verify_workflow_run(
            &case.declaration_envelope,
            &case.first_run_envelope,
            Some(&case.proof),
            &case.run,
            &case.verifier,
            &case.trust,
        )
        .expect("real checkpoints over real artifact ids verify");

        assert_eq!(report.pre_existence.grade, EvidenceGrade::Checked);
        assert_eq!(report.workflow_ref, case.workflow_ref);
    }

    #[test]
    fn composed_path_refuses_a_declaration_signed_by_an_untrusted_key() {
        let case = composed_case();
        let stranger =
            Ed25519Signer::generate("key_stranger").expect("test signer generation succeeds");
        let verifier = verifier_over(&[&stranger]);

        let error = verify_workflow_run(
            &case.declaration_envelope,
            &case.first_run_envelope,
            Some(&case.proof),
            &case.run,
            &verifier,
            &case.trust,
        )
        .expect_err("an unverifiable declaration must never reach the reducer");
        assert!(matches!(
            error,
            WorkflowRunVerifyError::DeclarationSignature(_)
        ));
    }

    #[test]
    fn composed_path_refuses_a_run_that_names_another_workflow() {
        let case = composed_case();
        let mut run = case.run.clone();
        run.workflow_ref = "art_some_other_workflow".into();

        let error = verify_workflow_run(
            &case.declaration_envelope,
            &case.first_run_envelope,
            Some(&case.proof),
            &run,
            &case.verifier,
            &case.trust,
        )
        .expect_err("an observation set for another workflow must be refused");
        assert!(matches!(
            error,
            WorkflowRunVerifyError::WorkflowRefMismatch { .. }
        ));
    }

    #[test]
    fn composed_path_refuses_a_first_run_bound_to_another_workflow() {
        let case = composed_case();
        let (_, other_envelope, _) = {
            let run_signer = Ed25519Signer::generate("key_workflow_run")
                .expect("test signer generation succeeds");
            let mut action = ActionStatement::new("agent://claude-code", "session.start");
            action.meta = Some(serde_json::json!({
                "session_start": true,
                "workflow_ref": "art_some_other_workflow",
            }));
            let signed = sign(&payload_type("action"), &action, &run_signer)
                .expect("session start action signs");
            let verifier = verifier_over(&[&run_signer]);
            (verifier, signed.envelope, signed.artifact_id)
        };

        let error = verify_workflow_run(
            &case.declaration_envelope,
            &other_envelope,
            None,
            &case.run,
            &case.verifier,
            &case.trust,
        )
        .expect_err("a session.start bound to a different workflow must be refused");
        assert!(matches!(error, WorkflowRunVerifyError::RunBinding(_)));
    }

    #[test]
    fn composed_path_refuses_a_receipt_that_is_not_a_workflow_declaration() {
        let case = composed_case();
        let signer = Ed25519Signer::generate("key_workflow_authority")
            .expect("test signer generation succeeds");
        let mut receipt = ReceiptStatement::new("system://treeship-test", "memory.read.v1");
        receipt.payload = Some(serde_json::json!({ "note": "not a workflow" }));
        let signed = sign(&payload_type("receipt"), &receipt, &signer).expect("receipt signs");

        let error = verify_workflow_run(
            &signed.envelope,
            &case.first_run_envelope,
            None,
            &case.run,
            &verifier_over(&[&signer]),
            &case.trust,
        )
        .expect_err("a non-workflow receipt must not be read as a declaration");
        assert!(matches!(
            error,
            WorkflowRunVerifyError::DeclarationNotAWorkflow { .. }
        ));
    }
}
