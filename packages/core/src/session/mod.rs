//! Session Receipt v1: unified session model for multi-agent workflows.
//!
//! This module provides the complete data model for Session Receipts:
//! session manifests, events, context propagation, agent graphs,
//! side-effect tracking, and receipt composition.

pub mod manifest;
pub mod event;
pub mod event_log;
pub mod context;
pub mod graph;
pub mod side_effects;
pub mod receipt;
pub mod render;
pub mod package;

pub use manifest::*;
pub use event::*;
pub use event_log::EventLog;
pub use context::PropagationContext;
pub use graph::{AgentGraph, AgentNode, AgentEdge, AgentEdgeType};
pub use side_effects::SideEffects;
pub use receipt::{ArtifactEntry, ReceiptComposer, SessionReceipt};
pub use render::RenderConfig;
pub use package::{build_package, read_package, verify_package, VerifyCheck, VerifyStatus};
