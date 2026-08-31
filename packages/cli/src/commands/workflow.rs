//! `treeship workflow verify`: the composed workflow conformance verifier.
//!
//! Every cryptographic decision lives in `treeship_core`'s
//! `verify_workflow_run`. This module loads four inputs -- a signed
//! `workflow.v1` declaration, the signed `session.start` that opened the run,
//! an observation set, and optionally a checkpoint proof -- and prints the
//! report that comes back. It deliberately grades nothing itself, so there is
//! exactly one place in the codebase that can call evidence `checked`.

use std::fs;

use treeship_core::trust::TrustRootStore;
use treeship_core::verify::workflow_conformance::{
    verify_workflow_run, EvidenceGrade, ObservedWorkflowRun, WorkflowConformanceReport,
    WorkflowPreExistenceProof,
};

use crate::commands::verifier;
use crate::ctx;
use crate::printer::Printer;

#[allow(clippy::too_many_arguments)]
pub fn verify(
    workflow_ref: &str,
    first_run: &str,
    run_path: &str,
    proof_path: Option<&str>,
    strict: bool,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let declaration = ctx.storage.read(workflow_ref).map_err(|e| {
        format!(
            "workflow declaration {workflow_ref} is not available locally: {e}\n\n  fix: mint or pull the workflow.v1 artifact before verifying"
        )
    })?;
    let first_run_record = ctx.storage.read(first_run).map_err(|e| {
        format!(
            "first-run artifact {first_run} is not available locally: {e}\n\n  fix: pull the session.start artifact for this run"
        )
    })?;

    let run_text = fs::read_to_string(run_path)
        .map_err(|e| format!("cannot read observation set {run_path}: {e}"))?;
    let run: ObservedWorkflowRun = serde_json::from_str(&run_text)
        .map_err(|e| format!("observation set {run_path} is not a valid workflow run: {e}"))?;

    let proof: Option<WorkflowPreExistenceProof> = match proof_path {
        Some(path) => {
            let text = fs::read_to_string(path)
                .map_err(|e| format!("cannot read pre-existence proof {path}: {e}"))?;
            Some(
                serde_json::from_str(&text)
                    .map_err(|e| format!("pre-existence proof {path} is malformed: {e}"))?,
            )
        }
        None => None,
    };

    let trust = TrustRootStore::open_default_or_empty()?;
    let verifier = verifier::from_local_and_trust(&ctx.keys, &trust)?.ok_or(
        "no verification keys are available: this machine has no local keys and no trust roots\n\n  fix: run `treeship init`, or add a trust root with `treeship trust add`",
    )?;

    let report = verify_workflow_run(
        &declaration.envelope,
        &first_run_record.envelope,
        proof.as_ref(),
        &run,
        &verifier,
        &trust,
    )?;

    if printer.format == crate::printer::Format::Json {
        printer.json(&report);
    } else {
        print_report(&report, proof.is_some(), printer);
    }

    if strict && !is_conformant(&report) {
        return Err(
            "workflow run is not conformant: see the deviations, gaps, or exceeded limits above"
                .into(),
        );
    }
    Ok(())
}

/// Whether a report is free of findings on every axis.
///
/// This is the caller's policy, not the substrate's. The spec is explicit that
/// there is no single workflow score, so this lives behind `--strict` and the
/// default run still exits zero with a full report.
fn is_conformant(report: &WorkflowConformanceReport) -> bool {
    report.path.deviations.is_empty()
        && report.path.gaps.is_empty()
        && report.authority.deviations.is_empty()
        && !report
            .loops
            .iter()
            .any(|l| l.limit_exceeded || l.budget_exceeded)
}

fn grade_label(grade: EvidenceGrade) -> &'static str {
    match grade {
        EvidenceGrade::Checked => "checked",
        EvidenceGrade::Captured => "captured",
        EvidenceGrade::Asserted => "asserted",
    }
}

fn print_report(report: &WorkflowConformanceReport, had_proof: bool, printer: &Printer) {
    printer.section("Workflow conformance");
    printer.info(&format!("  run:       {}", report.run_id));
    printer.info(&format!("  workflow:  {}", report.workflow_ref));
    printer.blank();

    // Each axis prints separately and none summarizes another. A checked path
    // with an authority deviation is a real and reportable state.
    let pre = grade_label(report.pre_existence.grade);
    printer.info(&format!("  pre-existence:  {pre}"));
    if !had_proof {
        printer.hint("no --proof supplied, so declaration ordering is unproven; pass a checkpoint proof to reach `checked`");
    }
    if let Some(reason) = &report.pre_existence.reason {
        printer.dim_info(&format!("    {reason}"));
    }

    printer.info(&format!(
        "  path:           {}",
        grade_label(report.path.grade)
    ));
    for deviation in &report.path.deviations {
        printer.warn(
            &format!(
                "    deviation: {} -> {} ({})",
                deviation.from, deviation.to, deviation.reason
            ),
            &[],
        );
    }
    for gap in &report.path.gaps {
        printer.warn(
            &format!("    gap: {} ({})", gap.node_id, gap.reason),
            &[("after", gap.after.as_str())],
        );
    }

    printer.info(&format!(
        "  authority:      {}",
        grade_label(report.authority.grade)
    ));
    for deviation in &report.authority.deviations {
        printer.warn(
            &format!(
                "    deviation: {} used {} `{}`",
                deviation.node_id, deviation.kind, deviation.value
            ),
            &[],
        );
    }

    for loop_report in &report.loops {
        printer.info(&format!(
            "  loop {}:  {} iteration(s) of max {}",
            loop_report.id, loop_report.iterations, loop_report.max_iterations
        ));
        if loop_report.limit_exceeded {
            printer.warn("    iteration limit exceeded", &[]);
        }
        if loop_report.budget_exceeded {
            printer.warn("    action budget exceeded", &[]);
        }
    }

    printer.blank();
    if is_conformant(report) {
        printer.success("no deviations, gaps, or exceeded limits", &[]);
    } else {
        printer.failure("the run has findings; each axis is reported above", &[]);
    }
}
