use serde::Deserialize;
use treeship_core::verify::workflow_conformance::{
    evaluate_workflow_conformance, ObservedWorkflowRun, WorkflowConformanceReport,
    WorkflowDeclaration,
};

const DECLARATION: &str = include_str!("fixtures/workflow-conformance/declaration.json");

#[derive(Deserialize)]
struct GoldenFixture {
    fixture_version: u32,
    run: ObservedWorkflowRun,
    expected_report: WorkflowConformanceReport,
}

fn assert_golden(name: &str, json: &str) {
    let declaration: WorkflowDeclaration =
        serde_json::from_str(DECLARATION).expect("shared workflow declaration must parse");
    let fixture: GoldenFixture = serde_json::from_str(json).expect("golden fixture must parse");
    assert_eq!(
        fixture.fixture_version, 1,
        "{name}: unknown fixture version"
    );

    let actual = evaluate_workflow_conformance(&declaration, &fixture.run)
        .unwrap_or_else(|error| panic!("{name}: reducer rejected golden input: {error}"));
    assert_eq!(actual, fixture.expected_report, "{name}: report drifted");
}

#[test]
fn valid_run_matches_golden_report() {
    assert_golden(
        "valid",
        include_str!("fixtures/workflow-conformance/valid.json"),
    );
}

#[test]
fn undeclared_edge_matches_deviation_report() {
    assert_golden(
        "deviation",
        include_str!("fixtures/workflow-conformance/deviation.json"),
    );
}

#[test]
fn missing_terminal_matches_gap_report() {
    assert_golden(
        "gap",
        include_str!("fixtures/workflow-conformance/gap.json"),
    );
}

#[test]
fn excess_back_edges_match_loop_cap_report() {
    assert_golden(
        "loop-cap",
        include_str!("fixtures/workflow-conformance/loop-cap.json"),
    );
}

#[test]
fn adapter_only_transition_matches_asserted_edge_report() {
    assert_golden(
        "asserted-edge",
        include_str!("fixtures/workflow-conformance/asserted-edge.json"),
    );
}

#[test]
fn signed_timestamps_do_not_upgrade_pre_existence() {
    assert_golden(
        "not-preexisting",
        include_str!("fixtures/workflow-conformance/not-preexisting.json"),
    );
}

#[test]
fn out_of_scope_tool_matches_authority_deviation_report() {
    assert_golden(
        "authority-deviation",
        include_str!("fixtures/workflow-conformance/authority-deviation.json"),
    );
}
