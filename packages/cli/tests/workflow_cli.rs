use std::path::PathBuf;
use std::process::{Command, Output};

use tempfile::TempDir;
use treeship_core::{statements::ActionStatement, storage::Store as ArtifactStore};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Workspace {
    _tmp: TempDir,
    root: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("temporary workspace");
        let root = tmp.path().to_path_buf();
        let workspace = Self { _tmp: tmp, root };
        let output = workspace
            .command()
            .args(["init", "--config"])
            .arg(workspace.config())
            .args(["--name", "workflow-test"])
            .output()
            .expect("treeship init runs");
        assert_success("init", &output);
        workspace
    }

    fn config(&self) -> String {
        self.root
            .join(".treeship/config.json")
            .display()
            .to_string()
    }

    fn command(&self) -> Command {
        let mut command = Command::new(cli_path());
        command
            .env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .current_dir(&self.root);
        command
    }

    fn attest_workflow(&self, payload: &str) -> Output {
        self.command()
            .args(["attest", "receipt", "--system", "human://operator"])
            .args(["--kind", "workflow.v1", "--payload", payload])
            .args(["--format", "json", "--config"])
            .arg(self.config())
            .output()
            .expect("attest receipt runs")
    }

    fn start_with_workflow(&self, workflow_ref: &str) -> Output {
        self.command()
            .args(["session", "start", "--workflow-ref", workflow_ref])
            .args(["--config"])
            .arg(self.config())
            .output()
            .expect("session start runs")
    }

    fn artifact_count(&self) -> usize {
        std::fs::read_dir(self.root.join(".treeship/artifacts"))
            .expect("artifact directory exists")
            .count()
    }
}

fn declaration() -> serde_json::Value {
    serde_json::json!({
        "kind": "workflow.v1",
        "schema_version": "1",
        "workflow_id": "single-step",
        "authority": "human://operator",
        "entry_node": "qa",
        "terminal_nodes": ["qa"],
        "nodes": [{
            "id": "qa",
            "executor": { "capability": "qa.browser" },
            "allowed_tools": ["gstack.qa"]
        }],
        "edges": [],
        "loops": []
    })
}

fn assert_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn artifact_id(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|value| {
            value
                .get("id")
                .or_else(|| value.get("artifact_id"))
                .and_then(|id| id.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            panic!(
                "attest output carried no artifact id: {}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
}

#[test]
fn generic_receipt_path_signs_a_valid_workflow_declaration() {
    let workspace = Workspace::new();
    let output = workspace.attest_workflow(&declaration().to_string());
    assert_success("attest workflow.v1", &output);

    let id = artifact_id(&output);
    let verify = workspace
        .command()
        .args(["verify", &id, "--config"])
        .arg(workspace.config())
        .output()
        .expect("verify runs");
    assert_success("verify workflow receipt", &verify);
}

#[test]
fn generic_receipt_path_refuses_unchecked_workflow_control_fields() {
    let workspace = Workspace::new();
    let before = std::fs::read_dir(workspace.root.join(".treeship/artifacts"))
        .expect("artifact directory exists")
        .count();
    let mut invalid = declaration();
    invalid["nodes"][0]["retry_policy"] = serde_json::json!({ "max": 99 });

    let output = workspace.attest_workflow(&invalid.to_string());
    assert!(!output.status.success(), "unknown control field was signed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("predicate validation failed") && stderr.contains("unknown field"),
        "refusal should name predicate validation and unknown field: {stderr}"
    );
    let after = std::fs::read_dir(workspace.root.join(".treeship/artifacts"))
        .expect("artifact directory exists")
        .count();
    assert_eq!(before, after, "a refused workflow must write no artifact");
}

#[test]
fn generic_receipt_path_refuses_missing_schema_required_allowed_tools() {
    let workspace = Workspace::new();
    let before = workspace.artifact_count();
    let mut invalid = declaration();
    invalid["nodes"][0]
        .as_object_mut()
        .expect("workflow node is an object")
        .remove("allowed_tools");

    let output = workspace.attest_workflow(&invalid.to_string());
    assert!(
        !output.status.success(),
        "workflow without schema-required allowed_tools was signed"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("allowed_tools"),
        "error should name the missing nested field: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        before,
        workspace.artifact_count(),
        "a schema-invalid workflow must write no artifact"
    );
}

#[test]
fn session_start_binds_workflow_into_signed_root_and_manifest() {
    let workspace = Workspace::new();
    let workflow = workspace.attest_workflow(&declaration().to_string());
    assert_success("attest workflow.v1", &workflow);
    let workflow_id = artifact_id(&workflow);

    let start = workspace.start_with_workflow(&workflow_id);
    assert_success("session start --workflow-ref", &start);

    let manifest_bytes = std::fs::read(workspace.root.join(".treeship/session.json"))
        .expect("session manifest exists");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("session manifest is JSON");
    assert_eq!(manifest["workflow_ref"], workflow_id);
    let root_id = manifest["root_artifact_id"]
        .as_str()
        .expect("manifest carries signed root artifact id");

    let store = ArtifactStore::open(workspace.root.join(".treeship/artifacts"))
        .expect("artifact store opens");
    let root = store.read(root_id).expect("root action exists");
    let action: ActionStatement = root
        .envelope
        .unmarshal_statement()
        .expect("root artifact is an action statement");
    assert_eq!(action.action, "session.start");
    assert_eq!(
        action
            .meta
            .as_ref()
            .and_then(|m| m["workflow_ref"].as_str()),
        Some(workflow_id.as_str()),
        "the authoritative workflow binding must be inside signed action bytes"
    );

    let verify = workspace
        .command()
        .args(["verify", root_id, "--config"])
        .arg(workspace.config())
        .output()
        .expect("verify root action runs");
    assert_success("verify workflow-bound session root", &verify);

    let close = workspace
        .command()
        .args(["session", "close", "--summary", "workflow run complete"])
        .args(["--config"])
        .arg(workspace.config())
        .output()
        .expect("session close runs");
    assert_success("close workflow-bound session", &close);

    let store = ArtifactStore::open(workspace.root.join(".treeship/artifacts"))
        .expect("artifact store reopens after close");
    let session_record = store
        .list()
        .into_iter()
        .filter_map(|entry| store.read(&entry.id).ok())
        .filter_map(|record| {
            record
                .envelope
                .unmarshal_statement::<treeship_core::statements::ReceiptStatement>()
                .ok()
        })
        .find(|statement| statement.kind == "session.v1")
        .expect("close mints a signed session.v1 record");
    assert_eq!(
        session_record
            .payload
            .as_ref()
            .and_then(|payload| payload["workflow_ref"].as_str()),
        Some(workflow_id.as_str()),
        "the signed work-history record must preserve the root workflow binding"
    );
}

#[test]
fn session_close_refuses_a_manifest_workflow_substitution_before_writing() {
    let workspace = Workspace::new();
    let first = workspace.attest_workflow(&declaration().to_string());
    assert_success("attest first workflow", &first);
    let first_id = artifact_id(&first);

    let mut alternate_declaration = declaration();
    alternate_declaration["workflow_id"] = serde_json::json!("alternate-step");
    let alternate = workspace.attest_workflow(&alternate_declaration.to_string());
    assert_success("attest alternate workflow", &alternate);
    let alternate_id = artifact_id(&alternate);

    let start = workspace.start_with_workflow(&first_id);
    assert_success("start first workflow", &start);

    let manifest_path = workspace.root.join(".treeship/session.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("session manifest exists"))
            .expect("session manifest is JSON");
    manifest["workflow_ref"] = serde_json::Value::String(alternate_id);
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("mutated manifest serializes"),
    )
    .expect("test mutates discovery manifest");
    let before = workspace.artifact_count();

    let close = workspace
        .command()
        .args(["session", "close", "--summary", "must not be signed"])
        .args(["--config"])
        .arg(workspace.config())
        .output()
        .expect("session close runs");
    assert!(
        !close.status.success(),
        "mutable manifest workflow substitution was signed at close"
    );
    assert!(
        String::from_utf8_lossy(&close.stderr).contains("manifest workflow mismatch"),
        "error should explain the signed-root mismatch: {}",
        String::from_utf8_lossy(&close.stderr)
    );
    assert_eq!(
        before,
        workspace.artifact_count(),
        "refusal must happen before close writes an artifact"
    );
    assert!(
        manifest_path.exists(),
        "refusal must leave active-session state available for repair"
    );
}

#[test]
fn session_start_refuses_non_workflow_reference_before_writing_root() {
    let workspace = Workspace::new();
    let receipt = workspace
        .command()
        .args(["attest", "receipt", "--system", "system://test"])
        .args(["--kind", "confirmation", "--payload", "{}"])
        .args(["--format", "json", "--config"])
        .arg(workspace.config())
        .output()
        .expect("attest non-workflow receipt runs");
    assert_success("attest non-workflow receipt", &receipt);
    let receipt_id = artifact_id(&receipt);
    let before = workspace.artifact_count();

    let start = workspace.start_with_workflow(&receipt_id);
    assert!(
        !start.status.success(),
        "non-workflow reference was accepted"
    );
    assert!(
        String::from_utf8_lossy(&start.stderr).contains("not a workflow.v1 declaration"),
        "error should explain the refused kind: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    assert_eq!(
        before,
        workspace.artifact_count(),
        "validation must happen before the session root is signed"
    );
    assert!(
        !workspace.root.join(".treeship/session.json").exists(),
        "a refused start must not create active-session state"
    );
}

#[test]
fn session_start_refuses_missing_workflow_before_writing_root() {
    let workspace = Workspace::new();
    let before = workspace.artifact_count();
    let missing = "art_00000000000000000000000000000000";

    let start = workspace.start_with_workflow(missing);
    assert!(
        !start.status.success(),
        "missing workflow reference was accepted"
    );
    assert!(
        String::from_utf8_lossy(&start.stderr).contains("not available locally"),
        "error should explain how to make the workflow available: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    assert_eq!(before, workspace.artifact_count());
    assert!(!workspace.root.join(".treeship/session.json").exists());
}
