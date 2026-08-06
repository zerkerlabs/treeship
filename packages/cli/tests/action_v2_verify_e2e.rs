//! End-to-end verification of an action/v2 receipt through the real CLI.
//!
//! Every other v2 test calls core functions directly or stops at
//! `extract_step_info`. That leaves the property we actually sell untested:
//! that a v2 receipt sitting in a real store, verified by the real binary,
//! reports its authority, delegation, and lifecycle honestly. Fixtures written
//! by the same person who wrote the verifier are exactly the evidence Treeship
//! tells everyone else not to accept.
//!
//! So: init a workspace with the binary, sign a v2 receipt with that
//! workspace's own key, write it to that workspace's own store, and read the
//! verdict back out of `--format json`.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;
use treeship_core::{
    attestation::sign,
    keys::Store as KeyStore,
    statements::{
        payload_type_v2, ActionStatementV2, DeadlineEvent, Effect, EffectConfidence,
        EffectFinality, Mandate, Resolution, Revocation,
    },
    storage::{Record, Store as ArtifactStore},
};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Workspace {
    _tmp: TempDir,
    root: PathBuf,
}

impl Workspace {
    /// A workspace whose keystore and store are the ones the binary will open,
    /// so a receipt planted here is signed by a key `verify` already trusts.
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let ws = Self { _tmp: tmp, root };
        let out = ws.cmd().args(["init"]).output().unwrap();
        assert!(
            out.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ws
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root);
        c.current_dir(&self.root);
        c
    }

    fn keys_dir(&self) -> PathBuf {
        self.root.join(".treeship/keys")
    }
    fn storage_dir(&self) -> PathBuf {
        self.root.join(".treeship/artifacts")
    }

    /// This workspace's default public key, base64url-no-pad — the form a
    /// grant's `grantee` uses.
    fn public_key_b64(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let keys = KeyStore::open(self.keys_dir()).expect("open keystore");
        let signer = keys.default_signer().expect("default key");
        URL_SAFE_NO_PAD.encode(signer.public_key_bytes())
    }

    /// Sign `stmt` with the workspace's default key and write it to the store,
    /// returning the artifact id `verify` will be pointed at.
    fn plant_v2(&self, stmt: &ActionStatementV2) -> String {
        let keys = KeyStore::open(self.keys_dir()).expect("open keystore");
        let signer = keys.default_signer().expect("workspace has a default key");
        let signed = sign(&payload_type_v2("action"), stmt, signer.as_ref()).expect("sign");

        let store = ArtifactStore::open(self.storage_dir()).expect("open store");
        let record = Record {
            artifact_id: signed.artifact_id.clone(),
            digest: signed.digest.clone(),
            payload_type: payload_type_v2("action"),
            key_id: signer.key_id().to_string(),
            signed_at: stmt.timestamp.clone(),
            parent_id: None,
            envelope: signed.envelope.clone(),
            hub_url: None,
        };
        store.write(&record).expect("write record");
        signed.artifact_id.to_string()
    }

    fn verify_json(&self, id: &str) -> serde_json::Value {
        let out = self
            .cmd()
            .args(["verify", id, "--format", "json"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("verify emitted non-JSON ({e}): {stdout}"))
    }
}

/// A mandate whose scope admits `payments.charge`, in window at the timestamp
/// the statements below use.
fn mandate(scope: Vec<&str>) -> Mandate {
    Mandate {
        grant_id: "grant_e2e".into(),
        grantor: "key_parent".into(),
        grantee: None,
        issuer_sig: None,
        objective_hash: None,
        scope: scope.into_iter().map(String::from).collect(),
        audience: "acme".into(),
        parent_request_id: None,
        delegation_depth: 0,
        issued_at: "2026-07-20T10:00:00Z".into(),
        expiry: "2026-07-20T11:00:00Z".into(),
        max_delegation: 3,
        revocation: Revocation {
            path: "hub://acme/revocations".into(),
            revoked_at: None,
        },
        chain: Vec::new(),
    }
}

fn action(scope: Vec<&str>, act: &str) -> ActionStatementV2 {
    let mut s = ActionStatementV2::new("agent://worker", act, mandate(scope));
    s.timestamp = "2026-07-20T10:30:00Z".into();
    s.audience = Some("acme".into());
    s
}

#[test]
fn in_scope_action_reports_unverified_authority_not_pass() {
    // The revocation layer has no resolver wired, so the only honest authority
    // verdict is `unverified`. If this ever reads `pass`, the CLI started
    // claiming a grant is live because nobody looked.
    let ws = Workspace::new();
    let id = ws.plant_v2(&action(vec!["payments.charge"], "payments.charge"));

    let j = ws.verify_json(&id);
    let check = &j["checks"][0];
    assert_eq!(
        check["authority"]["outcome"], "unverified",
        "authority should be unverified without a revocation resolver: {j}"
    );
    assert!(
        !check["authority"]["reasons"]
            .as_array()
            .unwrap()
            .is_empty(),
        "unverified must name the layer it could not check: {j}"
    );
    assert_eq!(
        j["authority_ok"], true,
        "unverified is not a violation, so the gate flag stays true: {j}"
    );
}

#[test]
fn out_of_scope_action_is_visible_to_a_machine_consumer() {
    // The whole point of exposing authority in JSON: a CI gate reading this
    // must be able to see that a perfectly-signed receipt recorded an action
    // its grant did not admit.
    let ws = Workspace::new();
    let id = ws.plant_v2(&action(vec!["payments.charge"], "payments.refund"));

    let j = ws.verify_json(&id);
    let check = &j["checks"][0];
    assert_eq!(
        check["authority"]["outcome"], "fail",
        "an out-of-scope action must fail the authority axis: {j}"
    );
    assert!(
        check["authority"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap_or_default().contains("scope")),
        "the reason should name scope: {j}"
    );
    assert_eq!(
        j["authority_ok"], false,
        "a single gate field must reflect the violation: {j}"
    );
}

#[test]
fn unbacked_finalized_claim_is_downgraded_in_the_json_surface() {
    // The 56%-of-writes shape, end to end: the actor says the change committed
    // and bundles nothing an outside party could check.
    let ws = Workspace::new();
    let mut stmt = action(vec!["payments.charge"], "payments.charge");
    stmt.effect = Some(Effect {
        output_hash: Some("sha256:out".into()),
        effect_confidence: Some(EffectConfidence::Verified),
        finality: Some(EffectFinality::Finalized),
        ..Default::default()
    });
    let id = ws.plant_v2(&stmt);

    let j = ws.verify_json(&id);
    let effect = &j["checks"][0]["effect"];
    assert_eq!(
        effect["effective_finality"], "indeterminate",
        "an unbacked Finalized must not survive to the machine surface: {j}"
    );
    assert_eq!(effect["claimed_finality"], "finalized");
    assert_eq!(effect["finality_downgraded"], true);
    // And the confidence axis is downgraded independently, not as a side effect.
    //
    // "not-verified" is kebab here while the receipt's own wire form is
    // `not_verified`. That mismatch predates this work and is documented on
    // `effect_label`; asserting the value the CLI actually emits keeps this
    // test honest about today's behaviour rather than the intended one.
    assert_eq!(effect["effective_confidence"], "not-verified");
    assert_eq!(effect["downgraded"], true);
}

#[test]
fn readback_backed_finalized_claim_survives_end_to_end() {
    let ws = Workspace::new();
    let mut stmt = action(vec!["payments.charge"], "payments.charge");
    stmt.effect = Some(Effect {
        readback: Some("sha256:observed".into()),
        effect_confidence: Some(EffectConfidence::Verified),
        finality: Some(EffectFinality::Finalized),
        ..Default::default()
    });
    let id = ws.plant_v2(&stmt);

    let j = ws.verify_json(&id);
    let effect = &j["checks"][0]["effect"];
    assert_eq!(effect["effective_finality"], "finalized", "{j}");
    assert_eq!(effect["effective_confidence"], "verified", "{j}");
    assert_eq!(effect["finality_downgraded"], false, "{j}");
}

#[test]
fn open_effect_with_no_deadline_is_reported_as_indefinite() {
    // The pending-forever row. It has to be visible without anyone knowing to
    // go looking for it.
    let ws = Workspace::new();
    let mut stmt = action(vec!["payments.charge"], "payments.charge");
    stmt.effect = Some(Effect {
        output_hash: Some("sha256:out".into()),
        finality: Some(EffectFinality::Initiated),
        ..Default::default()
    });
    let id = ws.plant_v2(&stmt);

    let j = ws.verify_json(&id);
    assert_eq!(
        j["checks"][0]["resolution"]["outcome"], "indefinite",
        "an open effect with no deadline must say so: {j}"
    );
}

#[test]
fn open_effect_past_its_deadline_reports_breached_with_its_event() {
    let ws = Workspace::new();
    let mut stmt = action(vec!["payments.charge"], "payments.charge");
    stmt.effect = Some(Effect {
        output_hash: Some("sha256:out".into()),
        finality: Some(EffectFinality::Initiated),
        resolution: Some(Resolution {
            // Long past by any wall clock this test runs under.
            deadline: "2026-07-20T11:00:00Z".into(),
            on_deadline: DeadlineEvent::Escalate,
        }),
        ..Default::default()
    });
    let id = ws.plant_v2(&stmt);

    let j = ws.verify_json(&id);
    let r = &j["checks"][0]["resolution"];
    assert_eq!(r["outcome"], "breached", "{j}");
    assert_eq!(
        r["on_deadline"], "escalate",
        "the declared obligation must travel with the breach: {j}"
    );
}

#[test]
fn a_single_hop_mandate_reports_not_claimed_rather_than_a_passing_chain() {
    // No ancestors carried means no lineage claim was made. Reporting that as
    // anything pass-shaped would let a reader infer a check that never ran.
    let ws = Workspace::new();
    let id = ws.plant_v2(&action(vec!["payments.charge"], "payments.charge"));

    let j = ws.verify_json(&id);
    assert_eq!(
        j["checks"][0]["delegation_chain"]["outcome"], "not_claimed",
        "{j}"
    );
}

#[test]
fn a_v1_receipt_gains_no_v2_claims() {
    // Emitted by the real CLI, which still produces v1. A v1 receipt must not
    // sprout an authority, chain, or resolution verdict it never made.
    let ws = Workspace::new();
    let out = ws
        .cmd()
        .args([
            "attest", "action", "--actor", "agent://legacy", "--action", "tool.call",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "attest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let j = ws.verify_json("last");
    let check = &j["checks"][0];
    assert!(check["authority"].is_null(), "v1 claimed authority: {j}");
    assert!(
        check["delegation_chain"].is_null(),
        "v1 claimed a chain: {j}"
    );
    assert!(check["resolution"].is_null(), "v1 claimed a resolution: {j}");
}

#[test]
fn a_gate_can_tell_checked_and_clean_from_never_checked() {
    // `authority_ok` alone is a boolean over a three-valued axis, so an
    // unverified mandate and a fully-checked clean one both read `true`. That
    // is the shape a CI job reading one field would mistake for safety --
    // exactly the "200 OK containing a logical dead end" failure.
    //
    // The counts travel alongside so the caller picks its own policy: a job
    // gating a read may accept unverified, one gating a payment may not.
    let ws = Workspace::new();
    let id = ws.plant_v2(&action(vec!["payments.charge"], "payments.charge"));

    let j = ws.verify_json(&id);
    assert_eq!(j["authority_ok"], true, "nothing was violated: {j}");
    assert_eq!(j["authority_checked"], 1, "one mandate was judged: {j}");
    assert_eq!(
        j["authority_unverified"], 1,
        "and it could not be fully checked -- revocation has no resolver: {j}"
    );
}

#[test]
fn a_violation_is_counted_as_a_failure_not_as_unverified() {
    // The two must not blur: an out-of-scope action is a finding, not a gap in
    // our ability to look.
    let ws = Workspace::new();
    let id = ws.plant_v2(&action(vec!["payments.charge"], "payments.refund"));

    let j = ws.verify_json(&id);
    assert_eq!(j["authority_ok"], false, "{j}");
    assert_eq!(j["authority_checked"], 1, "{j}");
    assert_eq!(
        j["authority_unverified"], 0,
        "a Fail is not an Unverified: {j}"
    );
}

#[test]
fn a_receipt_signed_by_a_key_the_grant_did_not_name_fails_authority() {
    // `attest` refuses to build this, so the only way it exists is if someone
    // constructed it outside our CLI -- which is exactly the case a verifier
    // has to survive. Both signatures are genuine; the receipt is still
    // somebody spending authority that was never issued to them.
    let ws = Workspace::new();
    let mut stmt = action(vec!["payments.charge"], "payments.charge");
    stmt.mandate.grantee = Some("a-key-that-is-not-this-workspace".into());
    let id = ws.plant_v2(&stmt);

    let j = ws.verify_json(&id);
    let auth = &j["checks"][0]["authority"];
    assert_eq!(
        auth["outcome"], "fail",
        "a receipt signed by a non-grantee must fail authority: {j}"
    );
    assert!(
        auth["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap_or_default().contains("holder")),
        "the reason must name the holder mismatch: {j}"
    );
    assert_eq!(j["authority_ok"], false, "{j}");
}

#[test]
fn a_receipt_signed_by_the_named_grantee_clears_the_holder_layer() {
    // Same shape, but the grant names the key that signs. Only revocation
    // should remain unverified.
    let ws = Workspace::new();
    let mut stmt = action(vec!["payments.charge"], "payments.charge");
    stmt.mandate.grantee = Some(ws.public_key_b64());
    let id = ws.plant_v2(&stmt);

    let j = ws.verify_json(&id);
    let auth = &j["checks"][0]["authority"];
    assert_eq!(auth["outcome"], "unverified", "{j}");
    let reasons = auth["reasons"].as_array().unwrap();
    assert!(
        reasons
            .iter()
            .all(|r| !r.as_str().unwrap_or_default().contains("holder")),
        "the holder layer must be clear: {j}"
    );
}
