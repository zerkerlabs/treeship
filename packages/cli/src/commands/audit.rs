//! `treeship audit --hub <url> <agent>` — audit an agent's transparency log.
//!
//! The client half of Certificate Transparency for agents
//! (docs/specs/transparency-log.md): pull an agent's append-only history from a
//! Hub, **re-verify each anchored entry's Merkle inclusion offline** against
//! your own trust roots, and check completeness against the agent's committed
//! `evidence_anchor` so omission is detectable. The Hub serves metadata and
//! anchors; this command, not the Hub, decides what holds.

use crate::{ctx, printer::Printer};
use treeship_core::merkle::{verify_consistency, Checkpoint, MerkleTree, ProofFile};
use treeship_core::trust::TrustRootStore;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// The highest trusted checkpoint we have seen for a `(hub, signer)` pair,
/// persisted across audits. Witnessing it over time is what lets a client
/// catch a Hub that **equivocates** (serves two different roots for the same
/// `tree_size`) or **regresses** (a smaller tree than before) -- a lying or
/// forking log. This is gossip/witnessing, not the cryptographic append-only
/// proof: it does not prove the new tree *extends* the old one (that is the
/// consistency proof, slice 3b), but it catches a Hub that contradicts itself.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct WitnessRecord {
    tree_size: usize,
    root:      String,
    index:     u64,
    signed_at: String,
    signer:    String,
}

/// Directory holding witnessed checkpoints: ~/.treeship/merkle/witnessed/
fn witnessed_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let home = home::home_dir().ok_or("cannot determine home directory")?;
    let dir = home.join(".treeship").join("merkle").join("witnessed");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Stable filename for a `(hub, signer)` witness record. The signer (the
/// checkpoint signing key) identifies the log; the hub host scopes it.
fn witness_path(hub: &str, signer: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let safe: String = format!("{hub}__{signer}")
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    Ok(witnessed_dir()?.join(format!("{safe}.json")))
}

fn load_witness(path: &std::path::Path) -> Option<WitnessRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn save_witness(path: &std::path::Path, rec: &WitnessRecord) -> CmdResult {
    std::fs::write(path, serde_json::to_string_pretty(rec)?)?;
    Ok(())
}

pub fn audit(
    agent: &str,
    hub: Option<&str>,
    watch: bool,
    interval: u64,
    config: Option<&str>,
    printer: &Printer,
) -> CmdResult {
    let _ctx = ctx::open(config)?;
    let trust = TrustRootStore::open_default_or_empty()?;
    let Some(hub) = hub else {
        return Err(
            "audit requires --hub <url> (the network transparency log); local history is `treeship log`"
                .into(),
        );
    };
    let base = hub.trim_end_matches('/');

    // One-shot, or monitor mode: re-run on an interval and keep alerting on
    // omission. "Monitors catch anomalies." Ctrl-C to stop.
    if !watch {
        let hostile = audit_once(base, agent, &trust, printer)?;
        if hostile {
            std::process::exit(1);
        }
        return Ok(());
    }
    printer.hint(&format!(
        "watching {agent} on {base} every {interval}s (Ctrl-C to stop)"
    ));
    loop {
        printer.blank();
        if let Err(e) = audit_once(base, agent, &trust, printer) {
            printer.warn("audit cycle failed", &[("error", &e.to_string())]);
        }
        // watch mode never exits on anomalies -- its job is to keep alerting.
        std::thread::sleep(std::time::Duration::from_secs(interval.max(1)));
    }
}

/// A single audit pass: pull the history, re-verify anchored inclusions, check
/// completeness against the agent's committed anchor. Returns whether the
/// verdict was HOSTILE (omission / invalid inclusion / equivocation /
/// append-only failure) so the one-shot caller can exit nonzero — a monitor
/// that detects a history rewrite and exits 0 is lying to whatever gates on
/// it. Watch mode keeps looping and alerting instead.
fn audit_once(base: &str, agent: &str, trust: &TrustRootStore, printer: &Printer) -> Result<bool, Box<dyn std::error::Error>> {
    let log: serde_json::Value = ureq::get(&format!("{base}/v1/agents/log"))
        .query("agent", agent)
        .call()
        .map_err(|e| format!("could not reach hub {base}: {e}"))?
        .into_json()
        .map_err(|e| format!("hub returned invalid JSON: {e}"))?;

    let entries = log
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Walk the history; re-verify each anchored entry's inclusion offline, and
    // track the highest fully-verified checkpoint so we can witness it.
    let (mut anchored, mut verified) = (0usize, 0usize);
    let mut invalid = 0usize;
    let mut current_cp: Option<Checkpoint> = None;
    let mut lines: Vec<String> = Vec::new();
    for e in &entries {
        let id = e.get("artifact_id").and_then(|v| v.as_str()).unwrap_or("");
        let kind = e.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
        let action = e.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let has_anchor = e
            .get("merkle_anchor")
            .map(|v| !v.is_null())
            .unwrap_or(false);

        let mark = if has_anchor {
            anchored += 1;
            match verify_inclusion(base, id, trust) {
                Ok((true, cp)) => {
                    verified += 1;
                    // Witness the highest verified checkpoint (by tree_size,
                    // then index) -- the most recent trusted state.
                    let higher = current_cp
                        .as_ref()
                        .map_or(true, |c| (cp.tree_size, cp.index) > (c.tree_size, c.index));
                    if higher {
                        current_cp = Some(cp);
                    }
                    "anchored ✓"
                }
                Ok((false, _)) => {
                    invalid += 1;
                    "anchored ✗ INVALID"
                }
                Err(_) => "anchored (proof unavailable)",
            }
        } else {
            ""
        };
        let label = if action.is_empty() {
            kind.to_string()
        } else {
            format!("{kind} {action}")
        };
        lines.push(format!("  {label:24} {} {mark}", &id[..id.len().min(20)]));
    }

    // Completeness against the agent's committed evidence_anchor.
    let committed_count = log
        .get("committed_anchor")
        .and_then(|c| c.get("receipt_count"))
        .and_then(|v| v.as_u64());
    let observed = entries.len() as u64;
    let completeness = match committed_count {
        Some(c) if observed >= c => format!("complete (committed {c}, observed {observed})"),
        Some(c) => format!("OMISSION — committed {c}, observed {observed}"),
        None => format!("no committed anchor (observed {observed})"),
    };

    // Witness the current checkpoint against what we have seen before: catch a
    // Hub that equivocates (two roots at one tree_size) or regresses.
    let (consistency, anomaly, prior_witness) = match &current_cp {
        Some(cp) => witness_checkpoint(base, cp),
        None => ("no verified checkpoint to witness".to_string(), false, None),
    };

    // 3b: cryptographic append-only. When the checkpoint advanced past a prior
    // witness, fetch the Hub's consistency chain and re-verify it proves the
    // current tree extends the one we last witnessed (no rewrite).
    let (append_only, append_anomaly) = match (&current_cp, &prior_witness) {
        (Some(cp), Some(p)) if cp.tree_size > p.tree_size => {
            verify_consistency_chain(base, &cp.signer, p.tree_size, &p.root, cp.tree_size, &cp.root)
        }
        (Some(_), Some(_)) => ("append-only: no new checkpoints since last audit".to_string(), false),
        (Some(_), None) => ("append-only: first witness, nothing to extend from yet".to_string(), false),
        _ => ("append-only: no checkpoint to prove".to_string(), false),
    };

    let omission = committed_count.is_some_and(|c| observed < c);
    let hostile = omission || invalid > 0 || anomaly || append_anomaly;

    // JSON mode: ONE structured verdict object (the text path streams
    // success + N warn objects, which is unparseable as a JSON document).
    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "verdict": if hostile { "ANOMALY" } else { "clean" },
            "ok": !hostile,
            "agent": agent,
            "hub": base,
            "receipts": observed,
            "anchored": anchored,
            "anchored_verified": verified,
            "anchored_invalid": invalid,
            "completeness": completeness,
            "omission": omission,
            "consistency": consistency,
            "equivocation_or_regression": anomaly,
            "append_only": append_only,
            "append_only_failed": append_anomaly,
            "entries": entries.iter().map(|e| serde_json::json!({
                "artifact_id": e.get("artifact_id"),
                "kind": e.get("kind"),
                "action": e.get("action"),
                "anchored": e.get("merkle_anchor").map(|v| !v.is_null()).unwrap_or(false),
            })).collect::<Vec<_>>(),
        }));
        return Ok(hostile);
    }

    let receipts_str = observed.to_string();
    let anchored_str = format!("{verified}/{anchored} verified");
    printer.success(
        "agent audit (remote)",
        &[
            ("agent", agent),
            ("hub", base),
            ("receipts", &receipts_str),
            ("anchored", &anchored_str),
            ("completeness", &completeness),
            ("consistency", &consistency),
            ("append-only", &append_only),
        ],
    );
    if committed_count.is_some_and(|c| observed < c) {
        printer.warn(
            "history is incomplete vs the agent's committed anchor",
            &[("completeness", &completeness)],
        );
    }
    if anomaly {
        printer.warn(
            "the hub's checkpoint contradicts a previously witnessed one",
            &[("consistency", &consistency)],
        );
    }
    if append_anomaly {
        printer.warn(
            "the hub could not prove the log only appended — possible history rewrite",
            &[("append-only", &append_only)],
        );
    }
    printer.blank();
    if lines.is_empty() {
        printer.hint("no history for this agent on the hub.");
    } else {
        printer.info("timeline (newest first):");
        for line in &lines {
            printer.info(line);
        }
    }
    printer.blank();
    printer.hint(
        "metadata + anchors only, never payloads. each anchored entry's inclusion is re-verified offline against your trust roots; completeness is checked against the agent's committed evidence_anchor (omission detectable for committed sets, not absolute). consistency witnesses the checkpoint across audits to catch a forking/regressing hub; append-only re-verifies the hub's Merkle consistency chain offline to prove the log only appended since you last witnessed it (no rewrite).",
    );
    printer.blank();
    Ok(hostile)
}

/// Fetch one artifact's Merkle proof from the Hub and re-verify it offline:
/// the checkpoint signature against our trust roots + inclusion in the signed
/// root. Returns `(both-hold, checkpoint)` so the caller can also witness the
/// checkpoint when it is fully verified.
pub(crate) fn verify_inclusion(base: &str, artifact_id: &str, trust: &TrustRootStore) -> CmdResult2 {
    let pf: ProofFile = ureq::get(&format!("{base}/v1/merkle/{artifact_id}"))
        .call()?
        .into_json()?;
    let cp_ok = pf.checkpoint.verify(trust);
    let root_hex = pf
        .checkpoint
        .root
        .strip_prefix("sha256:")
        .unwrap_or(&pf.checkpoint.root);
    let incl_ok = MerkleTree::verify_proof(
        pf.checkpoint.merkle_version,
        root_hex,
        &pf.artifact_id,
        &pf.inclusion_proof,
    );
    Ok((cp_ok && incl_ok, pf.checkpoint))
}

type CmdResult2 = Result<(bool, Checkpoint), Box<dyn std::error::Error>>;

/// Witness `current` against the persisted record for its `(hub, signer)`, then
/// update the record when the checkpoint advanced. Returns a human-readable
/// consistency line and whether an anomaly was detected (so the caller can
/// warn). Honest framing: this catches equivocation and regression; it does not
/// cryptographically prove append-only (that is the consistency proof, 3b).
/// Returns `(line, anomaly, prior)`. `prior` is the record as it was BEFORE
/// this audit (so the caller can verify a consistency chain from it to
/// `current`), even though the record may have just been advanced on disk.
fn witness_checkpoint(base: &str, current: &Checkpoint) -> (String, bool, Option<WitnessRecord>) {
    let path = match witness_path(base, &current.signer) {
        Ok(p) => p,
        Err(e) => return (format!("witness unavailable ({e})"), false, None),
    };
    let prior = load_witness(&path);
    let (line, anomaly, should_save) =
        witness_decision(prior.as_ref(), current.tree_size, &current.root, current.index);
    if should_save {
        let rec = WitnessRecord {
            tree_size: current.tree_size,
            root:      current.root.clone(),
            index:     current.index,
            signed_at: current.signed_at.clone(),
            signer:    current.signer.clone(),
        };
        if let Err(e) = save_witness(&path, &rec) {
            return (format!("{line}; (could not persist witness: {e})"), anomaly, prior);
        }
    }
    (line, anomaly, prior)
}

/// One link of a consistency chain as served by the Hub. The Hub stores these
/// verbatim from the publisher; this client re-verifies every one offline.
#[derive(serde::Deserialize)]
struct ChainLink {
    from_size: usize,
    from_root: String,
    to_size:   usize,
    to_root:   String,
    version:   u8,
    proof_json: String,
}

fn strip_sha(s: &str) -> &str {
    s.strip_prefix("sha256:").unwrap_or(s)
}

/// Verify, offline, that the current checkpoint's tree **extends** the one we
/// last witnessed, fetching the Hub's consistency chain and re-verifying every
/// link. Returns `(line, anomaly)`. anomaly is true ONLY when the Hub served a
/// chain that fails to prove the extension (a possible rewrite); a missing
/// chain is reported honestly but is not an anomaly (the publisher may simply
/// not have pushed proofs yet).
///
/// Four properties are enforced so a malicious Hub cannot pass a valid-but-
/// irrelevant chain: it must START at the witnessed `(size, root)`, every link's
/// proof must verify, links must be CONTIGUOUS, and it must END at the current
/// checkpoint.
fn verify_consistency_chain(
    base: &str,
    signer: &str,
    from_size: usize,
    from_root: &str,
    to_size: usize,
    to_root: &str,
) -> (String, bool) {
    let resp: serde_json::Value = match ureq::get(&format!("{base}/v1/merkle/consistency"))
        .query("signer", signer)
        .query("from", &from_size.to_string())
        .call()
        .and_then(|r| r.into_json().map_err(Into::into))
    {
        Ok(v) => v,
        Err(_) => return ("append-only: consistency endpoint unavailable".to_string(), false),
    };
    let links: Vec<ChainLink> = resp
        .get("chain")
        .and_then(|c| serde_json::from_value(c.clone()).ok())
        .unwrap_or_default();
    verify_chain_links(&links, from_size, from_root, to_size, to_root)
}

/// Pure verification of a fetched consistency chain, split from IO so it is
/// unit-testable. Enforces the four properties (start at the witnessed point,
/// every link's proof valid, contiguous, ends at the current checkpoint).
fn verify_chain_links(
    links: &[ChainLink],
    from_size: usize,
    from_root: &str,
    to_size: usize,
    to_root: &str,
) -> (String, bool) {
    if links.is_empty() {
        return (
            format!("append-only NOT PROVEN — no consistency proof published from tree_size {from_size} (publisher has not pushed one)"),
            false,
        );
    }

    let (mut cur_size, mut cur_root) = (from_size, strip_sha(from_root).to_string());
    let mut verified_links = 0usize;
    for link in links {
        if verified_links > 100_000 {
            return ("append-only INVALID — consistency chain too long".to_string(), true);
        }
        // Contiguity: this link must start exactly where the previous one ended
        // (and the first link at the witnessed point).
        if link.from_size != cur_size || strip_sha(&link.from_root) != cur_root {
            return (
                format!("append-only INVALID — chain not contiguous at tree_size {cur_size} (possible rewrite)"),
                true,
            );
        }
        let proof: Vec<String> = match serde_json::from_str(&link.proof_json) {
            Ok(p) => p,
            Err(_) => return ("append-only INVALID — malformed proof in chain".to_string(), true),
        };
        if !verify_consistency(
            link.version,
            link.from_size,
            strip_sha(&link.from_root),
            link.to_size,
            strip_sha(&link.to_root),
            &proof,
        ) {
            return (
                format!("append-only INVALID — consistency proof failed for #{}→#{} (possible rewrite)", link.from_size, link.to_size),
                true,
            );
        }
        cur_size = link.to_size;
        cur_root = strip_sha(&link.to_root).to_string();
        verified_links += 1;
        if cur_size >= to_size {
            break;
        }
    }

    // The chain must reach the current checkpoint exactly.
    if cur_size != to_size || cur_root != strip_sha(to_root) {
        return (
            format!("append-only INVALID — chain ends at tree_size {cur_size}, not the current {to_size}"),
            true,
        );
    }
    (
        format!("append-only VERIFIED — current tree cryptographically extends tree_size {from_size} ({verified_links} link(s), no rewrite)"),
        false,
    )
}

/// Pure witness decision, split from IO so it is unit-testable. Compares the
/// current checkpoint `(size, root, index)` to the prior witnessed record and
/// returns `(line, anomaly, should_save)`. On an anomaly the prior record is
/// kept (not overwritten), so the contradicting evidence is not lost.
fn witness_decision(
    prior: Option<&WitnessRecord>,
    cur_size: usize,
    cur_root: &str,
    cur_index: u64,
) -> (String, bool, bool) {
    match prior {
        // Equivocation: the same tree size now shows a different root. A log
        // that does this has presented two contradictory views -- a fork.
        Some(p) if p.tree_size == cur_size && p.root != cur_root => (
            format!(
                "FORK DETECTED — two different roots at tree_size {cur_size} (was {}, now {})",
                short(&p.root),
                short(cur_root),
            ),
            true,
            false,
        ),
        // Regression: the tree shrank. Append-only logs never do this.
        Some(p) if cur_size < p.tree_size => (
            format!("REGRESSION — tree_size went backwards {} → {cur_size} (history shrank)", p.tree_size),
            true,
            false,
        ),
        // Unchanged: same size, same root. Nothing new since last witness.
        Some(p) if p.tree_size == cur_size => (
            format!("consistent (unchanged at checkpoint #{cur_index}, tree_size {cur_size})"),
            false,
            false,
        ),
        // Monotonic growth. Append-only *so far as witnessing can tell*: no
        // equivocation, the tree only grew. The cryptographic proof that the
        // new tree extends the old (no silent rewrite) is the consistency
        // proof, slice 3b -- not claimed here.
        Some(p) => (
            format!(
                "consistent (witnessed #{} → #{cur_index}, tree_size {} → {cur_size}, monotonic; cryptographic append-only proof is slice 3b)",
                p.index, p.tree_size
            ),
            false,
            true,
        ),
        None => (
            format!("first witness (checkpoint #{cur_index}, tree_size {cur_size})"),
            false,
            true,
        ),
    }
}

fn short(s: &str) -> String {
    let h = s.strip_prefix("sha256:").unwrap_or(s);
    h.chars().take(12).collect()
}

#[cfg(test)]
mod witness_tests {
    use super::{witness_decision, WitnessRecord};

    fn rec(tree_size: usize, root: &str, index: u64) -> WitnessRecord {
        WitnessRecord {
            tree_size,
            root: root.into(),
            index,
            signed_at: "2026-01-01T00:00:00Z".into(),
            signer: "key_x".into(),
        }
    }

    #[test]
    fn first_witness_saves_no_anomaly() {
        let (line, anomaly, save) = witness_decision(None, 5, "sha256:aa", 0);
        assert!(!anomaly && save);
        assert!(line.contains("first witness"));
    }

    #[test]
    fn monotonic_growth_saves_no_anomaly() {
        let p = rec(5, "sha256:aa", 0);
        let (line, anomaly, save) = witness_decision(Some(&p), 9, "sha256:bb", 1);
        assert!(!anomaly && save);
        assert!(line.contains("monotonic"));
    }

    #[test]
    fn unchanged_does_not_save_no_anomaly() {
        let p = rec(5, "sha256:aa", 0);
        let (line, anomaly, save) = witness_decision(Some(&p), 5, "sha256:aa", 0);
        assert!(!anomaly && !save);
        assert!(line.contains("unchanged"));
    }

    #[test]
    fn equivocation_is_anomaly_and_does_not_overwrite() {
        // Same tree_size, different root -> a fork. Must flag and NOT save
        // (keep the prior so the contradiction is preserved).
        let p = rec(5, "sha256:aa", 0);
        let (line, anomaly, save) = witness_decision(Some(&p), 5, "sha256:bb", 0);
        assert!(anomaly && !save);
        assert!(line.contains("FORK DETECTED"));
    }

    #[test]
    fn regression_is_anomaly_and_does_not_overwrite() {
        let p = rec(9, "sha256:bb", 1);
        let (line, anomaly, save) = witness_decision(Some(&p), 5, "sha256:aa", 0);
        assert!(anomaly && !save);
        assert!(line.contains("REGRESSION"));
    }
}

#[cfg(test)]
mod chain_tests {
    use super::{verify_chain_links, ChainLink};
    use treeship_core::merkle::MerkleTree;

    const IDS: &[&str] = &["a", "b", "c", "d", "e", "f", "g", "h"];

    fn root(n: usize) -> String {
        let mut t = MerkleTree::new();
        for id in &IDS[..n] {
            t.append(id);
        }
        hex::encode(t.root().unwrap())
    }

    // A real consistency link from size m to size n, generated exactly as the
    // publish side does (consistency_proof over the size-n tree).
    fn link(m: usize, n: usize) -> ChainLink {
        let mut t = MerkleTree::new();
        for id in &IDS[..n] {
            t.append(id);
        }
        let proof = t.consistency_proof(m).unwrap();
        ChainLink {
            from_size: m,
            from_root: root(m),
            to_size: n,
            to_root: root(n),
            version: t.version(),
            proof_json: serde_json::to_string(&proof).unwrap(),
        }
    }

    #[test]
    fn single_link_verifies() {
        let (line, anomaly) = verify_chain_links(&[link(2, 8)], 2, &root(2), 8, &root(8));
        assert!(!anomaly, "{line}");
        assert!(line.contains("VERIFIED"));
    }

    #[test]
    fn multi_link_chain_verifies() {
        let (line, anomaly) =
            verify_chain_links(&[link(2, 5), link(5, 8)], 2, &root(2), 8, &root(8));
        assert!(!anomaly, "{line}");
        assert!(line.contains("VERIFIED"));
    }

    #[test]
    fn non_contiguous_chain_rejected() {
        // gap: second link starts at 6, not 5.
        let (line, anomaly) =
            verify_chain_links(&[link(2, 5), link(6, 8)], 2, &root(2), 8, &root(8));
        assert!(anomaly, "{line}");
        assert!(line.contains("not contiguous"));
    }

    #[test]
    fn wrong_start_rejected() {
        // Chain proves 2->8 but we witnessed size 3.
        let (_l, anomaly) = verify_chain_links(&[link(2, 8)], 3, &root(3), 8, &root(8));
        assert!(anomaly);
    }

    #[test]
    fn short_of_endpoint_rejected() {
        // Chain reaches 5, current checkpoint claims 8.
        let (line, anomaly) = verify_chain_links(&[link(2, 5)], 2, &root(2), 8, &root(8));
        assert!(anomaly, "{line}");
        assert!(line.contains("ends at"));
    }

    #[test]
    fn wrong_current_root_rejected() {
        // The link verifies 2->8 internally, but the current checkpoint root we
        // hold differs -- the hub served a valid chain for a different head.
        let bogus = "ab".repeat(32);
        let (_l, anomaly) = verify_chain_links(&[link(2, 8)], 2, &root(2), 8, &bogus);
        assert!(anomaly);
    }

    #[test]
    fn tampered_proof_rejected() {
        let mut l = link(2, 8);
        l.proof_json = serde_json::to_string(&vec!["00".repeat(32)]).unwrap();
        let (_l, anomaly) = verify_chain_links(&[l], 2, &root(2), 8, &root(8));
        assert!(anomaly);
    }

    #[test]
    fn empty_chain_not_proven_but_not_anomaly() {
        let (line, anomaly) = verify_chain_links(&[], 2, &root(2), 8, &root(8));
        assert!(!anomaly);
        assert!(line.contains("NOT PROVEN"));
    }
}
