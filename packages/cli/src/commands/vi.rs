//! `treeship vi`: Verifiable Intent (v0.1 draft) credentials with a Treeship
//! attestation inside them.
//!
//! An independent implementation against the open spec. The agent's P-256
//! key is generated here and sealed by the ship keystore; the user's wallet
//! binds its public JWK under `cnf` in a Layer 2 mandate; `check` asks
//! whether a purchase fits that mandate; `attest` signs the Layer 3 pair
//! (L3a for the network, L3b for the merchant) with the spec's optional
//! `agent_attestation` claim filled by a signed statement chained onto the
//! agent's receipt chain; `verify` checks a pair the way the reference
//! verifier does, then checks the attestation and, with `--local`, the chain
//! it names.

use std::path::{Path, PathBuf};

use serde_json::Value;
use treeship_core::{
    attestation::Envelope,
    journal::{self, Journal},
    merkle::MerkleTree,
    statements::approval_use_record_digest,
    storage::Record,
    vi::{
        self, build_attestation_claim, build_l3, keys as vikeys, l3::check_request,
        verify_l2_against_l1, verify_l3, AgentKey, AttestationStatement, L2View, L3Request,
        LineItem, SdJwt,
    },
};

use crate::{
    ctx,
    printer::{Format, Printer},
};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC 3339 UTC, seconds precision, no external crate.
fn rfc3339_now() -> String {
    let secs = unix_now() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Read a credential from a path, or `-` for stdin; whitespace trimmed.
fn read_text(arg: &str) -> Result<String, Box<dyn std::error::Error>> {
    if arg == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        return Ok(s.trim().to_string());
    }
    let p = Path::new(arg);
    if p.exists() {
        return Ok(std::fs::read_to_string(p)?.trim().to_string());
    }
    // A serialized SD-JWT pasted inline.
    if arg.contains('.') && arg.split('.').count() >= 3 {
        return Ok(arg.trim().to_string());
    }
    Err(format!("no such file: {arg}").into())
}

fn read_json(arg: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let text = read_text(arg)?;
    Ok(serde_json::from_str(&text)?)
}

fn parse_items(items: &[String]) -> Result<Vec<LineItem>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for raw in items {
        let (id, qty) = match raw.rsplit_once(':') {
            Some((id, q)) if q.chars().all(|c| c.is_ascii_digit()) && !q.is_empty() => {
                (id, q.parse::<u32>()?)
            }
            _ => (raw.as_str(), 1),
        };
        if id.is_empty() {
            return Err("--item needs a product id".into());
        }
        out.push(LineItem {
            id: id.to_string(),
            quantity: qty,
        });
    }
    Ok(out)
}

fn journal_for(config_path: &Path) -> Journal {
    Journal::new(
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("journals")
            .join("approval-use"),
    )
}

fn read_last(storage_dir: &str) -> Option<String> {
    let s = std::fs::read_to_string(Path::new(storage_dir).join(".last")).ok()?;
    let t = s.trim().to_string();
    (!t.is_empty()).then_some(t)
}

fn write_last(storage_dir: &str, artifact_id: &str) {
    let last_path = Path::new(storage_dir).join(".last");
    let _ = std::fs::write(&last_path, artifact_id);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&last_path, std::fs::Permissions::from_mode(0o600));
    }
}

fn envelope_payload(env: &Envelope) -> Option<Value> {
    let bytes = vi::jws::b64u_decode(&env.payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The chain from `head` back to `stop` (exclusive of nothing: `stop` is
/// included when reached) or to the first artifact without a parent, capped
/// at `max`. Returned root-first, with each record.
fn walk_chain(
    ctx: &ctx::Ctx,
    head: &str,
    stop: Option<&str>,
    max: usize,
) -> Result<Vec<Record>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut cursor = Some(head.to_string());
    while let Some(id) = cursor {
        if out.len() >= max {
            break;
        }
        let rec = ctx
            .storage
            .read(&id)
            .map_err(|e| format!("artifact {id} not in local storage: {e}"))?;
        let parent = rec.parent_id.clone();
        let is_stop = stop.map(|s| s == id).unwrap_or(false);
        out.push(rec);
        if is_stop {
            break;
        }
        cursor = parent;
    }
    out.reverse();
    Ok(out)
}

fn merkle_root(ids: &[String]) -> String {
    let mut tree = MerkleTree::new();
    for id in ids {
        tree.append(id);
    }
    tree.root()
        .map(|r| format!("mroot_{}", hex::encode(r)))
        .unwrap_or_else(|| "mroot_empty".into())
}

/// The most recent approval use the chain consumed, as its record digest.
fn latest_approval_use(ctx: &ctx::Ctx, chain: &[Record]) -> Option<(String, String)> {
    let j = journal_for(&ctx.config_path);
    for rec in chain.iter().rev() {
        let Some(payload) = envelope_payload(&rec.envelope) else {
            continue;
        };
        let Some(use_id) = payload
            .get("meta")
            .and_then(|m| m.get("approval_use_id"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if let Ok(Some(u)) = journal::find_use_by_id(&j, use_id) {
            return Some((use_id.to_string(), approval_use_record_digest(&u)));
        }
    }
    None
}

fn load_key(ctx: &ctx::Ctx, kid: Option<&str>) -> Result<AgentKey, Box<dyn std::error::Error>> {
    let keys_dir = Path::new(&ctx.config.keys_dir);
    let kid = match kid {
        Some(k) => k.to_string(),
        None => vikeys::default_agent_key(keys_dir)?.kid,
    };
    Ok(vikeys::load_agent_key(keys_dir, &ctx.keys, &kid)?)
}

// ---------------------------------------------------------------------------
// keygen / keys
// ---------------------------------------------------------------------------

pub fn keygen(label: Option<&str>, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let key = AgentKey::generate();
    let path = vikeys::save_agent_key(
        Path::new(&ctx.config.keys_dir),
        &ctx.keys,
        &key,
        label,
        &rfc3339_now(),
    )?;
    let jwk = key.public_jwk().to_value();
    if printer.format == Format::Json {
        printer.json(
            &serde_json::json!({"status":"ok","kid": key.kid, "public_jwk": jwk, "path": path}),
        );
        return Ok(());
    }
    printer.success(
        "VI agent key generated (P-256, ES256)",
        &[("kid", &key.kid), ("path", &path.display().to_string())],
    );
    printer.blank();
    printer.info(
        "  public JWK, for the wallet that issues the Layer 2 mandate (binds it under cnf.jwk):",
    );
    printer.info(&format!("  {}", serde_json::to_string(&jwk)?));
    printer.blank();
    printer.hint("the private scalar is sealed by this ship's keystore; `treeship vi keys export` reprints the public half");
    Ok(())
}

pub fn keys_list(config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let all = vikeys::list_agent_keys(Path::new(&ctx.config.keys_dir))?;
    if printer.format == Format::Json {
        let rows: Vec<Value> = all
            .iter()
            .map(|k| serde_json::json!({"kid": k.kid, "created_at": k.created_at, "label": k.label, "public_jwk": k.public_jwk}))
            .collect();
        printer.json(&serde_json::json!({"status":"ok","keys": rows}));
        return Ok(());
    }
    if all.is_empty() {
        printer.info("no VI keys");
        printer.hint("treeship vi keygen");
        return Ok(());
    }
    printer.section("VI agent keys (P-256)");
    for k in all {
        printer.info(&format!(
            "  {}  {}  {}",
            k.kid,
            k.created_at,
            k.label.unwrap_or_default()
        ));
    }
    Ok(())
}

pub fn keys_export(kid: Option<&str>, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let keys_dir = Path::new(&ctx.config.keys_dir);
    let stored = match kid {
        Some(k) => vikeys::read_stored(keys_dir, k)?,
        None => vikeys::default_agent_key(keys_dir)?,
    };
    let jwk = stored.public_jwk.to_value();
    if printer.format == Format::Json {
        printer.json(&serde_json::json!({"status":"ok","kid": stored.kid, "public_jwk": jwk}));
        return Ok(());
    }
    println!("{}", serde_json::to_string(&jwk)?);
    Ok(())
}

pub fn keys_import(
    jwk_path: &str,
    label: Option<&str>,
    config: Option<&str>,
    printer: &Printer,
) -> CmdResult {
    let ctx = ctx::open(config)?;
    let v = read_json(jwk_path)?;
    let key = AgentKey::from_private_jwk(&v)?;
    let path = vikeys::save_agent_key(
        Path::new(&ctx.config.keys_dir),
        &ctx.keys,
        &key,
        label,
        &rfc3339_now(),
    )?;
    if printer.format == Format::Json {
        printer.json(&serde_json::json!({"status":"ok","kid": key.kid, "public_jwk": key.public_jwk().to_value(), "path": path}));
        return Ok(());
    }
    printer.success(
        "VI agent key imported and sealed",
        &[("kid", &key.kid), ("path", &path.display().to_string())],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

pub struct PurchaseArgs<'a> {
    pub mandate: &'a str,
    pub merchant: &'a str,
    pub items: &'a [String],
    pub amount: i64,
    pub currency: &'a str,
}

fn request_from(
    l2: &L2View,
    p: &PurchaseArgs<'_>,
    checkout_jwt: &str,
    aud_network: &str,
    aud_merchant: &str,
    iss: Option<&str>,
    exp_secs: u64,
    attestation: Option<Value>,
) -> Result<L3Request, Box<dyn std::error::Error>> {
    let payee = l2.find_allowed_merchant(p.merchant).ok_or_else(|| {
        format!(
            "merchant '{}' is not in the mandate's allowed merchants or payees",
            p.merchant
        )
    })?;
    let now = unix_now();
    Ok(L3Request {
        nonce: vi::jws::b64u(&rand_bytes(16)),
        iat: now,
        exp: now + exp_secs,
        iss: iss.map(str::to_string),
        aud_network: aud_network.to_string(),
        aud_merchant: aud_merchant.to_string(),
        payee,
        payment_amount: serde_json::json!({"currency": p.currency, "amount": p.amount}),
        checkout_jwt: checkout_jwt.to_string(),
        line_items: parse_items(p.items)?,
        attestation,
    })
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn check(p: &PurchaseArgs<'_>, config: Option<&str>, printer: &Printer) -> CmdResult {
    let _ctx = ctx::open(config)?;
    let l2 = L2View::parse(&read_text(p.mandate)?)?;
    let req = request_from(&l2, p, "", "urn:check", "urn:check", None, 300, None)?;
    let result = check_request(&req, &l2);
    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "status": if result.satisfied { "ok" } else { "violation" },
            "satisfied": result.satisfied,
            "checked": result.checked, "violations": result.violations, "skipped": result.skipped,
            "mandate": {"autonomous": l2.autonomous, "agent_kid": l2.agent_kid},
        }));
    } else {
        printer.section("mandate check");
        for c in &result.checked {
            printer.info(&format!("  {} {c}", printer.green("PASS")));
        }
        for v in &result.violations {
            printer.info(&format!("  {} {v}", printer.red("FAIL")));
        }
        for s in &result.skipped {
            printer.info(&format!("  {} {s}", printer.yellow("SKIP")));
        }
        printer.blank();
        if result.satisfied {
            printer.success(
                "within the mandate",
                &[
                    ("merchant", p.merchant),
                    ("amount", &format!("{} {}", p.amount, p.currency)),
                ],
            );
        }
    }
    if !result.satisfied {
        return Err(format!("outside the mandate: {}", result.violations.join("; ")).into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// attest
// ---------------------------------------------------------------------------

pub struct AttestArgs<'a> {
    pub purchase: PurchaseArgs<'a>,
    pub checkout_jwt: &'a str,
    pub aud_network: &'a str,
    pub aud_merchant: &'a str,
    pub iss: Option<&'a str>,
    pub exp_secs: u64,
    pub key: Option<&'a str>,
    pub actor: Option<&'a str>,
    pub head: Option<&'a str>,
    pub session: Option<&'a str>,
    pub out: &'a str,
    pub no_receipt: bool,
}

pub fn attest(a: &AttestArgs<'_>, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let l2 = L2View::parse(&read_text(a.purchase.mandate)?)?;
    let key = load_key(&ctx, a.key)?;
    let checkout_jwt = read_text(a.checkout_jwt)?;

    // The chain this credential is minted at the end of.
    let manifest = crate::commands::session::load_session();
    let head = match a.head {
        Some(h) => h.to_string(),
        None => read_last(&ctx.config.storage_dir)
            .ok_or("no chain head: pass --head <artifact-id> or record something first")?,
    };
    let stop = manifest.as_ref().and_then(|m| m.root_artifact_id.clone());
    let chain = walk_chain(&ctx, &head, stop.as_deref(), 10_000)?;
    let ids: Vec<String> = chain.iter().map(|r| r.artifact_id.clone()).collect();
    let checkpoint = merkle_root(&ids);
    let approval = latest_approval_use(&ctx, &chain);
    // A chain that does not reach the session root is a chain with a gap
    // (an artifact signed without --parent, or a head from another
    // workspace). The attestation still names what it saw; say so.
    let reaches_root = match &stop {
        Some(root) => ids.first().map(|f| f == root).unwrap_or(false),
        None => true,
    };
    if !reaches_root {
        printer.warn(
            "the chain from this head does not reach the active session's root; the attestation covers only the linked artifacts",
            &[("head", &head), ("linked", &ids.len().to_string())],
        );
    }
    let session = a
        .session
        .map(str::to_string)
        .or_else(|| manifest.as_ref().map(|m| m.session_id.clone()));
    let actor = a
        .actor
        .map(str::to_string)
        .or_else(|| manifest.as_ref().map(|m| m.actor.clone()))
        .unwrap_or_else(|| "agent://vi".into());

    // The request, checked before anything is signed.
    let probe = request_from(
        &l2,
        &a.purchase,
        &checkout_jwt,
        a.aud_network,
        a.aud_merchant,
        a.iss,
        a.exp_secs,
        None,
    )?;
    let cr = check_request(&probe, &l2);
    if !cr.satisfied {
        return Err(format!(
            "refused: the request is outside the mandate: {}",
            cr.violations.join("; ")
        )
        .into());
    }
    let checkout_hash = vi::jws::sha256_b64u(checkout_jwt.as_bytes());
    let mandate_digest = vi::jws::sha256_b64u(l2.base_jwt().as_bytes());

    // The Treeship attestation: signed by the ship key, chained onto head.
    let stmt = AttestationStatement::new(
        &actor,
        session.clone(),
        &head,
        &checkpoint,
        ids.len() as u64,
        approval.as_ref().map(|(_, d)| d.clone()),
        &mandate_digest,
        &checkout_hash,
        &rfc3339_now(),
    );
    let signer = ctx.keys.default_signer()?;
    let (claim, signed) = build_attestation_claim(&stmt, signer.as_ref())?;
    if !a.no_receipt {
        let record = Record {
            artifact_id: signed.artifact_id.clone(),
            digest: signed.digest.clone(),
            payload_type: vi::attestation_payload_type(),
            key_id: signer.key_id().to_string(),
            signed_at: stmt.timestamp.clone(),
            parent_id: Some(head.clone()),
            envelope: signed.envelope.clone(),
            hub_url: None,
            anchors: Vec::new(),
        };
        ctx.storage.write(&record)?;
        write_last(&ctx.config.storage_dir, &signed.artifact_id);
    }

    let claim_v = serde_json::to_value(&claim)?;
    let req = L3Request {
        attestation: Some(claim_v.clone()),
        ..probe
    };
    let bundle = build_l3(&l2, &key, &req)?;

    let out = PathBuf::from(a.out);
    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("l3a.sdjwt"), bundle.l3a.serialize())?;
    std::fs::write(out.join("l3b.sdjwt"), bundle.l3b.serialize())?;
    std::fs::write(
        out.join("l2-payment.sdjwt"),
        &bundle.l2_payment_presentation,
    )?;
    std::fs::write(
        out.join("l2-checkout.sdjwt"),
        &bundle.l2_checkout_presentation,
    )?;
    std::fs::write(
        out.join("attestation.json"),
        serde_json::to_string_pretty(&claim_v)?,
    )?;
    let summary = serde_json::json!({
        "status": "ok",
        "out": out,
        "kid": key.kid,
        "checkout_hash": bundle.checkout_hash,
        "mandate_digest": mandate_digest,
        "attestation": {
            "artifact_id": signed.artifact_id,
            "key_id": signer.key_id(),
            "session": session,
            "chain_head": head,
            "chain_length": ids.len(),
            "checkpoint": checkpoint,
            "reaches_session_root": reaches_root,
            "approval_use_id": approval.as_ref().map(|(id, _)| id.clone()),
            "approval_use": approval.as_ref().map(|(_, d)| d.clone()),
            "recorded": !a.no_receipt,
        },
        "constraints": {"checked": cr.checked, "skipped": cr.skipped},
        "files": ["l3a.sdjwt", "l3b.sdjwt", "l2-payment.sdjwt", "l2-checkout.sdjwt", "attestation.json"],
    });
    std::fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(&summary)?,
    )?;

    if printer.format == Format::Json {
        printer.json(&summary);
        return Ok(());
    }
    printer.success(
        "Layer 3 credentials signed",
        &[
            ("out", &out.display().to_string()),
            ("transaction", &bundle.checkout_hash),
            ("attestation", &signed.artifact_id),
            (
                "chain",
                &format!(
                    "{} artifacts . {}",
                    ids.len(),
                    &checkpoint[..std::cmp::min(18, checkpoint.len())]
                ),
            ),
            (
                "approval",
                &approval
                    .as_ref()
                    .map(|(id, _)| id.clone())
                    .unwrap_or_else(|| "none in chain".into()),
            ),
        ],
    );
    printer.hint("l3a.sdjwt goes to the payment network with l2-payment.sdjwt; l3b.sdjwt to the merchant with l2-checkout.sdjwt");
    Ok(())
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

pub struct VerifyArgs<'a> {
    pub mandate: &'a str,
    pub l3a: Option<&'a str>,
    pub l3b: Option<&'a str>,
    pub l2_payment: Option<&'a str>,
    pub l2_checkout: Option<&'a str>,
    pub l1: Option<&'a str>,
    pub issuer_jwk: Option<&'a str>,
    pub local: bool,
    pub require_attestation: bool,
}

pub fn verify(v: &VerifyArgs<'_>, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let l2_text = read_text(v.mandate)?;
    let l2 = L2View::parse(&l2_text)?;
    let l3a = v
        .l3a
        .map(read_text)
        .transpose()?
        .map(|t| SdJwt::parse(&t))
        .transpose()?;
    let l3b = v
        .l3b
        .map(read_text)
        .transpose()?
        .map(|t| SdJwt::parse(&t))
        .transpose()?;
    if l3a.is_none() && l3b.is_none() {
        return Err("pass --l3a and/or --l3b".into());
    }
    let pay_pres = v.l2_payment.map(read_text).transpose()?;
    let chk_pres = v.l2_checkout.map(read_text).transpose()?;
    let now = unix_now();

    let mut checks = Vec::new();
    if let Some(l1_arg) = v.l1 {
        let l1 = SdJwt::parse(&read_text(l1_arg)?)?;
        let issuer = v
            .issuer_jwk
            .map(read_json)
            .transpose()?
            .map(|j| vi::Jwk::from_value(&j))
            .transpose()?;
        let r1 = verify_l2_against_l1(&l1, &l2.sd_jwt, issuer.as_ref(), now);
        checks.extend(r1.checks);
    }
    let mut report = verify_l3(
        &l2,
        l3a.as_ref(),
        l3b.as_ref(),
        pay_pres.as_deref(),
        chk_pres.as_deref(),
        now,
    );
    checks.append(&mut report.checks);
    report.checks = checks;

    if v.require_attestation && report.attestation.is_none() {
        report.checks.push(vi::Check {
            name: "attestation_required".into(),
            pass: false,
            detail: "no Treeship attestation on the credential".into(),
        });
    }
    if v.local {
        match &report.attestation {
            None => report.checks.push(vi::Check {
                name: "local_chain".into(),
                pass: false,
                detail: "no attestation to check locally".into(),
            }),
            Some(att) => {
                let head_ok = ctx.storage.read(&att.chain_head).is_ok();
                report.checks.push(vi::Check {
                    name: "local_chain_head".into(),
                    pass: head_ok,
                    detail: format!("{} in local storage", att.chain_head),
                });
                if head_ok {
                    match walk_chain(&ctx, &att.chain_head, None, att.chain_length as usize) {
                        Ok(chain) => {
                            let ids: Vec<String> =
                                chain.iter().map(|r| r.artifact_id.clone()).collect();
                            let root = merkle_root(&ids);
                            report.checks.push(vi::Check { name: "local_checkpoint".into(), pass: root == att.checkpoint, detail: format!("Merkle root over {} local artifacts recomputes to the attested checkpoint", ids.len()) });
                        }
                        Err(e) => report.checks.push(vi::Check {
                            name: "local_checkpoint".into(),
                            pass: false,
                            detail: e.to_string(),
                        }),
                    }
                }
                let art_ok = ctx.storage.read(&att.artifact_id).is_ok();
                report.checks.push(vi::Check {
                    name: "local_attestation_artifact".into(),
                    pass: art_ok,
                    detail: format!("{} in local storage", att.artifact_id),
                });
                if let Some(d) = &att.approval_use {
                    report.checks.push(vi::Check {
                        name: "attestation_approval_use".into(),
                        pass: true,
                        detail: format!(
                            "names approval use {d}; check it with treeship approval uses <grant>"
                        ),
                    });
                }
            }
        }
    }

    let ok = report.ok();
    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "status": if ok { "pass" } else { "fail" },
            "outcome": if ok { "pass" } else { "fail" },
            "passed": report.passed(), "failed": report.failed(),
            "checks": report.checks, "attestation": report.attestation, "checkout_hash": report.checkout_hash,
        }));
    } else {
        printer.section("verifiable intent");
        for c in &report.checks {
            let tag = if c.pass {
                printer.green("PASS")
            } else {
                printer.red("FAIL")
            };
            printer.info(&format!("  {tag} {} -- {}", c.name, c.detail));
        }
        printer.blank();
        if let Some(att) = &report.attestation {
            printer.info(&format!(
                "  attestation:  {}  signed by {}",
                att.artifact_id, att.key_id
            ));
            printer.info(&format!(
                "  session:      {}",
                att.session.clone().unwrap_or_else(|| "(none)".into())
            ));
            printer.info(&format!(
                "  chain head:   {}  ({} artifacts)",
                att.chain_head, att.chain_length
            ));
            printer.info(&format!("  checkpoint:   {}", att.checkpoint));
            printer.info(&format!(
                "  approval use: {}",
                att.approval_use.clone().unwrap_or_else(|| "none".into())
            ));
            printer.info(&format!("  key:          {}", att.public_key));
            printer.dim_info("  not checked here: whether that key is one you trust. Pin it with `treeship trust add` and verify the chain with `treeship verify <chain head>` on a package or bundle from the producer.");
            printer.blank();
        }
        let line = format!("{} passed, {} failed", report.passed(), report.failed());
        if ok {
            printer.success(&format!("verified  ({line})"), &[]);
        } else {
            printer.failure(&format!("verification failed  ({line})"), &[]);
        }
    }
    if !ok {
        return Err("verifiable intent verification failed".into());
    }
    Ok(())
}
