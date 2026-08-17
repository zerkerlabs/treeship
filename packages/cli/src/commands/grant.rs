//! `treeship grant` -- mint and inspect signed capability grants.
//!
//! v0.21 and v0.22 shipped the machinery to *verify* a delegation chain:
//! content-derived ids, signed parent links, order derived from those links
//! rather than trusted from the carrier, attenuation invariants. None of it was
//! reachable, because nothing could mint a grant. This is the other half.
//!
//! Two decisions worth stating, because both are load-bearing:
//!
//! **Attenuation is enforced at mint, not only at verify.** `--parent` refuses
//! to produce a grant that widens scope, outlives its parent, changes audience,
//! or exceeds the parent's `max_delegation`. A verifier catching that later is
//! the backstop; refusing to create it is the fix. An invalid chain that exists
//! is a chain someone will eventually be asked to trust.
//!
//! **Grants are workspace-scoped**, resolved relative to the active config the
//! same way the approval-use journal and cards are. A project-local Treeship
//! gets its own grants; the global config gets another set. The trust scope
//! stays honest -- these grants answer for the workspace they were minted in.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use treeship_core::statements::{
    parse_rfc3339_to_unix, payload_type, Grant, ReceiptStatement, RevocationSource,
    RevocationStatus,
};
use treeship_core::storage::Record;

use crate::ctx;
use crate::printer::{Format, Printer};

// The grant store's layout and read path live here and only here. `attest
// action --v2` loads grants through these rather than keeping its own copy:
// two definitions of "where grants live" agree right up until one of them
// changes.

/// `<config_dir>/grants/`, resolved from the active config so a project-local
/// Treeship answers for its own grants.
pub(crate) fn grants_dir_for(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("grants")
}

pub(crate) fn grant_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// Parse a grant without judging it. Used by `grant show`, whose whole job is
/// to report whether what is on disk is sound -- a loader that refused unsound
/// grants would leave the one command meant to diagnose them unable to open
/// them.
pub(crate) fn read_grant_unchecked(path: &Path) -> Result<Grant, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read grant file {}: {e}", path.display()))?;
    let g: Grant = serde_json::from_str(&raw).map_err(|e| {
        format!(
            "grant file is not valid Grant JSON ({}): {e}",
            path.display()
        )
    })?;
    Ok(g)
}

/// Parse a grant that is about to be *used*, refusing one whose declared id
/// does not match its content. A hand-chosen id cannot anchor a mandate chain:
/// a parent pointer to it names a string, not a grant.
pub(crate) fn read_grant_file(path: &Path) -> Result<Grant, Box<dyn std::error::Error>> {
    let g = read_grant_unchecked(path)?;
    if !g.id_is_consistent() {
        return Err(format!(
            "grant {} declares an id that does not match its content\n  \
             refused: a hand-chosen id cannot anchor a mandate chain",
            g.grant_id
        )
        .into());
    }
    Ok(g)
}

/// Load a grant by id from the workspace store, checked.
pub(crate) fn read_grant_id(dir: &Path, id: &str) -> Result<Grant, Box<dyn std::error::Error>> {
    let path = grant_path(dir, id);
    if !path.exists() {
        return Err(format!(
            "grant not found: {id}\n  looked in {}\n  mint one with: treeship grant issue …",
            dir.display()
        )
        .into());
    }
    read_grant_file(&path)
}

pub struct IssueArgs {
    pub scope: Vec<String>,
    pub audience: String,
    pub expiry: String,
    pub parent: Option<String>,
    pub max_delegation: u32,
    pub objective_hash: Option<String>,
    /// Public key entitled to exercise the grant. `None` mints a bearer grant,
    /// which `issue` warns about rather than silently producing.
    pub grantee: Option<String>,
    /// Bind the grant to the issuing workspace's own key. Convenience for the
    /// common self-grant case, so the safe path does not require pasting your
    /// own public key.
    pub grantee_self: bool,
    pub config: Option<String>,
}

/// Why a proposed child grant may not be minted from its parent.
///
/// Mirrors `GrantChainError`'s invariants deliberately: a grant this refuses is
/// exactly a grant `verify_grant_chain` would later reject, and catching it here
/// means the invalid artifact never exists to be presented to anyone.
fn attenuation_error(parent: &Grant, child: &Grant) -> Option<String> {
    if !child.scope.iter().all(|s| scope_covered(s, &parent.scope)) {
        return Some(format!(
            "scope widens: {:?} is not within the parent's {:?}",
            child.scope, parent.scope
        ));
    }
    match (
        parse_rfc3339_to_unix(&child.expiry),
        parse_rfc3339_to_unix(&parent.expiry),
    ) {
        (Some(c), Some(p)) if c > p => {
            return Some(format!(
                "expiry outlives the parent: {} is after {}",
                child.expiry, parent.expiry
            ))
        }
        (None, _) => return Some(format!("expiry does not parse: {}", child.expiry)),
        (_, None) => {
            return Some(format!(
                "the parent's expiry does not parse: {}",
                parent.expiry
            ))
        }
        _ => {}
    }
    if child.audience != parent.audience {
        return Some(format!(
            "audience changes: {} is not the parent's {}",
            child.audience, parent.audience
        ));
    }
    if child.delegation_depth > parent.max_delegation {
        return Some(format!(
            "delegation depth {} exceeds the parent's max_delegation {}",
            child.delegation_depth, parent.max_delegation
        ));
    }
    None
}

/// Whether `needle` is admitted by `haystack`, honouring a single trailing `*`.
/// Same shape as the core scope check; kept local so the mint-time refusal
/// cannot drift into being more permissive than the verifier.
fn scope_covered(needle: &str, haystack: &[String]) -> bool {
    haystack.iter().any(|allowed| {
        if let Some(prefix) = allowed.strip_suffix('*') {
            needle.starts_with(prefix)
        } else {
            allowed == needle
        }
    })
}

/// `treeship grant issue` -- mint a signed grant, optionally delegated from an
/// existing one.
pub fn issue(args: IssueArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    if args.scope.is_empty() {
        return Err("at least one --scope is required\n  example: --scope payments.charge".into());
    }
    if parse_rfc3339_to_unix(&args.expiry).is_none() {
        return Err(format!(
            "--expiry must be RFC 3339: {}\n  example: --expiry 2026-12-31T23:59:59Z",
            args.expiry
        )
        .into());
    }

    let ctx = ctx::open(args.config.as_deref())?;
    let signer = ctx.keys.default_signer()?;
    let dir = grants_dir_for(&ctx.config_path);
    std::fs::create_dir_all(&dir)?;

    let parent = match &args.parent {
        // Checked: we are about to delegate from this grant, so an
        // inconsistent id would produce a child pointing at nothing.
        Some(pid) => Some(read_grant_id(&dir, pid)?),
        None => None,
    };

    // Depth is derived from the parent, never accepted from the caller: a
    // self-declared depth inside the very chain being verified is the thing
    // `resolve_grant_chain` exists to stop trusting.
    let delegation_depth = parent.as_ref().map(|p| p.delegation_depth + 1).unwrap_or(0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let issued_at = format_rfc3339(now);

    let own_key = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());
    if args.grantee.is_some() && args.grantee_self {
        return Err("--grantee and --grantee-self are mutually exclusive".into());
    }
    let grantee = match (&args.grantee, args.grantee_self) {
        (Some(k), _) => Some(k.clone()),
        (None, true) => Some(own_key.clone()),
        (None, false) => None,
    };

    let mut g = Grant {
        grant_id: String::new(),
        grantor: own_key.clone(),
        grantee,
        issuer_sig: None,
        scope: args.scope.clone(),
        audience: args.audience.clone(),
        parent_request_id: None,
        parent_grant_id: parent.as_ref().map(|p| p.grant_id.clone()),
        delegation_depth,
        issued_at,
        expiry: args.expiry.clone(),
        max_delegation: args.max_delegation,
        objective_hash: args.objective_hash.clone(),
    };

    // A grant whose expiry has already passed is dead on arrival: it will fail
    // every window check it is ever presented to. Minting one is never
    // deliberate, and the failure would surface far from its cause.
    if let Some(exp) = parse_rfc3339_to_unix(&g.expiry) {
        if exp <= now {
            return Err(format!(
                "refusing to mint: --expiry {} is not in the future (now {})\n  \
                 a grant that has already expired can never verify",
                g.expiry, g.issued_at
            )
            .into());
        }
    }

    // Refuse to mint an invalid link. A chain that cannot pass verification
    // should not be creatable in the first place.
    if let Some(p) = &parent {
        if let Some(why) = attenuation_error(p, &g) {
            return Err(format!(
                "refusing to mint: a delegated grant may only narrow authority\n  {why}"
            )
            .into());
        }
    }

    // Id is derived from the signed bytes, then the signature covers those same
    // bytes. Order matters: deriving after signing would let the two disagree.
    g.grant_id = g.derive_grant_id();
    g.issuer_sig = Some(g.sign_canonical(signer.as_ref())?);

    debug_assert!(
        g.id_is_consistent(),
        "freshly minted grant must self-verify"
    );

    // Two grants with the same content have the same id -- that is what content
    // addressing means. `issued_at` is second-precision, so issuing the same
    // grant twice inside one second derives the same id and the second write
    // silently replaced the first. Five commands, five success lines, three
    // grants on disk.
    //
    // The honest behaviour is not a fresh id but an accurate report: this grant
    // already exists, and the caller now holds its id. Overwriting a signed
    // artifact while claiming to have issued a new one is the "success that did
    // not happen" this verifier exists to refuse.
    let path = grant_path(&dir, &g.grant_id);
    let already_existed = path.exists();
    if !already_existed {
        std::fs::write(&path, serde_json::to_string_pretty(&g)?)?;
    }

    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "grant_id": g.grant_id,
            "grantor": g.grantor,
            "scope": g.scope,
            "audience": g.audience,
            "expiry": g.expiry,
            "delegation_depth": g.delegation_depth,
            "parent_grant_id": g.parent_grant_id,
            "max_delegation": g.max_delegation,
            "path": path.display().to_string(),
            // Machine consumers must be able to tell "I created this" from "this
            // was already here", or a caller counting successful issuances
            // overcounts exactly the way the human output used to.
            "already_existed": already_existed,
        }));
        return Ok(());
    }

    let scope_str = g.scope.join(", ");
    let depth_str = g.delegation_depth.to_string();
    printer.success(
        &format!(
            "{}  {}",
            if already_existed {
                "grant already exists"
            } else {
                "grant issued"
            },
            g.grant_id
        ),
        &[
            ("scope", &scope_str),
            ("audience", &g.audience),
            ("expiry", &g.expiry),
            ("depth", &depth_str),
        ],
    );
    // A bearer grant is a legitimate mode, not an error -- but it is spendable
    // by anyone who obtains the file, and that has to be said out loud at the
    // moment it is created rather than discovered when someone else uses it.
    if !g.binds_holder() {
        printer.warn(
            "bearer grant: anyone holding this file can exercise it",
            &[(
                "bind it",
                "re-issue with --grantee-self, or --grantee <public-key>",
            )],
        );
    }
    printer.hint(&format!(
        "treeship grant issue --parent {} --scope <narrower>",
        g.grant_id
    ));
    Ok(())
}

/// `treeship grant list` -- every grant minted in this workspace.
pub fn list(config: Option<&str>, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let dir = grants_dir_for(&ctx.config_path);

    let mut grants: Vec<Grant> = Vec::new();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // A grant we cannot parse is reported by its absence from the list
            // rather than crashing the command; `show` will surface the error.
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(g) = serde_json::from_str::<Grant>(&raw) {
                    grants.push(g);
                }
            }
        }
    }
    grants.sort_by(|a, b| a.issued_at.cmp(&b.issued_at));

    // Listing grants without their revocation state showed a withdrawn grant
    // exactly like a live one. Built once and reused across every row rather
    // than per-grant, since it reads the whole receipt store.
    let revocations = crate::commands::revocation_source::for_ctx(&ctx);
    let state_of = |g: &Grant| revocations.status(&g.grant_id, "");

    if printer.format == Format::Json {
        let out: Vec<_> = grants
            .iter()
            .map(|g| {
                serde_json::json!({
                    "grant_id": g.grant_id,
                    "scope": g.scope,
                    "audience": g.audience,
                    "expiry": g.expiry,
                    "delegation_depth": g.delegation_depth,
                    "parent_grant_id": g.parent_grant_id,
                    "revocation": match state_of(g) {
                        RevocationStatus::NotRevoked => serde_json::json!({ "state": "not_revoked" }),
                        RevocationStatus::RevokedAt(at) => {
                            serde_json::json!({ "state": "revoked", "revoked_at": at })
                        }
                        RevocationStatus::Unknown(why) => {
                            serde_json::json!({ "state": "unknown", "reason": why })
                        }
                    },
                })
            })
            .collect();
        printer.json(&serde_json::json!({ "grants": out, "total": grants.len() }));
        return Ok(());
    }

    if grants.is_empty() {
        printer.info("no grants in this workspace");
        printer.hint("treeship grant issue --scope <s> --audience <a> --expiry <rfc3339>");
        return Ok(());
    }
    for g in &grants {
        // The marker goes first: scanning a list, the thing that changes
        // whether a row means anything should not be at the end of the line.
        let mark = match state_of(g) {
            RevocationStatus::NotRevoked => "",
            RevocationStatus::RevokedAt(_) => "REVOKED  ",
            RevocationStatus::Unknown(_) => "revocation unknown  ",
        };
        printer.info(&format!(
            "{}{}  depth {}  {}  expires {}",
            mark,
            g.grant_id,
            g.delegation_depth,
            g.scope.join(", "),
            g.expiry
        ));
    }
    printer.hint("treeship grant show <grant-id>");
    Ok(())
}

/// `treeship grant show <id>` -- one grant, with its id re-derived and its
/// signature re-checked rather than taken from the file.
pub fn show(
    id: &str,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let dir = grants_dir_for(&ctx.config_path);
    let path = grant_path(&dir, id);
    if !path.exists() {
        return Err(format!("grant not found: {id}\n  run: treeship grant list").into());
    }
    // Unchecked on purpose: this command reports soundness, so it has to be
    // able to open an unsound grant and say so. The checked loader is for
    // callers about to act on a grant.
    let g = read_grant_unchecked(&path)?;

    // Re-verify rather than trust the file. A grant on disk is just bytes, and
    // the point of a content-derived id is that it can be checked.
    let id_ok = g.id_is_consistent();
    let sig_ok = g
        .issuer_sig
        .as_deref()
        .map(|s| g.verify_canonical(s))
        .unwrap_or(false);

    // A grant's signature stays valid forever; revocation is what makes it
    // stop counting. `show` reported the signature and never the revocation,
    // so a grant revoked seconds earlier printed a clean success -- the
    // command whose whole job is "tell me about this grant" was the one
    // surface that never looked.
    //
    // `for_ctx` is the same resolver `verify` uses: it reads local
    // `grant_revocation.v1` receipts and verifies their signatures rather
    // than trusting a filename.
    let revocation = crate::commands::revocation_source::for_ctx(&ctx).status(&g.grant_id, "");
    let revocation_str = match &revocation {
        RevocationStatus::NotRevoked => "not revoked".to_string(),
        RevocationStatus::RevokedAt(at) => format!("REVOKED at {at}"),
        // Unknown is not "fine". It says the question could not be answered,
        // which is the honest output when no resolver could be consulted.
        RevocationStatus::Unknown(why) => format!("unknown -- {why}"),
    };

    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "grant": g,
            "id_consistent": id_ok,
            "signature_valid": sig_ok,
            "revocation": match &revocation {
                RevocationStatus::NotRevoked => serde_json::json!({ "state": "not_revoked" }),
                RevocationStatus::RevokedAt(at) => {
                    serde_json::json!({ "state": "revoked", "revoked_at": at })
                }
                RevocationStatus::Unknown(why) => {
                    serde_json::json!({ "state": "unknown", "reason": why })
                }
            },
        }));
        return Ok(());
    }

    let scope_str = g.scope.join(", ");
    let depth_str = g.delegation_depth.to_string();
    let parent_str = g
        .parent_grant_id
        .clone()
        .unwrap_or_else(|| "-- (root)".into());
    let id_str = yes_no(id_ok);
    let sig_str = yes_no(sig_ok);
    printer.success(
        &g.grant_id,
        &[
            ("grantor", &g.grantor),
            ("scope", &scope_str),
            ("audience", &g.audience),
            ("issued", &g.issued_at),
            ("expiry", &g.expiry),
            ("depth", &depth_str),
            ("parent", &parent_str),
            ("id matches content", &id_str),
            ("issuer signature", &sig_str),
            ("revocation", &revocation_str),
        ],
    );
    Ok(())
}

fn yes_no(b: bool) -> String {
    if b {
        "yes".into()
    } else {
        "NO".into()
    }
}

/// RFC 3339 in UTC from a unix timestamp, without pulling in a date crate the
/// workspace does not already depend on.
fn format_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Civil-from-days (Howard Hinnant's algorithm), epoch-shifted to 0000-03-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Withdraw a grant by minting a signed `grant_revocation.v1` receipt.
///
/// # Why a receipt and not a flag on the grant
///
/// A grant is content-addressed: its id is derived from its bytes. Editing it
/// to add `revoked: true` would change the id, so every mandate naming the old
/// id would stop resolving -- the grant would not be revoked, it would vanish,
/// and receipts already signed under it would become unverifiable rather than
/// correctly-authorized-then-withdrawn.
///
/// So revocation is a separate artifact that points at the grant, exactly as
/// capability-card revocation already works.
///
/// # Who may revoke
///
/// Only the grantor. The receipt is signed with the ship's default key and
/// records the grantor it claims to be; `LocalRevocationSource` honors it only
/// when those match. A revocation anyone could mint is a denial of service
/// against every grant whose id they know, and grant ids appear in published
/// receipts.
///
/// # What revocation does not do
///
/// It does not invalidate what already happened. `verify_mandate` compares the
/// revocation instant against the action's `signed_at`, so actions signed
/// before this moment stay authorized. Withdrawing authority and unmaking the
/// past are different operations, and only the first is available.
pub fn revoke(
    id: &str,
    reason: Option<&str>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let dir = grants_dir_for(&ctx.config_path);
    let path = grant_path(&dir, id);
    if !path.exists() {
        return Err(format!("grant not found: {id}\n  run: treeship grant list").into());
    }

    // Checked, not unchecked: we are about to assert something about this
    // grant's authority, and an inconsistent id means the bytes are not the
    // grant that id names.
    let grant = read_grant_unchecked(&path)?;
    if !grant.id_is_consistent() {
        return Err(format!(
            "grant {id} has an inconsistent id -- its bytes do not derive it. Refusing to \
             revoke a grant that is not what it claims to be; inspect it with:\n  \
             treeship grant show {id}"
        )
        .into());
    }

    let signer = ctx.keys.default_signer()?;
    let signer_pub = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());

    // Refuse up front rather than minting a receipt the resolver will ignore.
    // A revocation that silently does nothing is worse than an error: the
    // operator believes the grant is dead.
    if signer_pub != grant.grantor {
        return Err(format!(
            "only the grantor can revoke this grant.\n  \
             grant was issued by: {}\n  \
             your default key is: {}\n\n\
             A revocation signed by anyone else is ignored by verifiers, so minting one \
             here would tell you the grant was withdrawn when it was not.",
            grant.grantor, signer_pub
        )
        .into());
    }

    let revoked_at = crate::commands::verify::now_rfc3339();
    let mut payload = serde_json::Map::new();
    payload.insert("schema".into(), "grant_revocation.v1".into());
    payload.insert("grant_id".into(), grant.grant_id.clone().into());
    payload.insert("grantor".into(), grant.grantor.clone().into());
    if let Some(r) = reason {
        payload.insert("reason".into(), r.into());
    }
    payload.insert("revoked_at".into(), revoked_at.clone().into());
    let payload = serde_json::Value::Object(payload);

    treeship_core::predicates::validate("grant_revocation.v1", Some(&payload))
        .map_err(|e| format!("invalid revocation: {e}"))?;

    let mut stmt = ReceiptStatement::new(
        format!("ship://{}", ctx.config.ship_id),
        "grant_revocation.v1",
    );
    stmt.payload = Some(payload);

    let signed = treeship_core::attestation::sign(&payload_type("receipt"), &stmt, &*signer)?;
    ctx.storage.write(&Record {
        artifact_id: signed.artifact_id.clone(),
        digest: signed.digest.clone(),
        payload_type: signed.envelope.payload_type.clone(),
        key_id: signer.key_id().to_string(),
        signed_at: revoked_at.clone(),
        parent_id: None,
        envelope: signed.envelope.clone(),
        hub_url: None,
        anchors: Vec::new(),
    })?;

    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "status":     "revoked",
            "grant_id":   grant.grant_id,
            "revoked_at": revoked_at,
            "reason":     reason,
            "artifact":   signed.artifact_id,
        }));
        return Ok(());
    }

    printer.success(
        "grant revoked",
        &[
            ("grant", grant.grant_id.as_str()),
            ("revoked_at", revoked_at.as_str()),
            ("reason", reason.unwrap_or("(none given)")),
            ("receipt", signed.artifact_id.as_str()),
        ],
    );
    printer.blank();
    printer.hint(
        "actions signed BEFORE this instant remain authorized -- revoking withdraws authority, \
         it does not unmake what was already done under it. Verifiers on other machines honor \
         this only once they have the revocation receipt; publish it with `treeship publish`.",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(scope: &[&str], audience: &str, expiry: &str, depth: u32, max: u32) -> Grant {
        Grant {
            grant_id: "grn_test".into(),
            grantor: "k".into(),
            grantee: None,
            issuer_sig: None,
            scope: scope.iter().map(|s| s.to_string()).collect(),
            audience: audience.into(),
            parent_request_id: None,
            parent_grant_id: None,
            delegation_depth: depth,
            issued_at: "2026-08-05T10:00:00Z".into(),
            expiry: expiry.into(),
            max_delegation: max,
            objective_hash: None,
        }
    }

    #[test]
    fn narrowing_is_allowed() {
        let p = grant(&["payments.*"], "acme", "2026-12-31T00:00:00Z", 0, 3);
        let c = grant(&["payments.charge"], "acme", "2026-06-30T00:00:00Z", 1, 3);
        assert_eq!(attenuation_error(&p, &c), None);
    }

    #[test]
    fn widening_scope_is_refused_at_mint() {
        let p = grant(&["payments.charge"], "acme", "2026-12-31T00:00:00Z", 0, 3);
        let c = grant(&["payments.refund"], "acme", "2026-12-31T00:00:00Z", 1, 3);
        let why = attenuation_error(&p, &c).expect("must refuse");
        assert!(why.contains("scope widens"), "{why}");
    }

    #[test]
    fn outliving_the_parent_is_refused_at_mint() {
        let p = grant(&["payments.*"], "acme", "2026-06-30T00:00:00Z", 0, 3);
        let c = grant(&["payments.charge"], "acme", "2026-12-31T00:00:00Z", 1, 3);
        let why = attenuation_error(&p, &c).expect("must refuse");
        assert!(why.contains("outlives"), "{why}");
    }

    #[test]
    fn changing_audience_is_refused_at_mint() {
        let p = grant(&["payments.*"], "acme", "2026-12-31T00:00:00Z", 0, 3);
        let c = grant(&["payments.charge"], "other", "2026-06-30T00:00:00Z", 1, 3);
        let why = attenuation_error(&p, &c).expect("must refuse");
        assert!(why.contains("audience"), "{why}");
    }

    #[test]
    fn exceeding_max_delegation_is_refused_at_mint() {
        let p = grant(&["payments.*"], "acme", "2026-12-31T00:00:00Z", 0, 1);
        let c = grant(&["payments.charge"], "acme", "2026-06-30T00:00:00Z", 2, 1);
        let why = attenuation_error(&p, &c).expect("must refuse");
        assert!(why.contains("max_delegation"), "{why}");
    }

    #[test]
    fn wildcard_scope_covers_its_prefix_only() {
        assert!(scope_covered("payments.charge", &["payments.*".into()]));
        assert!(!scope_covered("email.send", &["payments.*".into()]));
        // An exact entry must not behave like a prefix.
        assert!(!scope_covered(
            "payments.charge.extra",
            &["payments.charge".into()]
        ));
    }

    #[test]
    fn checked_read_refuses_a_tampered_id_but_unchecked_still_opens_it() {
        // The two readers exist for different jobs and must not collapse into
        // one. A caller about to *use* a grant needs the refusal; `grant show`
        // needs to open the same file and report that it is unsound. If the
        // only loader refused, the command meant to diagnose a bad grant could
        // never read one.
        let dir = std::env::temp_dir().join("ts_grant_reader_split_test");
        std::fs::create_dir_all(&dir).unwrap();
        let mut g = grant(&["payments.charge"], "acme", "2027-01-01T00:00:00Z", 0, 3);
        g.grant_id = "grn_0000000000000000".into(); // not derived from content
        let path = grant_path(&dir, &g.grant_id);
        std::fs::write(&path, serde_json::to_string(&g).unwrap()).unwrap();

        assert!(
            read_grant_file(&path).is_err(),
            "a grant whose id does not match its content must not be usable"
        );
        let opened = read_grant_unchecked(&path).expect("show must still be able to open it");
        assert!(
            !opened.id_is_consistent(),
            "and it must be reportable as inconsistent"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rfc3339_formatting_round_trips_through_the_parser() {
        // The formatter is hand-rolled, so pin it against the parser the rest
        // of the codebase uses rather than against my own arithmetic.
        for secs in [0u64, 1_000_000_000, 1_784_545_200, 2_000_000_000] {
            let s = format_rfc3339(secs);
            assert_eq!(
                parse_rfc3339_to_unix(&s),
                Some(secs),
                "{s} did not round-trip"
            );
        }
    }
}
