use serde_json::Value;
use treeship_core::{
    attestation::sign,
    statements::{ActionStatement, ApprovalStatement, HandoffStatement, ReceiptStatement, payload_type, SubjectRef},
    storage::Record,
};

use crate::{ctx, printer::Printer};

// --- action -----------------------------------------------------------------

pub struct ActionArgs {
    pub actor:          String,
    pub action:         String,
    pub input_digest:   Option<String>,
    pub output_digest:  Option<String>,
    pub content_uri:    Option<String>,
    pub parent_id:      Option<String>,
    pub approval_nonce: Option<String>,
    pub meta:           Option<String>,
    pub out:            Option<String>,
    pub config:         Option<String>,
}

pub fn action(args: ActionArgs, printer: &Printer) -> Result<String, Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    let meta: Option<Value> = args.meta.as_deref()
        .map(|m| serde_json::from_str(m))
        .transpose()
        .map_err(|e| format!("--meta is not valid JSON: {e}"))?;

    let subject = SubjectRef {
        digest:      args.input_digest.clone(),
        uri:         args.content_uri.clone(),
        artifact_id: None,
    };

    let mut stmt = ActionStatement::new(&args.actor, &args.action);
    stmt.subject       = subject;
    stmt.parent_id     = args.parent_id.clone();
    stmt.approval_nonce = args.approval_nonce.clone();
    stmt.meta          = meta;

    let signer = ctx.keys.default_signer()?;
    let pt     = payload_type("action");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    // Store locally.
    let record = Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt.clone(),
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    args.parent_id.clone(),
        envelope:     result.envelope.clone(),
        hub_url:      None,
    };
    ctx.storage.write(&record)?;

    // Optional: write raw DSSE envelope to file or stdout.
    if let Some(path) = &args.out {
        let json = result.envelope.to_json()?;
        if path == "-" {
            println!("{}", String::from_utf8_lossy(&json));
        } else {
            std::fs::write(path, &json)?;
        }
    }

    // Build display fields.
    let signed_str = stmt.timestamp.clone();
    let mut fields: Vec<(&str, String)> = vec![
        ("id",     result.artifact_id.clone()),
        ("actor",  args.actor.clone()),
        ("action", args.action.clone()),
        ("signed", signed_str),
    ];
    if let Some(d) = &args.output_digest {
        fields.push(("out-digest", d.clone()));
    }
    if let Some(p) = &args.parent_id {
        fields.push(("parent", p.clone()));
    }

    let field_refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    printer.success("action attested", &field_refs);
    printer.hint(&format!("treeship verify {}", result.artifact_id));
    printer.blank();
    Ok(result.artifact_id)
}

// --- approval ---------------------------------------------------------------

pub struct ApprovalArgs {
    pub approver:        String,
    pub subject_id:      Option<String>,
    pub description:     Option<String>,
    pub expires:         Option<String>,
    pub config:          Option<String>,
}

pub fn approval(args: ApprovalArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    // Generate a cryptographically random nonce for approval binding.
    let nonce = {
        let mut b = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut b);
        b.iter().fold(String::new(), |mut s, byte| {
            s.push_str(&format!("{:02x}", byte));
            s
        })
    };

    let mut stmt = ApprovalStatement::new(&args.approver, &nonce);
    stmt.description = args.description.clone();
    stmt.expires_at  = args.expires.clone();
    if let Some(id) = &args.subject_id {
        stmt.subject.artifact_id = Some(id.clone());
    }

    let signer = ctx.keys.default_signer()?;
    let pt     = payload_type("approval");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    None,
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    printer.success("approval attested", &[
        ("id",       &result.artifact_id),
        ("approver", &args.approver),
        ("nonce",    &nonce),
        ("signed",   &stmt.timestamp),
    ]);
    printer.hint(&format!("nonce: {}  (echo this in --approval-nonce when you attest the action)", nonce));
    printer.blank();
    Ok(())
}

// --- handoff ----------------------------------------------------------------

pub struct HandoffArgs {
    pub from:        String,
    pub to:          String,
    pub artifacts:   Vec<String>,
    pub approvals:   Vec<String>,
    pub obligations: Vec<String>,
    pub config:      Option<String>,
}

pub fn handoff(args: HandoffArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    let mut stmt = HandoffStatement::new(&args.from, &args.to, args.artifacts.clone());
    stmt.approval_ids = args.approvals.clone();
    stmt.obligations  = args.obligations.clone();

    let signer = ctx.keys.default_signer()?;
    let pt     = payload_type("handoff");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    args.artifacts.first().cloned(),
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    printer.success("handoff attested", &[
        ("id",        &result.artifact_id),
        ("from",      &args.from),
        ("to",        &args.to),
        ("artifacts", &args.artifacts.join(", ")),
        ("signed",    &stmt.timestamp),
    ]);
    printer.hint(&format!("treeship verify {}", result.artifact_id));
    printer.blank();
    Ok(())
}

// --- receipt ----------------------------------------------------------------

pub struct ReceiptArgs {
    pub system:     String,
    pub kind:       String,
    pub subject_id: Option<String>,
    pub payload:    Option<String>,
    pub config:     Option<String>,
}

pub fn receipt(args: ReceiptArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    let payload_val: Option<Value> = args.payload.as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| format!("--payload is not valid JSON: {e}"))?;

    let mut stmt = ReceiptStatement::new(&args.system, &args.kind);
    stmt.payload = payload_val;
    if let Some(id) = &args.subject_id {
        stmt.subject = Some(SubjectRef {
            artifact_id: Some(id.clone()),
            ..Default::default()
        });
    }

    let signer = ctx.keys.default_signer()?;
    let pt     = payload_type("receipt");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    args.subject_id.clone(),
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    printer.success("receipt attested", &[
        ("id",     &result.artifact_id),
        ("system", &args.system),
        ("kind",   &args.kind),
        ("signed", &stmt.timestamp),
    ]);
    printer.hint(&format!("treeship verify {}", result.artifact_id));
    printer.blank();
    Ok(())
}
