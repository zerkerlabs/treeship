use std::process;
use std::time::Instant;

use treeship_core::{
    attestation::sign,
    statements::{ActionStatement, payload_type},
    storage::Record,
};

use crate::{ctx, printer::Printer};

pub fn run(
    actor:     Option<String>,
    action:    Option<String>,
    parent_id: Option<String>,
    _push:     bool,
    config:    Option<&str>,
    args:      &[String],     // everything after --
    printer:   &Printer,
) -> Result<(), Box<dyn std::error::Error>> {

    if args.is_empty() {
        return Err(
            "no command given\n\n  usage: treeship wrap [flags] -- <command> [args...]".into()
        );
    }

    let ctx = ctx::open(config)?;

    // The action label defaults to the executable name
    let action_label = action.clone().unwrap_or_else(|| {
        std::path::Path::new(&args[0])
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&args[0])
            .to_string()
    });
    let actor_uri = actor.unwrap_or_else(|| format!("ship://{}", ctx.config.ship_id));

    // Run the subprocess -- stdin/stdout/stderr pass through unchanged
    let start  = Instant::now();
    let status = process::Command::new(&args[0])
        .args(&args[1..])
        .stdin(process::Stdio::inherit())
        .stdout(process::Stdio::inherit())
        .stderr(process::Stdio::inherit())
        .status();

    let elapsed_ms = start.elapsed().as_millis();

    let (exit_code, succeeded) = match &status {
        Ok(s)  => (s.code().unwrap_or(-1), s.success()),
        Err(_) => (-1, false),
    };

    // Attest regardless of exit code -- the fact it ran is what we record
    let mut stmt = ActionStatement::new(&actor_uri, &action_label);
    stmt.parent_id = parent_id.clone();
    stmt.meta = Some(serde_json::json!({
        "command":  args.join(" "),
        "exitCode": exit_code,
        "elapsedMs": elapsed_ms,
    }));

    let signer = ctx.keys.default_signer()?;
    let pt     = payload_type("action");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id,
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    // Print below the subprocess output, separated by a blank line
    printer.blank();

    if succeeded {
        printer.success("attested", &[
            ("id",      &result.artifact_id),
            ("action",  &action_label),
            ("exit",    "0"),
            ("elapsed", &format!("{}ms", elapsed_ms)),
        ]);
    } else {
        printer.warn("attested (non-zero exit)", &[
            ("id",      &result.artifact_id),
            ("action",  &action_label),
            ("exit",    &exit_code.to_string()),
            ("elapsed", &format!("{}ms", elapsed_ms)),
        ]);
    }

    printer.hint(&format!("treeship verify {}", result.artifact_id));
    printer.blank();

    // Propagate the subprocess exit code
    if let Ok(s) = status {
        if !s.success() {
            if let Some(code) = s.code() {
                process::exit(code);
            }
        }
    }

    Ok(())
}
