//! treeship quickstart -- guided first-time setup in 90 seconds.

use std::io::{self, Write};

use crate::printer::{Format, Printer};

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();
    input.trim().to_string()
}

const DEFAULT_COMMAND: &str = "echo hello treeship";

pub fn run(config: Option<&str>, outer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    // A JSON consumer cannot answer a prompt and wants one document: the
    // sub-commands run silently with the default command, nothing is
    // uploaded, and one document reports the run. (0.31.11 re-test, N-2:
    // prompt text used to be mixed into the JSON.)
    let json = outer.format == Format::Json;
    let quiet = Printer::new(Format::Text, true, outer.no_color);
    let printer: &Printer = if json { &quiet } else { outer };

    printer.blank();
    printer.info("  Welcome to Treeship.");
    printer.blank();

    // Step 1: Init if needed
    printer.info("  Step 1/4  Initializing...");
    let needs_init = crate::ctx::open(config).is_err();
    if needs_init {
        // Run init non-interactively
        let result = super::init::run(None, None, false, false, None, printer);
        if let Err(e) = result {
            // Already initialized is fine
            if !e.to_string().contains("already initialized") {
                return Err(e);
            }
        }
    }
    let ctx = crate::ctx::open(config)?;
    printer.success(&format!("Ship ID: {}", ctx.config.ship_id), &[]);
    printer.blank();

    // Step 2: Start session
    printer.info("  Step 2/4  Starting a session...");
    // Close any existing session first
    let mut closed_previous = false;
    if super::session::load_session().is_some() {
        printer.dim_info("  (closing previous session)");
        let _ = super::session::close(
            Some("auto-closed by quickstart".into()),
            None,
            None,
            None,
            config,
            printer,
        );
        closed_previous = true;
    }
    super::session::start(
        Some("quickstart session".into()),
        None,
        None,
        false,
        config,
        printer,
    )?;
    printer.blank();

    // Step 3: Wrap a command
    printer.info("  Step 3/4  Wrap a command to record it.");
    let cmd = if json {
        DEFAULT_COMMAND.to_string()
    } else {
        let typed = prompt("  Enter a command to run (e.g. \"ls -la\"): ");
        if typed.is_empty() {
            DEFAULT_COMMAND.to_string()
        } else {
            typed
        }
    };

    let args: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
    let mut wrap_report = serde_json::Value::Null;
    if !args.is_empty() {
        if json {
            wrap_report = wrap_as_json(config, &args);
        } else {
            let wrap_result = super::wrap::run(None, None, None, false, config, &args, printer);
            match wrap_result {
                Ok(_) => {
                    printer.blank();
                    printer.success(&format!("Wrapped: {}", cmd), &[]);
                }
                Err(e) => {
                    printer.warn(&format!("Wrap failed: {}", e), &[]);
                }
            }
        }
    }
    printer.blank();

    // Step 4: Close and create receipt
    printer.info("  Step 4/4  Creating your receipt...");
    super::session::close(
        Some(format!("Quickstart: ran '{}'", cmd)),
        Some("First Treeship receipt".into()),
        None,
        None,
        config,
        printer,
    )?;

    printer.blank();

    if json {
        outer.json(&serde_json::json!({
            "status": "ok",
            "ship_id": ctx.config.ship_id,
            "session": "quickstart session",
            "closed_previous_session": closed_previous,
            "command": cmd,
            "wrap": wrap_report,
            "receipt": "sealed",
            "uploaded": false,
            "hub_attached": ctx.config.is_attached(),
            "next": "treeship session report",
        }));
        return Ok(());
    }

    // Ask about hub upload
    let upload = prompt("  Want to upload it and get a shareable URL? (y/n): ");
    if upload.eq_ignore_ascii_case("y") || upload.eq_ignore_ascii_case("yes") {
        printer.blank();
        printer.info("  Attaching to Hub...");
        // Check if already attached
        if ctx.config.is_attached() {
            printer.dim_info("  (already attached)");
        } else {
            printer.hint("Run: treeship hub attach --endpoint https://api.treeship.dev");
            printer.hint("Then: treeship session report");
            printer.blank();
            return Ok(());
        }
        let report_result = super::session::report(None, config, "text", false, false, printer);
        if let Err(e) = report_result {
            printer.warn(&format!("Report failed: {}", e), &[]);
            printer.hint("Run: treeship session report  to try again");
        }
    } else {
        printer.blank();
        printer.info("  Your receipt is ready locally.");
        printer.hint("Run: treeship session report  when you want a shareable URL");
    }

    printer.blank();
    Ok(())
}

/// Run the wrap step as `treeship --format json wrap -- <cmd>` and return its
/// document. In-process `wrap` writes the child's output and its own JSON to
/// this process's stdout, which must hold exactly one document here.
fn wrap_as_json(config: Option<&str>, args: &[String]) -> serde_json::Value {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return serde_json::json!({ "ok": false, "error": e.to_string() }),
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["--format", "json"]);
    if let Some(cfg) = config {
        cmd.args(["--config", cfg]);
    }
    cmd.arg("wrap").arg("--").args(args);
    match cmd.output() {
        Ok(out) => match serde_json::from_slice::<serde_json::Value>(&out.stdout) {
            Ok(mut doc) => {
                doc["ok"] = serde_json::json!(out.status.success());
                doc
            }
            Err(_) => serde_json::json!({
                "ok": false,
                "error": String::from_utf8_lossy(&out.stderr).trim(),
            }),
        },
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
    }
}
