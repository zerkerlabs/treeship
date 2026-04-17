//! treeship quickstart -- guided first-time setup in 90 seconds.

use std::io::{self, Write};

use crate::printer::Printer;

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();
    input.trim().to_string()
}

pub fn run(
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    printer.blank();
    printer.info("  Welcome to Treeship.");
    printer.blank();

    // Step 1: Init if needed
    printer.info("  Step 1/4  Initializing...");
    let needs_init = crate::ctx::open(config).is_err();
    if needs_init {
        // Run init non-interactively
        let result = super::init::run(None, None, false, None, printer);
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
    if super::session::load_session().is_some() {
        printer.dim_info("  (closing previous session)");
        let _ = super::session::close(
            Some("auto-closed by quickstart".into()),
            None, None,
            config, printer,
        );
    }
    super::session::start(
        Some("quickstart session".into()),
        None, config, printer,
    )?;
    printer.blank();

    // Step 3: Wrap a command
    printer.info("  Step 3/4  Wrap a command to record it.");
    let cmd = prompt("  Enter a command to run (e.g. \"ls -la\"): ");
    let cmd = if cmd.is_empty() { "echo hello treeship".to_string() } else { cmd };

    let args: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
    if !args.is_empty() {
        let wrap_result = super::wrap::run(
            None, None, None, false, config, &args, printer,
        );
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
    printer.blank();

    // Step 4: Close and create receipt
    printer.info("  Step 4/4  Creating your receipt...");
    super::session::close(
        Some(format!("Quickstart: ran '{}'", cmd)),
        Some("First Treeship receipt".into()),
        None,
        config,
        printer,
    )?;

    printer.blank();

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
        let report_result = super::session::report(None, config, printer);
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
