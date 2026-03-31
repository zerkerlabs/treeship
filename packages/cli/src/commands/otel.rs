//! CLI commands for `treeship otel {test|status|export|enable|disable}`.
//!
//! When compiled without the `otel` feature, all commands print a message
//! directing the user to rebuild with `--features otel`.

use crate::printer::Printer;

// ---------------------------------------------------------------------------
// Feature-gated implementations
// ---------------------------------------------------------------------------

#[cfg(feature = "otel")]
pub fn test_connection(
    _config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let otel_config = crate::otel::config::OtelConfig::from_env()
        .ok_or("TREESHIP_OTEL_ENDPOINT not set\n\n  export TREESHIP_OTEL_ENDPOINT=http://localhost:4318")?;

    if !otel_config.enabled {
        printer.warn("otel export is disabled (TREESHIP_OTEL_ENABLED=false)", &[]);
        return Ok(());
    }

    printer.info("  sending test span...");

    match crate::otel::exporter::send_test_span(&otel_config) {
        Ok(()) => {
            printer.blank();
            printer.success("connected", &[
                ("endpoint", &otel_config.endpoint),
                ("service",  &otel_config.service_name),
            ]);
            printer.info("  sent 1 test span");
            printer.blank();
        }
        Err(e) => {
            printer.blank();
            printer.failure("connection failed", &[
                ("endpoint", &otel_config.endpoint),
                ("error",    &e),
            ]);
            printer.blank();
        }
    }

    Ok(())
}

#[cfg(feature = "otel")]
pub fn status(
    printer: &Printer,
) {
    match crate::otel::config::OtelConfig::from_env() {
        Some(cfg) => {
            printer.blank();
            printer.section("otel");
            printer.info(&format!("  endpoint:  {}", cfg.endpoint));
            printer.info(&format!("  service:   {}", cfg.service_name));
            printer.info(&format!("  enabled:   {}", cfg.enabled));
            if cfg.auth_header.is_some() {
                printer.info("  auth:      configured");
            } else {
                printer.dim_info("  auth:      none");
            }
            printer.blank();
        }
        None => {
            printer.blank();
            printer.dim_info("  otel not configured");
            printer.blank();
            printer.hint("export TREESHIP_OTEL_ENDPOINT=http://localhost:4318");
            printer.blank();
        }
    }
}

#[cfg(feature = "otel")]
pub fn export_artifact(
    id: &str,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let otel_config = crate::otel::config::OtelConfig::from_env()
        .ok_or("TREESHIP_OTEL_ENDPOINT not set")?;

    let ctx = crate::ctx::open(config)?;
    let record = ctx.storage.read(id)?;

    match crate::otel::exporter::export_artifact(&otel_config, &record) {
        Ok(()) => {
            printer.blank();
            printer.success("exported", &[
                ("artifact", id),
                ("endpoint", &otel_config.endpoint),
            ]);
            printer.blank();
        }
        Err(e) => {
            printer.blank();
            printer.failure("export failed", &[
                ("artifact", id),
                ("error",    &e),
            ]);
            printer.blank();
        }
    }

    Ok(())
}

#[cfg(feature = "otel")]
pub fn enable(printer: &Printer) {
    printer.blank();
    printer.info("  otel is controlled by environment variables:");
    printer.blank();
    printer.info("  export TREESHIP_OTEL_ENABLED=true");
    printer.info("  export TREESHIP_OTEL_ENDPOINT=http://localhost:4318");
    printer.blank();
    printer.hint("set TREESHIP_OTEL_ENABLED=false to disable");
    printer.blank();
}

#[cfg(feature = "otel")]
pub fn disable(printer: &Printer) {
    printer.blank();
    printer.info("  to disable otel export:");
    printer.blank();
    printer.info("  export TREESHIP_OTEL_ENABLED=false");
    printer.blank();
    printer.hint("unset TREESHIP_OTEL_ENDPOINT to fully remove");
    printer.blank();
}

// ---------------------------------------------------------------------------
// Fallback when feature is not compiled in
// ---------------------------------------------------------------------------

#[cfg(not(feature = "otel"))]
pub fn not_available(printer: &Printer) {
    printer.blank();
    printer.warn("otel export not available in this build", &[]);
    printer.blank();
    printer.hint("rebuild with: cargo install treeship-cli --features otel");
    printer.blank();
}
