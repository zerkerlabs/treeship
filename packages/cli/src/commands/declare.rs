//! Declaration management: create and inspect `.treeship/declaration.json`.
//!
//! A declaration defines the authorized scope for agent work in this project:
//! which tools are allowed, which are forbidden, and which require escalation.

use std::path::PathBuf;

use crate::printer::Printer;

fn ts_dir() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".treeship");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn declaration_path() -> Option<PathBuf> {
    ts_dir().map(|d| d.join("declaration.json"))
}

/// Create or overwrite `.treeship/declaration.json`.
pub fn create(
    bounded_actions: Vec<String>,
    forbidden: Vec<String>,
    escalation_required: Vec<String>,
    valid_until: Option<String>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = declaration_path()
        .ok_or("no .treeship directory found -- run treeship init first")?;

    let created_at = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        treeship_core::statements::unix_to_rfc3339(secs)
    };

    let decl = serde_json::json!({
        "bounded_actions": bounded_actions,
        "forbidden": forbidden,
        "escalation_required": escalation_required,
        "valid_until": valid_until,
        "created_at": created_at,
    });

    let json = serde_json::to_string_pretty(&decl)?;
    std::fs::write(&path, &json)?;

    printer.blank();
    printer.success("declaration created", &[]);
    printer.info(&format!("  path:       {}", path.display()));
    printer.info(&format!("  authorized: {} tools", bounded_actions.len()));
    printer.info(&format!("  forbidden:  {} tools", forbidden.len()));
    printer.info(&format!("  escalation: {} tools", escalation_required.len()));
    if let Some(ref v) = valid_until {
        printer.info(&format!("  valid until: {}", v));
    }
    printer.blank();

    Ok(())
}

/// Show the current declaration.
pub fn show(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let path = declaration_path()
        .ok_or("no .treeship directory found")?;

    if !path.exists() {
        printer.blank();
        printer.dim_info("  no declaration found");
        printer.blank();
        printer.hint("treeship declare --tools read_file,write_file,bash");
        printer.blank();
        return Ok(());
    }

    let data = std::fs::read_to_string(&path)?;
    let decl: serde_json::Value = serde_json::from_str(&data)?;

    printer.blank();
    printer.section("declaration");

    if let Some(tools) = decl.get("bounded_actions").and_then(|v| v.as_array()) {
        printer.info(&format!("  authorized: {:?}", tools.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()));
    }
    if let Some(forbidden) = decl.get("forbidden").and_then(|v| v.as_array()) {
        if !forbidden.is_empty() {
            printer.info(&format!("  forbidden:  {:?}", forbidden.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()));
        }
    }
    if let Some(esc) = decl.get("escalation_required").and_then(|v| v.as_array()) {
        if !esc.is_empty() {
            printer.info(&format!("  escalation: {:?}", esc.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()));
        }
    }
    if let Some(v) = decl.get("valid_until").and_then(|v| v.as_str()) {
        printer.info(&format!("  valid until: {}", v));
    }
    if let Some(c) = decl.get("created_at").and_then(|v| v.as_str()) {
        printer.info(&format!("  created:    {}", c));
    }

    printer.blank();

    Ok(())
}

/// Read authorized tools from the declaration if it exists.
pub fn read_authorized_tools() -> Vec<String> {
    let path = match declaration_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    if !path.exists() {
        return Vec::new();
    }
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let decl: serde_json::Value = match serde_json::from_str(&data) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    decl.get("bounded_actions")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}
