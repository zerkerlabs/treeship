use std::io::{self, IsTerminal};

#[derive(Clone, Copy, PartialEq)]
pub enum Format { Text, Json }

impl Format {
    pub fn from_str(s: &str) -> Self {
        match s { "json" => Self::Json, _ => Self::Text }
    }
}

pub struct Printer {
    pub format:   Format,
    pub quiet:    bool,
    pub no_color: bool,
}

impl Printer {
    pub fn new(format: Format, quiet: bool, no_color: bool) -> Self {
        Self { format, quiet, no_color }
    }

    /// ✓ green success header + aligned key:value fields
    pub fn success(&self, msg: &str, fields: &[(&str, &str)]) {
        if self.quiet { return; }
        if self.format == Format::Json {
            self.print_json_with_status("ok", Some(msg), fields);
            return;
        }
        println!("{}", self.green(&format!("✓ {msg}")));
        self.print_fields(fields);
    }

    /// ✗ red failure to stderr -- always shows.
    ///
    /// In JSON mode emits a structured error envelope:
    ///   {"status": "error", "error": "<msg>", "<field>": "<v>", ...}
    /// to stderr. Prior versions called print_json with only the
    /// fields slice, which dropped `msg` entirely -- callers
    /// (especially the @treeship/mcp bridge) saw an empty `{}` body
    /// with a non-zero exit code and no error text. The MCP bridge
    /// then surfaced that as a generic isError on every tool call.
    pub fn failure(&self, msg: &str, fields: &[(&str, &str)]) {
        if self.format == Format::Json {
            // Errors go to stderr in JSON mode too -- callers parsing
            // the success path's stdout shouldn't have to demux a
            // fail-shaped object from a success-shaped object on the
            // same stream. Keep stdout clean for happy-path callers.
            let body = self.json_envelope("error", Some(msg), fields);
            eprintln!("{body}");
            return;
        }
        eprintln!("{}", self.red(&format!("✗ {msg}")));
        for (k, v) in fields { eprintln!("  {k}: {v}"); }
    }

    /// ⚠ amber warning
    pub fn warn(&self, msg: &str, fields: &[(&str, &str)]) {
        if self.quiet { return; }
        if self.format == Format::Json {
            self.print_json_with_status("warning", Some(msg), fields);
            return;
        }
        println!("{}", self.yellow(&format!("⚠ {msg}")));
        self.print_fields(fields);
    }

    /// Dim hint line shown after a success to guide the next step
    ///   →  treeship verify art_abc123
    pub fn hint(&self, msg: &str) {
        if self.quiet || self.format == Format::Json { return; }
        println!("{}", self.dim(&format!("   → {msg}")));
    }

    /// Blank breathing room
    pub fn blank(&self) {
        if self.quiet || self.format == Format::Json { return; }
        println!();
    }

    /// Plain info line
    pub fn info(&self, msg: &str) {
        if self.quiet || self.format == Format::Json { return; }
        println!("{msg}");
    }

    /// Dim secondary info
    pub fn dim_info(&self, msg: &str) {
        if self.quiet || self.format == Format::Json { return; }
        println!("{}", self.dim(msg));
    }

    /// Bold section header (for status-style multi-part output)
    pub fn section(&self, title: &str) {
        if self.quiet || self.format == Format::Json { return; }
        println!("{}", self.bold(title));
    }

    /// Print any serialisable value as indented JSON
    pub fn json<T: serde::Serialize>(&self, v: &T) {
        match serde_json::to_string_pretty(v) {
            Ok(s)  => println!("{s}"),
            Err(e) => eprintln!("json error: {e}"),
        }
    }

    // --- internal ---

    fn print_fields(&self, fields: &[(&str, &str)]) {
        if fields.is_empty() { return; }
        let max = fields.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        for (k, v) in fields {
            let pad = " ".repeat(max - k.len());
            println!("  {}  {}", self.dim(&format!("{k}:{pad}")), v);
        }
    }

    fn print_json(&self, fields: &[(&str, &str)]) {
        let mut m = serde_json::Map::new();
        for (k, v) in fields {
            m.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
        println!("{}", serde_json::to_string(&m).unwrap_or_default());
    }

    fn print_json_with_status(
        &self,
        status: &str,
        message: Option<&str>,
        fields: &[(&str, &str)],
    ) {
        println!("{}", self.json_envelope(status, message, fields));
    }

    /// Build the JSON envelope used for success / warning / error in
    /// --format json mode. Backwards-compatible with the previous
    /// success shape: every field that used to be a top-level key is
    /// still a top-level key. We just *also* add `status` and `error`
    /// (when applicable) so callers can branch on them.
    fn json_envelope(
        &self,
        status: &str,
        message: Option<&str>,
        fields: &[(&str, &str)],
    ) -> String {
        let mut m = serde_json::Map::new();
        m.insert("status".into(), serde_json::Value::String(status.to_string()));
        if let Some(msg) = message {
            // success/warning use `message`; error uses `error`. Both
            // are present so callers don't have to read `status` to
            // know which key carries the human text.
            let key = if status == "error" { "error" } else { "message" };
            m.insert(key.into(), serde_json::Value::String(msg.to_string()));
        }
        for (k, v) in fields {
            m.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
        serde_json::to_string(&m).unwrap_or_default()
    }

    fn use_color(&self) -> bool {
        !self.no_color
            && std::env::var("NO_COLOR").is_err()
            && std::env::var("TERM").as_deref() != Ok("dumb")
            && io::stdout().is_terminal()
    }

    fn code(&self, s: &str, c: &str) -> String {
        if self.use_color() { format!("{c}{s}\x1b[0m") } else { s.to_string() }
    }

    pub fn green(&self, s: &str)  -> String { self.code(s, "\x1b[32m") }
    pub fn red(&self, s: &str)    -> String { self.code(s, "\x1b[31m") }
    pub fn yellow(&self, s: &str) -> String { self.code(s, "\x1b[33m") }
    pub fn dim(&self, s: &str)    -> String { self.code(s, "\x1b[2m")  }
    pub fn bold(&self, s: &str)   -> String { self.code(s, "\x1b[1m")  }
    pub fn cyan(&self, s: &str)   -> String { self.code(s, "\x1b[36m") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn json_printer() -> Printer {
        Printer::new(Format::Json, /* quiet */ false, /* no_color */ true)
    }

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).expect("envelope must be valid JSON")
    }

    #[test]
    fn error_envelope_carries_message() {
        // Regression for the v0.10.0 bug: failure(msg, &[]) in JSON
        // mode emitted `{}` and dropped the message, so the @treeship/mcp
        // bridge surfaced every CLI error as an empty isError object.
        let p = json_printer();
        let body = p.json_envelope("error", Some("keys crypto: MAC failed"), &[]);
        let v = parse(&body);
        assert_eq!(v["status"], "error");
        assert_eq!(v["error"], "keys crypto: MAC failed");
        // No spurious "message" key on errors -- only "error".
        assert!(v.get("message").is_none());
    }

    #[test]
    fn success_envelope_keeps_existing_fields() {
        let p = json_printer();
        let body = p.json_envelope(
            "ok",
            Some("action attested"),
            &[("id", "art_abc"), ("actor", "agent://t")],
        );
        let v = parse(&body);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["message"], "action attested");
        assert_eq!(v["id"], "art_abc");
        assert_eq!(v["actor"], "agent://t");
    }

    #[test]
    fn warning_envelope_uses_message_key() {
        let p = json_printer();
        let body = p.json_envelope("warning", Some("clock skew detected"), &[]);
        let v = parse(&body);
        assert_eq!(v["status"], "warning");
        assert_eq!(v["message"], "clock skew detected");
        assert!(v.get("error").is_none());
    }
}
