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
        if self.format == Format::Json { self.print_json(fields); return; }
        println!("{}", self.green(&format!("✓ {msg}")));
        self.print_fields(fields);
    }

    /// ✗ red failure to stderr -- always shows
    pub fn failure(&self, msg: &str, fields: &[(&str, &str)]) {
        if self.format == Format::Json { self.print_json(fields); return; }
        eprintln!("{}", self.red(&format!("✗ {msg}")));
        for (k, v) in fields { eprintln!("  {k}: {v}"); }
    }

    /// ⚠ amber warning
    pub fn warn(&self, msg: &str, fields: &[(&str, &str)]) {
        if self.quiet { return; }
        if self.format == Format::Json { self.print_json(fields); return; }
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
