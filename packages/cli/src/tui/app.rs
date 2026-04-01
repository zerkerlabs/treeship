use std::time::Instant;

use ratatui::Frame;

use crate::ctx::Ctx;

use super::views;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ArtifactEntry {
    pub id: String,
    pub action: String,
    pub actor: String,
    pub exit_code: i32,
    pub elapsed_ms: u64,
    pub timestamp: String,
    pub artifact_type: String,
    pub parent_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub session_id: String,
    pub name: Option<String>,
    pub elapsed_str: String,
    pub artifact_count: u64,
}

#[derive(Clone, Debug)]
pub struct PendingEntry {
    pub command: String,
    pub label: String,
    pub actor: Option<String>,
    pub waiting_str: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum View {
    Dashboard,
    Log,
    ArtifactDetail(usize),
    Approve,
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub view: View,
    pub artifacts: Vec<ArtifactEntry>,
    pub selected: usize,
    pub session: Option<SessionInfo>,
    pub dock_status: String,
    pub dock_endpoint: String,
    pub ship_id: String,
    pub key_id: String,
    pub pending: Vec<PendingEntry>,
    pub pending_selected: usize,
    pub should_quit: bool,
    pub last_refresh: Instant,
}

impl App {
    pub fn new(ctx: &Ctx) -> Result<Self, Box<dyn std::error::Error>> {
        let mut app = App {
            view: View::Dashboard,
            artifacts: Vec::new(),
            selected: 0,
            session: None,
            dock_status: if ctx.config.is_docked() { "docked".into() } else { "undocked".into() },
            dock_endpoint: ctx.config.active_dock_entry()
                .map(|(_, e)| e.endpoint.clone())
                .unwrap_or_else(|| "treeship.dev".into()),
            ship_id: ctx.config.ship_id.clone(),
            key_id: ctx.config.default_key_id.clone(),
            pending: Vec::new(),
            pending_selected: 0,
            should_quit: false,
            last_refresh: Instant::now(),
        };
        app.refresh(ctx)?;
        Ok(app)
    }

    // -----------------------------------------------------------------------
    // Data refresh
    // -----------------------------------------------------------------------

    pub fn maybe_refresh(&mut self, ctx: &Ctx) -> Result<(), Box<dyn std::error::Error>> {
        if self.last_refresh.elapsed().as_secs() >= 2 {
            self.refresh(ctx)?;
        }
        Ok(())
    }

    fn refresh(&mut self, ctx: &Ctx) -> Result<(), Box<dyn std::error::Error>> {
        self.last_refresh = Instant::now();

        // Artifacts from storage index
        let entries = ctx.storage.list();
        self.artifacts = entries
            .iter()
            .map(|e| {
                let short_type = e
                    .payload_type
                    .strip_prefix("application/vnd.treeship.")
                    .and_then(|s| s.strip_suffix(".v1+json"))
                    .unwrap_or(&e.payload_type)
                    .to_string();

                // Try to extract action/actor/exit from the full record
                let (action, actor, exit_code, elapsed_ms) =
                    if let Ok(rec) = ctx.storage.read(&e.id) {
                        parse_record_fields(&rec)
                    } else {
                        (String::new(), String::new(), 0, 0)
                    };

                ArtifactEntry {
                    id: e.id.clone(),
                    action,
                    actor,
                    exit_code,
                    elapsed_ms,
                    timestamp: e.signed_at.clone(),
                    artifact_type: short_type,
                    parent_id: e.parent_id.clone(),
                }
            })
            .collect();

        // Session
        self.session = crate::commands::session::load_session().map(|m| {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let elapsed_ms = now_ms.saturating_sub(m.started_at_ms);
            SessionInfo {
                session_id: m.session_id,
                name: m.name,
                elapsed_str: format_duration_ms(elapsed_ms),
                artifact_count: m.artifact_count,
            }
        });

        // Pending approvals
        self.pending = list_pending_entries();

        // Clamp selection
        if !self.artifacts.is_empty() && self.selected >= self.artifacts.len() {
            self.selected = self.artifacts.len() - 1;
        }
        if !self.pending.is_empty() && self.pending_selected >= self.pending.len() {
            self.pending_selected = self.pending.len() - 1;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Key handling
    // -----------------------------------------------------------------------

    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if matches!(self.view, View::ArtifactDetail(_) | View::Approve) {
                    self.view = View::Dashboard;
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Char('d') => self.view = View::Dashboard,
            KeyCode::Char('l') => self.view = View::Log,
            KeyCode::Char('a') => self.view = View::Approve,
            KeyCode::Up => self.select_prev(),
            KeyCode::Down => self.select_next(),
            KeyCode::Enter => {
                if matches!(self.view, View::Dashboard | View::Log) && !self.artifacts.is_empty() {
                    self.view = View::ArtifactDetail(self.selected);
                }
            }
            _ => {}
        }
    }

    fn select_prev(&mut self) {
        match &self.view {
            View::Approve => {
                if self.pending_selected > 0 {
                    self.pending_selected -= 1;
                }
            }
            _ => {
                if self.selected > 0 {
                    self.selected -= 1;
                }
            }
        }
    }

    fn select_next(&mut self) {
        match &self.view {
            View::Approve => {
                if !self.pending.is_empty() && self.pending_selected < self.pending.len() - 1 {
                    self.pending_selected += 1;
                }
            }
            _ => {
                if !self.artifacts.is_empty() && self.selected < self.artifacts.len() - 1 {
                    self.selected += 1;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Render dispatch
    // -----------------------------------------------------------------------

    pub fn render(&self, frame: &mut Frame) {
        match &self.view {
            View::Dashboard => views::dashboard::render(frame, self),
            View::Log => views::log::render(frame, self),
            View::ArtifactDetail(idx) => views::artifact::render(frame, self, *idx),
            View::Approve => views::approve::render(frame, self),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_duration_ms(ms: u64) -> String {
    let secs = ms / 1000;
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{}h{}m", h, m)
    }
}

pub fn format_elapsed(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else {
        let secs = ms as f64 / 1000.0;
        format!("{:.1}s", secs)
    }
}

pub fn short_id(id: &str) -> &str {
    if id.len() > 16 {
        &id[..16]
    } else {
        id
    }
}

fn parse_record_fields(
    rec: &treeship_core::storage::Record,
) -> (String, String, i32, u64) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&rec.envelope.payload)
        .unwrap_or_default();
    let val: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap_or_default();

    let action = val
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let actor = val
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let exit_code = val
        .get("exit_code")
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as i32;
    let elapsed_ms = val
        .get("elapsed_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    (action, actor, exit_code, elapsed_ms)
}

fn list_pending_entries() -> Vec<PendingEntry> {
    // Reuse the pending directory discovery from approve module
    let mut dir = match std::env::current_dir().ok() {
        Some(d) => d,
        None => return vec![],
    };

    let pending_dir = loop {
        let ts_dir = dir.join(".treeship").join("pending");
        if ts_dir.is_dir() {
            break ts_dir;
        }
        if !dir.pop() {
            return vec![];
        }
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut entries = Vec::new();

    if let Ok(read_dir) = std::fs::read_dir(&pending_dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(data) = std::fs::read_to_string(&path) {
                    if let Ok(pa) =
                        serde_json::from_str::<crate::commands::approve::PendingApproval>(&data)
                    {
                        if !pa.approved && !pa.denied {
                            let age_ms = now_ms.saturating_sub(pa.requested_at_ms);
                            if age_ms < 3_600_000 {
                                entries.push(PendingEntry {
                                    command: pa.command,
                                    label: pa.label,
                                    actor: pa.actor,
                                    waiting_str: format_duration_ms(age_ms),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    entries
}
