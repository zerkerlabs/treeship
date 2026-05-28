use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::Serialize;
use treeship_core::session::{
    read_package, render_preview_html, verify_package, SessionReceipt, VerifyStatus,
};

use crate::printer::Printer;

const DEFAULT_PORT: u16 = 9347;
const MAX_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct DashboardOptions {
    pub host: String,
    pub port: u16,
    pub session_id: Option<String>,
    pub roots: Vec<PathBuf>,
}

impl Default for DashboardOptions {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: DEFAULT_PORT,
            session_id: None,
            roots: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct DashboardState {
    treeship_dir: PathBuf,
    sessions_root: PathBuf,
    treeships: Vec<TreeshipRoot>,
}

#[derive(Debug, Clone)]
struct TreeshipRoot {
    treeship_dir: PathBuf,
    sessions_root: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
struct TreeshipInstanceSummary {
    ship_id: String,
    name: String,
    root: String,
    sessions_root: String,
    receipts: usize,
    reports: usize,
    proof_packages: usize,
    agents: usize,
    hub_attached: bool,
    agent_members: Vec<TreeshipAgentMember>,
}

#[derive(Debug, Clone, Serialize)]
struct TreeshipAgentMember {
    agent_key: String,
    name: String,
    receipts: usize,
    latest_receipt_url: String,
}

#[derive(Debug, Clone, Serialize)]
struct SessionRow {
    treeship_id: String,
    treeship_name: String,
    session_id: String,
    name: Option<String>,
    status: Option<String>,
    started_at: Option<String>,
    ended_at: Option<String>,
    duration_ms: Option<u64>,
    package_path: String,
    preview_url: String,
    receipt_url: String,
    verification: VerificationSummary,
    agents: usize,
    artifacts: usize,
    events: usize,
    files_written: usize,
    files_read: usize,
    commands: usize,
    tool_invocations: usize,
    sensitive_reads: usize,
    network_connections: usize,
    ports_opened: usize,
    failed_commands: usize,
    has_token_capture: bool,
    has_daemon_evidence: bool,
    has_mcp_evidence: bool,
    has_financial_mcp_evidence: bool,
    findings: usize,
    updated_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct VerificationSummary {
    verdict: String,
    pass: usize,
    warn: usize,
    fail: usize,
}

#[derive(Debug, Clone)]
struct HttpRequest {
    method: String,
    path: String,
}

#[derive(Debug, Clone)]
struct ReviewItem {
    severity: &'static str,
    title: String,
    detail: String,
    fix: Option<String>,
    href: String,
}

#[derive(Debug, Clone, Serialize)]
struct CoverageItem {
    status: &'static str,
    title: &'static str,
    detail: String,
    fix: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
struct AgentWorkSummary {
    agent_key: String,
    name: String,
    role: Option<String>,
    sessions: usize,
    receipts: Vec<AgentReceiptLink>,
    latest_session_id: String,
    latest_session_title: String,
    latest_receipt_url: String,
    tool_calls: u32,
    files_written: usize,
    files_read: usize,
    commands: usize,
    network_connections: usize,
    warnings: usize,
    models: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AgentReceiptLink {
    session_id: String,
    title: String,
    href: String,
}

#[derive(Debug, Clone, Serialize)]
struct CollaborationSummary {
    session_id: String,
    session_title: String,
    from: String,
    to: String,
    edge_type: String,
    artifacts: usize,
    href: String,
}

#[derive(Debug, Clone, Serialize)]
struct StatusSummary {
    runtime: &'static str,
    mode: &'static str,
    bind: &'static str,
    treeships: usize,
    sessions_root: String,
    receipts: usize,
    verified: usize,
    warnings: usize,
    failures: usize,
    agents: usize,
    collaboration_links: usize,
    review_items: usize,
    capabilities_ready: usize,
    capabilities_total: usize,
    hub_attached: bool,
}

pub fn run(opts: DashboardOptions, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let treeship_dir = resolve_treeship_dir()?;
    let sessions_root = treeship_dir.join("sessions");
    let treeships = resolve_dashboard_roots(&treeship_dir, &opts.roots)?;
    let state = DashboardState {
        treeship_dir,
        sessions_root,
        treeships,
    };

    let bind_addr = format!("{}:{}", opts.host, opts.port);
    let listener = TcpListener::bind(&bind_addr)?;
    let actual = listener.local_addr()?;
    let target = match opts.session_id {
        Some(ref id) => format!("http://{actual}/session/{id}"),
        None => format!("http://{actual}/"),
    };

    printer.success("dashboard running", &[]);
    printer.info(&format!("  url:      {target}"));
    printer.info(&format!("  sessions: {}", state.sessions_root.display()));
    printer.info(&format!("  treeships: {}", state.treeships.len()));
    printer.info("  mode:     local-only, read-only");
    printer.blank();
    printer.hint("Press Ctrl+C to stop");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_connection(stream, &state) {
                    eprintln!("dashboard request failed: {e}");
                }
            }
            Err(e) => eprintln!("dashboard accept failed: {e}"),
        }
    }

    Ok(())
}

fn resolve_treeship_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let ts = find_treeship_dir()
        .ok_or("treeship not initialized here -- run `treeship init` from a Treeship workspace")?;
    Ok(ts)
}

fn find_treeship_dir() -> Option<PathBuf> {
    if let Ok(cfg) = std::env::var("TREESHIP_CONFIG") {
        let p = PathBuf::from(cfg);
        if let Some(parent) = p.parent() {
            if parent.is_dir() {
                return Some(parent.to_path_buf());
            }
        }
    }

    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".treeship");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }

    home::home_dir()
        .map(|h| h.join(".treeship"))
        .filter(|p| p.is_dir())
}

fn resolve_dashboard_roots(
    current_treeship_dir: &Path,
    roots: &[PathBuf],
) -> Result<Vec<TreeshipRoot>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    push_dashboard_root(&mut out, current_treeship_dir.to_path_buf())?;
    for root in roots {
        push_dashboard_root(&mut out, normalize_treeship_root(root)?)?;
    }
    Ok(out)
}

fn push_dashboard_root(
    out: &mut Vec<TreeshipRoot>,
    treeship_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let treeship_dir = treeship_dir.canonicalize().unwrap_or(treeship_dir);
    if !treeship_dir.is_dir() {
        return Err(format!("Treeship root not found: {}", treeship_dir.display()).into());
    }
    if !treeship_dir.join("config.json").is_file() {
        return Err(format!(
            "Treeship root is missing config.json: {}",
            treeship_dir.display()
        )
        .into());
    }
    if out.iter().any(|r| r.treeship_dir == treeship_dir) {
        return Ok(());
    }
    let sessions_root = treeship_dir.join("sessions");
    out.push(TreeshipRoot {
        treeship_dir,
        sessions_root,
    });
    Ok(())
}

fn normalize_treeship_root(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if path.file_name().and_then(|s| s.to_str()) == Some("config.json") {
        return path
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| "config path has no parent".into());
    }
    if path.file_name().and_then(|s| s.to_str()) == Some(".treeship") {
        return Ok(path.to_path_buf());
    }
    let candidate = path.join(".treeship");
    if candidate.is_dir() {
        return Ok(candidate);
    }
    Ok(path.to_path_buf())
}

fn handle_connection(
    mut stream: TcpStream,
    state: &DashboardState,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = match read_request(&mut stream)? {
        Some(req) => req,
        None => return Ok(()),
    };

    if req.method != "GET" && req.method != "HEAD" {
        return respond(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
            req.method == "HEAD",
        );
    }

    let (status, content_type, body) = route(&req.path, state);
    respond(
        &mut stream,
        status,
        content_type,
        body.as_slice(),
        req.method == "HEAD",
    )
}

fn read_request(stream: &mut TcpStream) -> Result<Option<HttpRequest>, Box<dyn std::error::Error>> {
    let mut buf = [0u8; MAX_REQUEST_BYTES];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    let raw = String::from_utf8_lossy(&buf[..n]);
    let first = raw.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let path = target.split('?').next().unwrap_or("/").to_string();
    Ok(Some(HttpRequest {
        method,
        path: percent_decode_path(&path),
    }))
}

fn route(path: &str, state: &DashboardState) -> (u16, &'static str, Vec<u8>) {
    match path {
        "/" => {
            let body = render_index(state, None);
            (200, "text/html; charset=utf-8", body.into_bytes())
        }
        "/api/sessions" => {
            let rows = load_sessions(state);
            let body = serde_json::to_vec_pretty(&rows).unwrap_or_else(|_| b"[]".to_vec());
            (200, "application/json; charset=utf-8", body)
        }
        "/api/status" => {
            let status = build_status_summary(state);
            let body = serde_json::to_vec_pretty(&status).unwrap_or_else(|_| b"{}".to_vec());
            (200, "application/json; charset=utf-8", body)
        }
        "/api/treeships" => {
            let rows = load_sessions(state);
            let agents = build_agent_work(state, &rows);
            let instances = build_treeship_instances(state, &rows, &agents);
            let body = serde_json::to_vec_pretty(&instances).unwrap_or_else(|_| b"[]".to_vec());
            (200, "application/json; charset=utf-8", body)
        }
        "/api/agents" => {
            let rows = load_sessions(state);
            let agents = build_agent_work(state, &rows);
            let body = serde_json::to_vec_pretty(&agents).unwrap_or_else(|_| b"[]".to_vec());
            (200, "application/json; charset=utf-8", body)
        }
        "/api/collaboration" => {
            let rows = load_sessions(state);
            let links = build_collaboration(state, &rows);
            let body = serde_json::to_vec_pretty(&links).unwrap_or_else(|_| b"[]".to_vec());
            (200, "application/json; charset=utf-8", body)
        }
        "/api/capabilities" => {
            let rows = load_sessions(state);
            let capabilities = build_coverage_items(state, &rows);
            let body = serde_json::to_vec_pretty(&capabilities).unwrap_or_else(|_| b"[]".to_vec());
            (200, "application/json; charset=utf-8", body)
        }
        "/favicon.ico" => (204, "image/x-icon", Vec::new()),
        _ if path.starts_with("/session/") => {
            let id = path.trim_start_matches("/session/").trim_matches('/');
            if id.is_empty() {
                return not_found();
            }
            serve_receipt_report(state, id)
        }
        _ if path.starts_with("/package/") => {
            let rest = path.trim_start_matches("/package/");
            let mut parts = rest.splitn(2, '/');
            let id = parts.next().unwrap_or("");
            let rel = parts.next().unwrap_or("preview.html");
            if id.is_empty() || rel.is_empty() {
                return not_found();
            }
            serve_package_file(state, id, rel)
        }
        _ => not_found(),
    }
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if !head_only {
        stream.write_all(body)?;
    }
    Ok(())
}

fn not_found() -> (u16, &'static str, Vec<u8>) {
    (404, "text/plain; charset=utf-8", b"not found".to_vec())
}

fn load_sessions(state: &DashboardState) -> Vec<SessionRow> {
    let mut rows = Vec::new();
    for root in &state.treeships {
        if !root.sessions_root.is_dir() {
            continue;
        }
        let Ok(entries) = fs::read_dir(&root.sessions_root) else {
            continue;
        };
        let (treeship_id, treeship_name) = ship_identity_from_dir(&root.treeship_dir);
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("treeship") {
                continue;
            }
            if !path.is_dir() || !path.join("receipt.json").is_file() {
                continue;
            }
            if let Some(row) = session_row(&path, &treeship_id, &treeship_name) {
                rows.push(row);
            }
        }
    }

    rows.sort_by(|a, b| {
        b.ended_at
            .cmp(&a.ended_at)
            .then_with(|| b.started_at.cmp(&a.started_at))
            .then_with(|| b.updated_unix_ms.cmp(&a.updated_unix_ms))
    });
    rows
}

fn session_row(pkg_dir: &Path, treeship_id: &str, treeship_name: &str) -> Option<SessionRow> {
    let receipt = read_package(pkg_dir).ok()?;
    let checks = verify_package(pkg_dir).unwrap_or_default();
    let pass = checks
        .iter()
        .filter(|c| c.status == VerifyStatus::Pass)
        .count();
    let warn = checks
        .iter()
        .filter(|c| c.status == VerifyStatus::Warn)
        .count();
    let fail = checks
        .iter()
        .filter(|c| c.status == VerifyStatus::Fail)
        .count();
    let verdict = if fail > 0 {
        "failed"
    } else if warn > 0 {
        "verified-with-warnings"
    } else {
        "verified"
    };

    let se = &receipt.side_effects;
    let sensitive_reads = sensitive_file_count(se);
    let network_connections = se.network_connections.len();
    let ports_opened = se.ports_opened.len();
    let failed_commands = se
        .processes
        .iter()
        .filter(|p| p.exit_code.map_or(false, |code| code != 0))
        .count();
    let has_daemon_evidence = receipt
        .timeline
        .iter()
        .any(|e| e.agent_name == "treeship-daemon")
        || se
            .files_read
            .iter()
            .any(|f| f.source.as_deref() == Some("daemon-atime"))
        || se
            .files_written
            .iter()
            .any(|f| f.source.as_deref() == Some("daemon-atime"));
    let has_mcp_evidence = se
        .tool_invocations
        .iter()
        .any(|t| t.tool_name.contains("mcp"))
        || se
            .files_read
            .iter()
            .any(|f| f.source.as_deref() == Some("mcp"))
        || se
            .files_written
            .iter()
            .any(|f| f.source.as_deref() == Some("mcp"))
        || se
            .processes
            .iter()
            .any(|p| p.source.as_deref() == Some("mcp"));
    let has_financial_mcp_evidence = has_financial_mcp_evidence(&receipt);
    let has_token_capture =
        receipt.session.total_tokens_in > 0 || receipt.session.total_tokens_out > 0;
    let findings = sensitive_reads + network_connections + ports_opened + failed_commands;
    let session_id = receipt.session.id.clone();

    Some(SessionRow {
        treeship_id: treeship_id.to_string(),
        treeship_name: treeship_name.to_string(),
        session_id: session_id.clone(),
        name: receipt.session.name.clone(),
        status: Some(format!("{:?}", receipt.session.status).to_lowercase()),
        started_at: Some(receipt.session.started_at.clone()),
        ended_at: receipt.session.ended_at.clone(),
        duration_ms: receipt.session.duration_ms,
        package_path: pkg_dir.display().to_string(),
        preview_url: format!("/session/{session_id}"),
        receipt_url: format!("/package/{session_id}/receipt.json"),
        verification: VerificationSummary {
            verdict: verdict.into(),
            pass,
            warn,
            fail,
        },
        agents: receipt.agent_graph.nodes.len(),
        artifacts: receipt.artifacts.len(),
        events: receipt.timeline.len(),
        files_written: se.files_written.len(),
        files_read: se.files_read.len(),
        commands: se.processes.len(),
        tool_invocations: se.tool_invocations.len(),
        sensitive_reads,
        network_connections,
        ports_opened,
        failed_commands,
        has_token_capture,
        has_daemon_evidence,
        has_mcp_evidence,
        has_financial_mcp_evidence,
        findings,
        updated_unix_ms: modified_unix_ms(pkg_dir),
    })
}

fn sensitive_file_count(se: &treeship_core::session::SideEffects) -> usize {
    se.files_read
        .iter()
        .filter(|f| sensitive_path(&f.file_path))
        .count()
}

fn modified_unix_ms(path: &Path) -> u128 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

fn serve_package_file(
    state: &DashboardState,
    session_id: &str,
    rel: &str,
) -> (u16, &'static str, Vec<u8>) {
    let Some(pkg_dir) = package_dir_for(state, session_id) else {
        return not_found();
    };
    let Some(path) = safe_join(&pkg_dir, rel) else {
        return not_found();
    };
    if !path.is_file() {
        return not_found();
    }
    match fs::read(&path) {
        Ok(bytes) => (200, content_type(&path), bytes),
        Err(_) => (
            500,
            "text/plain; charset=utf-8",
            b"failed to read file".to_vec(),
        ),
    }
}

fn serve_receipt_report(state: &DashboardState, session_id: &str) -> (u16, &'static str, Vec<u8>) {
    let Some(pkg_dir) = package_dir_for(state, session_id) else {
        return not_found();
    };
    match read_package(&pkg_dir) {
        Ok(receipt) => {
            let html = render_preview_html(&receipt);
            (200, "text/html; charset=utf-8", html.into_bytes())
        }
        Err(_) => serve_package_file(state, session_id, "preview.html"),
    }
}

fn package_dir_for(state: &DashboardState, session_id: &str) -> Option<PathBuf> {
    if !session_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    for root in &state.treeships {
        let path = root.sessions_root.join(format!("{session_id}.treeship"));
        if path.is_dir() {
            return Some(path);
        }
    }
    None
}

fn safe_join(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() {
        return Some(root.join("preview.html"));
    }
    let mut out = root.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains('\\') {
            return None;
        }
        out.push(part);
    }
    Some(out)
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn percent_decode_path(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(a * 16 + b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn render_index(state: &DashboardState, selected: Option<&str>) -> String {
    let rows = load_sessions(state);
    let failures = rows.iter().filter(|r| r.verification.fail > 0).count();
    let review_items = build_review_items(&rows);
    let risk_items = review_items.iter().filter(|i| i.severity == "risk").count();
    let warn_items = review_items.iter().filter(|i| i.severity == "warn").count();
    let info_items = review_items.iter().filter(|i| i.severity == "info").count();
    let coverage_items = build_coverage_items(state, &rows);
    let agent_work = build_agent_work(state, &rows);
    let collaboration = build_collaboration(state, &rows);
    let treeships = build_treeship_instances(state, &rows, &agent_work);
    let coverage_ready = coverage_items.iter().filter(|i| i.status == "ok").count();
    let latest = selected
        .and_then(|id| rows.iter().find(|r| r.session_id == id))
        .or_else(|| rows.first());

    let mut h = String::new();
    h.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Treeship Dashboard</title>");
    h.push_str("<style>");
    h.push_str(":root{--bg:#10100f;--panel:#171715;--panel2:#20201d;--line:#2d2c28;--text:#ece9e3;--muted:#9d998f;--faint:#666158;--ok:#56b685;--warn:#d79b51;--risk:#db6868;--info:#69a7d8;--accent:#72c2ad;--mono:'SF Mono','JetBrains Mono',monospace;--font:Inter,'Segoe UI',system-ui,sans-serif}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:18px}body{margin:0;background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.5}a{color:inherit;text-decoration:none}code{font-family:var(--mono);font-size:12px}.shell{font-family:var(--mono)}.layout{display:grid;grid-template-columns:280px 1fr;min-height:100dvh}.rail{border-right:1px solid var(--line);padding:24px 18px;position:sticky;top:0;height:100dvh;overflow:auto}.brand{font-weight:750;font-size:18px;margin-bottom:4px}.sub{color:var(--muted);font-size:12px;margin-bottom:24px}.main{padding:28px 28px 58px;min-width:0}.home{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(320px,.65fr);gap:16px;margin-bottom:18px}.home h1{margin:10px 0 8px;font-size:34px;letter-spacing:-.04em;line-height:1.08}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px}.pad{padding:18px}.kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.kpi{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:14px}.label{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}.value{font-size:28px;font-weight:760;letter-spacing:-.04em}.btn{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:7px;padding:8px 11px;color:var(--text);background:var(--panel2);font-weight:650;font-size:12px}.btn:hover{border-color:#45433d}.btn.primary{background:rgba(114,194,173,.12);border-color:rgba(114,194,173,.38);color:var(--accent)}.session{display:block;padding:12px;border:1px solid transparent;border-radius:8px;margin-bottom:8px}.session:hover,.session.active{background:var(--panel2);border-color:var(--line)}.session[hidden],.issue[hidden]{display:none}.session-title{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.session-meta{font-family:var(--mono);font-size:11px;color:var(--faint);margin-top:2px}.badge{display:inline-flex;align-items:center;border-radius:99px;padding:2px 7px;font-family:var(--mono);font-size:10px;font-weight:700;text-transform:uppercase}.ok{background:rgba(86,182,133,.12);color:var(--ok);border:1px solid rgba(86,182,133,.3)}.warn{background:rgba(215,155,81,.12);color:var(--warn);border:1px solid rgba(215,155,81,.3)}.risk{background:rgba(219,104,104,.12);color:var(--risk);border:1px solid rgba(219,104,104,.3)}.info{background:rgba(105,167,216,.12);color:var(--info);border:1px solid rgba(105,167,216,.3)}.section{margin-top:18px}.section-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-end;margin:0 0 10px}.section-title{font-size:18px;font-weight:760;letter-spacing:-.03em}.section-sub{font-size:12px;color:var(--muted)}.answer-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.answer-card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:15px;min-height:145px}.answer-title{font-size:15px;font-weight:760;margin:9px 0 5px}.priority-list{display:grid;gap:8px;margin-top:14px}.priority{display:grid;grid-template-columns:auto 1fr;gap:10px;align-items:start;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--panel2)}.priority strong{display:block}.ship-grid{display:grid;grid-template-columns:1fr;gap:10px}.ship-card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px}.ship-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.ship-title{font-size:18px;font-weight:760;letter-spacing:-.03em}.member-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:14px}.member{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:12px;min-width:0}.member-name{font-weight:740;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.issue{display:grid;grid-template-columns:92px 1fr auto;gap:14px;align-items:start;padding:14px;border-top:1px solid var(--line)}.issue:first-child{border-top:0}.issue-title{font-weight:740}.issue-detail{font-size:12px;color:var(--muted);margin-top:2px}.fix{font-family:var(--mono);font-size:11px;color:var(--accent);background:rgba(114,194,173,.08);border:1px solid rgba(114,194,173,.2);border-radius:6px;padding:6px 8px;white-space:nowrap}.health{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.health-row{padding:14px;border-radius:8px;border:1px solid var(--line);background:var(--panel)}.health-row.okish{border-color:rgba(86,182,133,.22)}.health-row.warnish{border-color:rgba(215,155,81,.28)}.health-row.riskish{border-color:rgba(219,104,104,.28)}.agent-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.agent-card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px;min-width:0}.agent-name{font-size:16px;font-weight:760;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.statline{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;color:var(--muted);font-family:var(--mono);font-size:11px}.edge-row{display:grid;grid-template-columns:1fr auto 1fr auto;gap:12px;align-items:center;padding:13px 14px;border-top:1px solid var(--line)}.edge-row:first-child{border-top:0}.edge-node{font-weight:740;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.edge-type{font-family:var(--mono);font-size:10px;color:var(--accent);border:1px solid rgba(114,194,173,.25);border-radius:99px;padding:3px 7px;text-transform:uppercase}.proof-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.proof-step{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}.proof-step:before{content:attr(data-step);display:inline-flex;width:20px;height:20px;align-items:center;justify-content:center;border-radius:50%;background:rgba(114,194,173,.12);color:var(--accent);font-family:var(--mono);font-size:11px;margin-bottom:10px}.status-strip{position:fixed;left:280px;right:0;bottom:0;display:flex;gap:14px;align-items:center;justify-content:space-between;padding:9px 28px;background:rgba(16,16,15,.94);border-top:1px solid var(--line);backdrop-filter:blur(10px);z-index:20}.status-group{display:flex;gap:12px;align-items:center;min-width:0}.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px rgba(86,182,133,.12)}.api-row,.filterbar{display:flex;gap:8px;flex-wrap:wrap}.seg{border:1px solid var(--line);border-radius:999px;background:var(--panel2);color:var(--muted);font:700 11px var(--mono);padding:6px 9px;cursor:pointer}.seg.active{color:var(--accent);border-color:rgba(114,194,173,.38);background:rgba(114,194,173,.1)}.search{width:100%;border:1px solid var(--line);border-radius:7px;background:var(--panel2);color:var(--text);font:12px var(--mono);padding:9px 10px;margin-bottom:10px;outline:none}.search:focus{border-color:rgba(114,194,173,.45)}.countline{font:11px var(--mono);color:var(--faint);margin:6px 0 10px}.rail-details{margin-top:14px}.rail-details summary{cursor:pointer;color:var(--muted);font-size:13px;padding:7px 10px;border-radius:7px}.rail-details[open] summary,.rail-details summary:hover{background:var(--panel2);color:var(--text)}.table{width:100%;border-collapse:collapse}.table th{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);text-align:left;padding:10px;border-bottom:1px solid var(--line)}.table td{padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:middle}.muted{color:var(--muted)}.faint{color:var(--faint)}.empty{display:grid;place-items:center;min-height:180px;color:var(--muted);text-align:center}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.rail-link{display:block;color:var(--muted);font-size:13px;padding:7px 10px;border-radius:7px}.rail-link:hover{background:var(--panel2);color:var(--text)}@media(max-width:1100px){.agent-grid,.proof-grid,.answer-grid,.member-grid{grid-template-columns:1fr 1fr}.edge-row{grid-template-columns:1fr}}@media(max-width:920px){.layout{grid-template-columns:1fr}.rail{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line)}.home{grid-template-columns:1fr}.kpis,.health{grid-template-columns:1fr 1fr}.issue{grid-template-columns:1fr}.main{padding:16px 16px 74px}.status-strip{left:0;padding:9px 16px;align-items:flex-start;flex-direction:column}}@media(max-width:640px){.kpis,.health,.agent-grid,.proof-grid,.answer-grid,.member-grid{grid-template-columns:1fr}.fix{white-space:normal}}");
    h.push_str("</style></head><body><div class=\"layout\"><aside class=\"rail\"><div class=\"brand\">treeship</div><div class=\"sub\">Local dashboard - read-only - localhost</div>");
    h.push_str("<div class=\"label\" style=\"margin:0 0 8px\">Workspace</div>");
    h.push_str("<a class=\"rail-link\" href=\"#overview\">Overview</a>");
    h.push_str("<a class=\"rail-link\" href=\"#treeships\">Treeship instances</a>");
    h.push_str("<a class=\"rail-link\" href=\"#review\">Review queue</a>");
    h.push_str("<a class=\"rail-link\" href=\"#agents\">Agent evidence</a>");
    h.push_str("<a class=\"rail-link\" href=\"#coverage\">Setup health</a>");
    h.push_str("<a class=\"rail-link\" href=\"/api/status\">Status API</a>");
    h.push_str("<details class=\"rail-details\"><summary>Receipts (");
    h.push_str(&rows.len().to_string());
    h.push_str(")</summary>");
    if rows.is_empty() {
        h.push_str("<div class=\"muted\" style=\"font-size:13px\">No sealed receipts yet.</div>");
    } else {
        h.push_str("<input class=\"search\" id=\"receiptSearch\" type=\"search\" placeholder=\"Search receipts\" aria-label=\"Search receipts\"><div class=\"countline\" id=\"receiptCount\">");
        h.push_str(&format!("{} shown", rows.len().min(30)));
        h.push_str("</div>");
        for row in rows.iter().take(30) {
            let active = latest.map(|r| r.session_id.as_str()) == Some(row.session_id.as_str());
            let cls = if active { "session active" } else { "session" };
            h.push_str(&format!(
                "<a class=\"{cls}\" data-search=\"{search}\" href=\"/session/{id}\"><div class=\"session-title\">{title}</div><div class=\"session-meta\">{id}</div><div style=\"margin-top:7px\">{badge}</div></a>",
                id = esc(&row.session_id),
                title = esc(row.name.as_deref().unwrap_or(&row.session_id)),
                search = esc(&format!(
                    "{} {} {}",
                    row.session_id,
                    row.name.as_deref().unwrap_or(""),
                    row.status.as_deref().unwrap_or("")
                )),
                badge = verdict_badge(&row.verification),
            ));
        }
    }
    h.push_str("</details>");
    h.push_str("</aside><main class=\"main\">");

    let hero_badge = if failures > 0 {
        "<span class=\"badge risk\">action required</span>"
    } else if review_items.is_empty() {
        "<span class=\"badge ok\">ready to share</span>"
    } else {
        "<span class=\"badge warn\">review recommended</span>"
    };
    let hero_title = if failures > 0 {
        "Some receipts need verification before you trust them"
    } else if review_items.is_empty() {
        "Your local receipts are clean"
    } else {
        "Your receipts verify, but a few signals need review"
    };
    let hero_copy = if failures > 0 {
        "Start with failed checks. A failed package should not be shared until it verifies locally."
    } else if review_items.is_empty() {
        "No failed checks or obvious review items were found in indexed receipts."
    } else {
        "Nothing is failing, but warnings can make future receipts more useful for teams, audits, and agent accountability."
    };

    h.push_str("<section class=\"home\" id=\"overview\"><div class=\"panel pad\"><div style=\"display:flex;justify-content:space-between;gap:12px;align-items:flex-start\"><div class=\"label\">Can I trust this?</div>");
    h.push_str(hero_badge);
    h.push_str("</div><h1>");
    h.push_str(hero_title);
    h.push_str("</h1><p class=\"muted\" style=\"max-width:72ch;margin:0\">");
    h.push_str(hero_copy);
    h.push_str("</p><div class=\"answer-grid\" style=\"margin-top:16px\">");
    h.push_str(&render_answer_card(
        "Trust",
        if failures > 0 {
            "risk"
        } else if review_items.is_empty() {
            "ok"
        } else {
            "warn"
        },
        if failures > 0 {
            "Blocked"
        } else if review_items.is_empty() {
            "Clean"
        } else {
            "Local pass"
        },
        &format!(
            "{} receipt(s), {} failed check(s), {} warning item(s).",
            rows.len(),
            failures,
            warn_items
        ),
    ));
    h.push_str(&render_answer_card(
        "Attention",
        if risk_items > 0 {
            "risk"
        } else if warn_items > 0 {
            "warn"
        } else {
            "info"
        },
        &format!("{} review item(s)", review_items.len()),
        "Open the queue only when you need to fix or share proof.",
    ));
    h.push_str(&render_answer_card(
        "Attribution",
        if agent_work.is_empty() { "warn" } else { "ok" },
        &format!("{} agent(s)", agent_work.len()),
        "Each agent is attached to this Treeship through the receipts it produced.",
    ));
    h.push_str("</div><div class=\"actions\">");
    if let Some(row) = latest {
        h.push_str("<a class=\"btn primary\" href=\"");
        h.push_str(&esc(&row.preview_url));
        h.push_str("\">Open latest receipt</a>");
    }
    h.push_str("<a class=\"btn\" href=\"#review\">Review issues</a><a class=\"btn\" href=\"#agents\">See agents</a></div></div>");

    h.push_str(&render_priority_panel(
        latest,
        &review_items,
        &coverage_items,
        risk_items,
        warn_items,
        info_items,
        failures,
    ));
    h.push_str("</section>");

    h.push_str(&render_treeship_instances(&treeships));

    h.push_str("<section class=\"section\"><div class=\"section-head\"><div><div class=\"section-title\">Deeper evidence</div><div class=\"section-sub\">The instance view answers where work belongs. Open these when you need proof details.</div></div></div></section>");

    h.push_str("<details class=\"panel section\" id=\"agents\" style=\"padding:14px\"><summary style=\"cursor:pointer;list-style:none;display:flex;justify-content:space-between;gap:16px;align-items:center\"><span><span class=\"section-title\">Agent work map</span><span class=\"section-sub\" style=\"display:block\">Which agent did what, across sealed receipts.</span></span><span class=\"badge info\">");
    h.push_str(&format!("{} agents", agent_work.len()));
    h.push_str("</span></summary><div style=\"margin-top:14px\">");
    if agent_work.is_empty() {
        h.push_str("<div class=\"panel empty\"><div><div style=\"font-weight:700;color:var(--text);margin-bottom:4px\">No agent identities captured yet</div><div>Open a sealed receipt with agent graph data, or attach an agent runtime so Treeship can attribute actions.</div></div></div>");
    } else {
        h.push_str("<div class=\"agent-grid\">");
        for agent in agent_work.iter().take(9) {
            h.push_str(&render_agent_work(agent));
        }
        h.push_str("</div>");
    }
    h.push_str("</div></details>");

    h.push_str("<details class=\"panel section\" id=\"collaboration\" style=\"padding:14px\"><summary style=\"cursor:pointer;list-style:none;display:flex;justify-content:space-between;gap:16px;align-items:center\"><span><span class=\"section-title\">Collaboration and handoffs</span><span class=\"section-sub\" style=\"display:block\">Who worked with whom when receipts capture multi-agent edges.</span></span><span class=\"badge info\">");
    h.push_str(&format!("{} links", collaboration.len()));
    h.push_str("</span></summary><div style=\"margin-top:14px\">");
    if collaboration.is_empty() {
        h.push_str("<div class=\"empty\"><div><div style=\"font-weight:700;color:var(--text);margin-bottom:4px\">No multi-agent edges captured</div><div>Receipts can show parent-child spawns, handoffs, returns, and collaboration when the runtime emits those events.</div></div></div>");
    } else {
        for edge in collaboration.iter().take(14) {
            h.push_str(&render_collaboration(edge));
        }
    }
    h.push_str("</div></details>");

    if let Some(row) = latest {
        h.push_str("<details class=\"panel section\" id=\"anatomy\" style=\"padding:14px\"><summary style=\"cursor:pointer;list-style:none;display:flex;justify-content:space-between;gap:16px;align-items:center\"><span><span class=\"section-title\">Receipt anatomy</span><span class=\"section-sub\" style=\"display:block\">Report, receipt JSON, Merkle proof data, and local verify.</span></span><span class=\"badge ok\">local proof</span></summary><div style=\"margin-top:14px\">");
        h.push_str(&render_receipt_anatomy(state, row));
        h.push_str("</div></details>");
    }

    h.push_str("<section class=\"section\" id=\"review\"><div class=\"section-head\"><div><div class=\"section-title\">Review queue</div><div class=\"section-sub\">The things to inspect before trusting or sharing agent work.</div></div><span class=\"badge ");
    h.push_str(if review_items.is_empty() {
        "ok"
    } else {
        "warn"
    });
    h.push_str("\">");
    h.push_str(&format!("{} items", review_items.len()));
    h.push_str("</span></div><div class=\"panel pad\" style=\"margin-bottom:10px\"><div class=\"label\">How to read this</div><div class=\"issue-detail\">");
    if risk_items > 0 {
        h.push_str("Risk items are possible trust blockers. Review those before sharing a receipt outside your machine.");
    } else if warn_items > 0 {
        h.push_str("No blocking risk is queued. Warnings usually mean the receipt verifies but deserves a quick human check.");
    } else if info_items > 0 {
        h.push_str("The queue is mostly evidence-quality guidance: ways to make future receipts more useful.");
    } else {
        h.push_str("No review items are queued for indexed receipts.");
    }
    h.push_str("</div></div><div class=\"filterbar\" style=\"margin-bottom:10px\"><button class=\"seg active\" data-review-filter=\"all\">All</button><button class=\"seg\" data-review-filter=\"risk\">Risk");
    if risk_items > 0 {
        h.push_str(&format!(" {risk_items}"));
    }
    h.push_str("</button><button class=\"seg\" data-review-filter=\"warn\">Warnings");
    if warn_items > 0 {
        h.push_str(&format!(" {warn_items}"));
    }
    h.push_str("</button><button class=\"seg\" data-review-filter=\"info\">Info");
    if info_items > 0 {
        h.push_str(&format!(" {info_items}"));
    }
    h.push_str("</button><span class=\"countline\" id=\"reviewCount\">");
    h.push_str(&format!("{} shown", review_items.len().min(12)));
    h.push_str("</span></div>");
    h.push_str(&render_review_lanes(&review_items));
    h.push_str("<div class=\"panel\">");
    if review_items.is_empty() {
        h.push_str("<div class=\"empty\"><div><div style=\"font-weight:700;color:var(--text);margin-bottom:4px\">No review items found</div><div>Indexed receipts have no failed checks, failed commands, sensitive reads, network calls, or missing capture signals.</div></div></div>");
    } else {
        for item in review_items.iter().take(12) {
            h.push_str(&render_review_item(item));
        }
    }
    h.push_str("</div></section>");

    h.push_str("<details class=\"panel section\" id=\"coverage\" style=\"padding:14px\"><summary style=\"cursor:pointer;list-style:none;display:flex;justify-content:space-between;gap:16px;align-items:center\"><span><span class=\"section-title\">Treeship capabilities</span><span class=\"section-sub\" style=\"display:block\">What this workspace can prove today, and the next command to unlock missing signals.</span></span><span class=\"badge info\">");
    h.push_str(&format!("{coverage_ready}/{} ready", coverage_items.len()));
    h.push_str("</span></summary><div class=\"health\" style=\"margin-top:14px\">");
    for item in &coverage_items {
        h.push_str(&render_coverage_item(item));
    }
    h.push_str("</div></details>");

    h.push_str("<details class=\"panel section\" id=\"receipts\"><summary style=\"cursor:pointer;list-style:none;display:flex;justify-content:space-between;gap:16px;align-items:center;padding:14px\"><span><span class=\"section-title\">All receipts</span><span class=\"section-sub\" style=\"display:block\">Full local receipt index for deeper inspection.</span></span><span class=\"badge info\">");
    h.push_str(&format!("{} receipts", rows.len()));
    h.push_str("</span></summary><table class=\"table\"><thead><tr><th>Receipt</th><th>Trust</th><th>Agents</th><th>Changes</th><th>Commands</th><th></th></tr></thead><tbody>");
    if rows.is_empty() {
        h.push_str("<tr><td colspan=\"6\"><div class=\"empty\"><div><div style=\"font-weight:700;color:var(--text);margin-bottom:4px\">No sealed receipts found</div><div>Run <code>treeship session start</code>, <code>treeship wrap -- &lt;cmd&gt;</code>, then <code>treeship session close</code>.</div></div></div></td></tr>");
    } else {
        for row in &rows {
            h.push_str("<tr><td><div style=\"font-weight:700\">");
            h.push_str(&esc(row.name.as_deref().unwrap_or(&row.session_id)));
            h.push_str("</div><div class=\"shell faint\">");
            h.push_str(&esc(&row.session_id));
            h.push_str("</div></td><td>");
            h.push_str(&verdict_badge(&row.verification));
            h.push_str("</td><td>");
            h.push_str(&row.agents.to_string());
            h.push_str("</td><td>");
            h.push_str(&format!(
                "{} writes - {} reads",
                row.files_written, row.files_read
            ));
            h.push_str("</td><td>");
            h.push_str(&row.commands.to_string());
            h.push_str("</td><td><a class=\"btn\" href=\"");
            h.push_str(&esc(&row.preview_url));
            h.push_str("\">Open</a></td></tr>");
        }
    }
    h.push_str("</tbody></table></details>");
    h.push_str("<footer class=\"faint\" style=\"padding:22px 0\">Serving ");
    h.push_str(&esc(&state.sessions_root.display().to_string()));
    h.push_str("</footer><div class=\"status-strip\"><div class=\"status-group\"><span class=\"dot\"></span><span class=\"shell\">local dashboard</span><span class=\"faint\">read-only</span><span class=\"faint\">");
    h.push_str(&format!("{} receipts", rows.len()));
    h.push_str("</span></div><div class=\"status-group\"><a class=\"btn\" href=\"/api/status\">API</a><span class=\"faint\">");
    h.push_str(&format!(
        "{} review - {}/{} capabilities",
        review_items.len(),
        coverage_ready,
        coverage_items.len()
    ));
    h.push_str("</span></div></div></main></div>");
    h.push_str("<script>");
    h.push_str("(()=>{const q=document.getElementById('receiptSearch');const count=document.getElementById('receiptCount');const receipts=[...document.querySelectorAll('.session[data-search]')];function filterReceipts(){if(!q)return;const term=q.value.trim().toLowerCase();let shown=0;receipts.forEach(el=>{const ok=!term||el.dataset.search.toLowerCase().includes(term);el.hidden=!ok;if(ok)shown++;});if(count)count.textContent=`${shown} shown`;}q?.addEventListener('input',filterReceipts);filterReceipts();const buttons=[...document.querySelectorAll('[data-review-filter]')];const issues=[...document.querySelectorAll('#review .issue[data-severity]')];const reviewCount=document.getElementById('reviewCount');function filterReview(kind){let shown=0;issues.forEach(el=>{const ok=kind==='all'||el.dataset.severity===kind;el.hidden=!ok;if(ok)shown++;});buttons.forEach(b=>b.classList.toggle('active',b.dataset.reviewFilter===kind));if(reviewCount)reviewCount.textContent=`${shown} shown`;}buttons.forEach(b=>b.addEventListener('click',()=>filterReview(b.dataset.reviewFilter)));filterReview('all');})();");
    h.push_str("</script></body></html>");
    h
}

fn render_answer_card(label: &str, status: &str, title: &str, detail: &str) -> String {
    format!(
        "<article class=\"answer-card\"><span class=\"badge {status}\">{label}</span><div class=\"answer-title\">{title}</div><div class=\"issue-detail\">{detail}</div></article>",
        status = esc(status),
        label = esc(label),
        title = esc(title),
        detail = esc(detail)
    )
}

fn render_review_lanes(items: &[ReviewItem]) -> String {
    let blockers = items.iter().filter(|i| i.severity == "risk").count();
    let warnings = items.iter().filter(|i| i.severity == "warn").count();
    let setup = items.iter().filter(|i| i.severity == "info").count();
    let sensitive = items
        .iter()
        .filter(|i| {
            let title = i.title.to_ascii_lowercase();
            title.contains("financial")
                || title.contains("sensitive")
                || title.contains("network")
                || title.contains("port")
        })
        .count();
    let mut h = String::new();
    h.push_str("<div class=\"answer-grid\" style=\"margin-bottom:10px\">");
    h.push_str(&render_answer_card(
        "Blockers",
        if blockers > 0 { "risk" } else { "ok" },
        &format!("{blockers} blocker(s)"),
        if blockers > 0 {
            "Resolve these before sharing or relying on the receipt outside this machine."
        } else {
            "No failed verification or high-risk trust blockers are queued."
        },
    ));
    h.push_str(&render_answer_card(
        "Warnings",
        if warnings > 0 { "warn" } else { "ok" },
        &format!("{warnings} warning(s)"),
        if warnings > 0 {
            "Review these for incomplete evidence, failed commands, or unexpected behavior."
        } else {
            "No warning-level review work is queued."
        },
    ));
    h.push_str(&render_answer_card(
        "Setup gaps",
        if setup > 0 { "info" } else { "ok" },
        &format!("{setup} setup gap(s)"),
        if setup > 0 {
            "Improve future receipts with better model, token, daemon, or Hub capture."
        } else {
            "No setup-quality guidance is queued."
        },
    ));
    h.push_str(&render_answer_card(
        "Sensitive",
        if sensitive > 0 { "risk" } else { "ok" },
        &format!("{sensitive} sensitive item(s)"),
        if sensitive > 0 {
            "Financial, credential, network, or similar activity needs intentional review."
        } else {
            "No sensitive or financial activity is queued in the indexed receipts."
        },
    ));
    h.push_str("</div>");
    h
}

fn render_treeship_instances(instances: &[TreeshipInstanceSummary]) -> String {
    let mut h = String::new();
    h.push_str("<section class=\"section\" id=\"treeships\"><div class=\"section-head\"><div><div class=\"section-title\">Treeship instances</div><div class=\"section-sub\">A Treeship is the local trust container. Agents attach to it and produce receipts, reports, and proof packages inside it.</div></div><span class=\"badge info\">");
    h.push_str(&format!("{} instance(s)", instances.len()));
    h.push_str("</span></div><div class=\"ship-grid\">");
    if instances.is_empty() {
        h.push_str("<div class=\"panel empty\"><div><div style=\"font-weight:700;color:var(--text);margin-bottom:4px\">No Treeship instances found</div><div>Run <code>treeship init</code> in a workspace to create one.</div></div></div>");
    } else {
        for instance in instances {
            h.push_str("<article class=\"ship-card\"><div class=\"ship-head\"><div><div class=\"label\">Current Treeship</div><div class=\"ship-title\">");
            h.push_str(&esc(&instance.name));
            h.push_str("</div><div class=\"shell faint\" style=\"font-size:11px;margin-top:3px\">");
            h.push_str(&esc(&instance.ship_id));
            h.push_str("</div></div><span class=\"badge ");
            h.push_str(if instance.hub_attached { "ok" } else { "info" });
            h.push_str("\">");
            h.push_str(if instance.hub_attached {
                "hub attached"
            } else {
                "local only"
            });
            h.push_str("</span></div><div class=\"statline\"><span>");
            h.push_str(&format!("{} agent(s)", instance.agents));
            h.push_str("</span><span>");
            h.push_str(&format!("{} receipt(s)", instance.receipts));
            h.push_str("</span><span>");
            h.push_str(&format!("{} report(s)", instance.reports));
            h.push_str("</span><span>");
            h.push_str(&format!("{} proof package(s)", instance.proof_packages));
            h.push_str("</span></div><div class=\"issue-detail\">Root: <code>");
            h.push_str(&esc(&instance.root));
            h.push_str("</code></div>");
            if instance.agent_members.is_empty() {
                h.push_str("<div class=\"empty\" style=\"min-height:90px\"><div>No agents have produced receipts in this Treeship yet.</div></div>");
            } else {
                h.push_str("<div class=\"member-grid\">");
                for agent in instance.agent_members.iter().take(9) {
                    h.push_str("<a class=\"member\" href=\"");
                    h.push_str(&esc(&agent.latest_receipt_url));
                    h.push_str("\"><div class=\"member-name\">");
                    h.push_str(&esc(&agent.name));
                    h.push_str("</div><div class=\"shell faint\" style=\"font-size:11px\">");
                    h.push_str(&esc(&agent.agent_key));
                    h.push_str("</div><div class=\"statline\"><span>");
                    h.push_str(&format!("{} receipt(s)", agent.receipts));
                    h.push_str("</span></div></a>");
                }
                h.push_str("</div>");
            }
            h.push_str("</article>");
        }
    }
    h.push_str("</div></section>");
    h
}

fn render_priority_panel(
    latest: Option<&SessionRow>,
    review_items: &[ReviewItem],
    coverage_items: &[CoverageItem],
    risk_items: usize,
    warn_items: usize,
    info_items: usize,
    failures: usize,
) -> String {
    let mut h = String::new();
    let first_href = review_items
        .first()
        .map(|i| i.href.as_str())
        .or_else(|| latest.map(|r| r.preview_url.as_str()))
        .unwrap_or("#receipts");
    let first_title = review_items
        .first()
        .map(|i| i.title.as_str())
        .or_else(|| latest.map(|r| r.name.as_deref().unwrap_or(&r.session_id)))
        .unwrap_or("No receipt selected");
    let first_detail = review_items
        .first()
        .map(|i| i.detail.as_str())
        .unwrap_or("No urgent review item is queued. Open the latest receipt when you want to inspect the proof trail.");
    let capability = coverage_items.iter().find(|i| i.status != "ok");

    h.push_str("<div class=\"panel pad\"><div class=\"label\">Next best action</div><div class=\"priority-list\">");
    h.push_str("<a class=\"priority\" href=\"#review\"><span class=\"badge ");
    h.push_str(if failures > 0 || risk_items > 0 {
        "risk"
    } else if warn_items > 0 || info_items > 0 {
        "warn"
    } else {
        "ok"
    });
    h.push_str("\">1</span><span><strong>");
    if failures > 0 {
        h.push_str("Do not share yet");
    } else if risk_items > 0 {
        h.push_str("Review risk first");
    } else if warn_items > 0 || info_items > 0 {
        h.push_str("Trust locally, review before sharing");
    } else {
        h.push_str("Ready to share");
    }
    h.push_str("</strong><span class=\"issue-detail\">");
    if failures > 0 {
        h.push_str(
            "At least one package check failed. Fix verification before trusting this work.",
        );
    } else if risk_items > 0 {
        h.push_str("Verification passes, but risk items need a human look before this leaves your machine.");
    } else if warn_items > 0 || info_items > 0 {
        h.push_str(
            "Local verification passes. The queue is mostly review and evidence-quality guidance.",
        );
    } else {
        h.push_str("No failed checks or review items are queued for indexed receipts.");
    }
    h.push_str("</span></span></a>");

    h.push_str("<a class=\"priority\" href=\"");
    h.push_str(&esc(first_href));
    h.push_str("\"><span class=\"badge info\">2</span><span><strong>");
    h.push_str(&esc(first_title));
    h.push_str("</strong><span class=\"issue-detail\">");
    h.push_str(&esc(first_detail));
    h.push_str("</span></span></a>");

    h.push_str("<a class=\"priority\" href=\"#coverage\"><span class=\"badge ");
    h.push_str(capability.map(|i| i.status).unwrap_or("ok"));
    h.push_str("\">3</span><span><strong>");
    h.push_str(&esc(capability
        .map(|i| i.title)
        .unwrap_or("Capture looks good")));
    h.push_str("</strong><span class=\"issue-detail\">");
    h.push_str(&esc(capability.map(|i| i.detail.as_str()).unwrap_or("Core local evidence checks are ready. Use the evidence explorer only when you need deeper proof.")));
    h.push_str("</span></span></a></div><div class=\"issue-detail\" style=\"margin-top:14px\">Local-only and read-only from <code>127.0.0.1</code>. The receipt package stays the source of truth.</div></div>");
    h
}

fn verdict_badge(v: &VerificationSummary) -> String {
    if v.fail > 0 {
        format!("<span class=\"badge risk\">{} fail</span>", v.fail)
    } else if v.warn > 0 {
        format!("<span class=\"badge warn\">{} warn</span>", v.warn)
    } else {
        "<span class=\"badge ok\">verified</span>".into()
    }
}

fn build_status_summary(state: &DashboardState) -> StatusSummary {
    let rows = load_sessions(state);
    let verified = rows.iter().filter(|r| r.verification.fail == 0).count();
    let warnings = rows.iter().filter(|r| r.verification.warn > 0).count();
    let failures = rows.iter().filter(|r| r.verification.fail > 0).count();
    let review_items = build_review_items(&rows);
    let capabilities = build_coverage_items(state, &rows);
    let agents = build_agent_work(state, &rows);
    let links = build_collaboration(state, &rows);
    StatusSummary {
        runtime: "treeship-dashboard",
        mode: "local-read-only",
        bind: "127.0.0.1",
        treeships: state.treeships.len(),
        sessions_root: state.sessions_root.display().to_string(),
        receipts: rows.len(),
        verified,
        warnings,
        failures,
        agents: agents.len(),
        collaboration_links: links.len(),
        review_items: review_items.len(),
        capabilities_ready: capabilities.iter().filter(|i| i.status == "ok").count(),
        capabilities_total: capabilities.len(),
        hub_attached: hub_is_attached(&state.treeship_dir),
    }
}

fn build_treeship_instances(
    state: &DashboardState,
    rows: &[SessionRow],
    agents: &[AgentWorkSummary],
) -> Vec<TreeshipInstanceSummary> {
    state
        .treeships
        .iter()
        .map(|root| {
            let (ship_id, name) = ship_identity_from_dir(&root.treeship_dir);
            let instance_rows: Vec<&SessionRow> = rows
                .iter()
                .filter(|row| row.treeship_id == ship_id)
                .collect();
            let agent_members = agents
                .iter()
                .filter_map(|agent| {
                    let receipts: Vec<&AgentReceiptLink> = agent
                        .receipts
                        .iter()
                        .filter(|receipt| {
                            instance_rows
                                .iter()
                                .any(|row| row.session_id == receipt.session_id)
                        })
                        .collect();
                    let latest = receipts.first()?;
                    Some(TreeshipAgentMember {
                        agent_key: agent.agent_key.clone(),
                        name: agent.name.clone(),
                        receipts: receipts.len(),
                        latest_receipt_url: latest.href.clone(),
                    })
                })
                .collect::<Vec<_>>();

            TreeshipInstanceSummary {
                ship_id,
                name,
                root: root
                    .treeship_dir
                    .parent()
                    .unwrap_or(&root.treeship_dir)
                    .display()
                    .to_string(),
                sessions_root: root.sessions_root.display().to_string(),
                receipts: instance_rows.len(),
                reports: instance_rows.len(),
                proof_packages: instance_rows.len(),
                agents: agent_members.len(),
                hub_attached: hub_is_attached(&root.treeship_dir),
                agent_members,
            }
        })
        .collect()
}

fn ship_identity_from_dir(treeship_dir: &Path) -> (String, String) {
    let path = treeship_dir.join("config.json");
    let Ok(raw) = fs::read_to_string(path) else {
        return (
            "local-treeship".into(),
            treeship_dir
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .unwrap_or("local Treeship")
                .to_string(),
        );
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return ("local-treeship".into(), "local Treeship".into());
    };
    let ship_id = value
        .get("ship_id")
        .and_then(|v| v.as_str())
        .unwrap_or("local-treeship")
        .to_string();
    let fallback_name = treeship_dir
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("local Treeship");
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(fallback_name)
        .to_string();
    (ship_id, name)
}

fn build_agent_work(state: &DashboardState, rows: &[SessionRow]) -> Vec<AgentWorkSummary> {
    #[derive(Debug, Default)]
    struct Acc {
        name: String,
        role: Option<String>,
        sessions: usize,
        receipts: Vec<AgentReceiptLink>,
        latest_session_id: String,
        latest_session_title: String,
        latest_receipt_url: String,
        tool_calls: u32,
        files_written: usize,
        files_read: usize,
        commands: usize,
        network_connections: usize,
        warnings: usize,
        models: Vec<String>,
    }

    let mut agents: BTreeMap<String, Acc> = BTreeMap::new();
    for row in rows {
        let Some(receipt) = read_receipt_for_row(state, row) else {
            continue;
        };
        for node in &receipt.agent_graph.nodes {
            let key = if node.agent_instance_id.is_empty() {
                node.agent_id.clone()
            } else {
                node.agent_instance_id.clone()
            };
            if key.is_empty() {
                continue;
            }

            let acc = agents.entry(key).or_default();
            if acc.name.is_empty() {
                acc.name = display_agent_name(node);
            }
            if acc.role.is_none() {
                acc.role = node.agent_role.clone();
            }
            acc.sessions += 1;
            if !acc.receipts.iter().any(|r| r.session_id == row.session_id) {
                acc.receipts.push(AgentReceiptLink {
                    session_id: row.session_id.clone(),
                    title: row.name.clone().unwrap_or_else(|| row.session_id.clone()),
                    href: row.preview_url.clone(),
                });
            }
            if acc.latest_session_id.is_empty() {
                acc.latest_session_id = row.session_id.clone();
                acc.latest_session_title =
                    row.name.clone().unwrap_or_else(|| row.session_id.clone());
                acc.latest_receipt_url = row.preview_url.clone();
            }
            acc.tool_calls += node.tool_calls;
            acc.files_written += receipt
                .side_effects
                .files_written
                .iter()
                .filter(|f| f.agent_instance_id == node.agent_instance_id)
                .count();
            acc.files_read += receipt
                .side_effects
                .files_read
                .iter()
                .filter(|f| f.agent_instance_id == node.agent_instance_id)
                .count();
            acc.commands += receipt
                .side_effects
                .processes
                .iter()
                .filter(|p| p.agent_instance_id == node.agent_instance_id)
                .count();
            let agent_network = receipt
                .side_effects
                .network_connections
                .iter()
                .filter(|n| n.agent_instance_id == node.agent_instance_id)
                .count();
            let agent_ports = receipt
                .side_effects
                .ports_opened
                .iter()
                .filter(|p| p.agent_instance_id == node.agent_instance_id)
                .count();
            let failed = receipt
                .side_effects
                .processes
                .iter()
                .filter(|p| p.agent_instance_id == node.agent_instance_id)
                .filter(|p| p.exit_code.map_or(false, |code| code != 0))
                .count();
            let sensitive = receipt
                .side_effects
                .files_read
                .iter()
                .filter(|f| f.agent_instance_id == node.agent_instance_id)
                .filter(|f| sensitive_path(&f.file_path))
                .count();
            acc.network_connections += agent_network;
            acc.warnings += agent_network + agent_ports + failed + sensitive;
            if let Some(model) = &node.model {
                if !acc.models.contains(model) {
                    acc.models.push(model.clone());
                }
            }
        }
    }

    let mut out: Vec<_> = agents
        .into_iter()
        .map(|(agent_key, acc)| AgentWorkSummary {
            agent_key,
            name: if acc.name.is_empty() {
                "unknown agent".into()
            } else {
                acc.name
            },
            role: acc.role,
            sessions: acc.sessions,
            receipts: acc.receipts,
            latest_session_id: acc.latest_session_id,
            latest_session_title: acc.latest_session_title,
            latest_receipt_url: acc.latest_receipt_url,
            tool_calls: acc.tool_calls,
            files_written: acc.files_written,
            files_read: acc.files_read,
            commands: acc.commands,
            network_connections: acc.network_connections,
            warnings: acc.warnings,
            models: acc.models,
        })
        .collect();
    out.sort_by(|a, b| {
        b.tool_calls
            .cmp(&a.tool_calls)
            .then_with(|| b.files_written.cmp(&a.files_written))
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

fn build_collaboration(state: &DashboardState, rows: &[SessionRow]) -> Vec<CollaborationSummary> {
    let mut edges = Vec::new();
    for row in rows {
        let Some(receipt) = read_receipt_for_row(state, row) else {
            continue;
        };
        let names: BTreeMap<_, _> = receipt
            .agent_graph
            .nodes
            .iter()
            .map(|n| (n.agent_instance_id.as_str(), display_agent_name(n)))
            .collect();
        for edge in &receipt.agent_graph.edges {
            let from = names
                .get(edge.from_instance_id.as_str())
                .cloned()
                .unwrap_or_else(|| edge.from_instance_id.clone());
            let to = names
                .get(edge.to_instance_id.as_str())
                .cloned()
                .unwrap_or_else(|| edge.to_instance_id.clone());
            edges.push(CollaborationSummary {
                session_id: row.session_id.clone(),
                session_title: row.name.clone().unwrap_or_else(|| row.session_id.clone()),
                from,
                to,
                edge_type: format!("{:?}", edge.edge_type).to_ascii_lowercase(),
                artifacts: edge.artifacts.len(),
                href: row.preview_url.clone(),
            });
        }
    }
    edges
}

fn read_receipt_for_row(state: &DashboardState, row: &SessionRow) -> Option<SessionReceipt> {
    package_dir_for(state, &row.session_id).and_then(|p| read_package(&p).ok())
}

fn display_agent_name(node: &treeship_core::session::AgentNode) -> String {
    if !node.agent_name.is_empty() {
        node.agent_name.clone()
    } else if !node.agent_id.is_empty() {
        node.agent_id.clone()
    } else {
        node.agent_instance_id.clone()
    }
}

fn sensitive_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains(".env")
        || p.contains(".ssh")
        || p.contains(".pem")
        || p.contains(".aws")
        || p.contains(".gnupg")
        || p.contains("credentials")
        || p.contains("id_rsa")
        || p.contains("id_ed25519")
}

fn has_financial_mcp_evidence(receipt: &SessionReceipt) -> bool {
    let se = &receipt.side_effects;
    se.tool_invocations
        .iter()
        .any(|t| financial_mcp_signal(&t.tool_name))
        || se
            .network_connections
            .iter()
            .any(|n| financial_mcp_signal(&n.destination))
        || se.processes.iter().any(|p| {
            financial_mcp_signal(&p.process_name)
                || p.command
                    .as_deref()
                    .map(financial_mcp_signal)
                    .unwrap_or(false)
        })
}

fn financial_mcp_signal(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("agent.robinhood.com")
        || value.contains("robinhood-trading")
        || value.contains("robinhood trading")
        || value.contains("trading mcp")
        || (value.contains("robinhood") && value.contains("order"))
}

fn build_review_items(rows: &[SessionRow]) -> Vec<ReviewItem> {
    let mut items = Vec::new();
    let mut missing_token_capture = 0usize;
    let mut first_missing_token_href = None::<String>;
    for row in rows {
        let title = row.name.as_deref().unwrap_or(&row.session_id);
        let href = row.preview_url.clone();
        if row.verification.fail > 0 {
            items.push(ReviewItem {
                severity: "risk",
                title: format!("{title}: verification failed"),
                detail: format!("{} package check(s) failed. Do not share this receipt until it verifies locally.", row.verification.fail),
                fix: Some(format!("treeship package verify {}", row.package_path)),
                href: href.clone(),
            });
        } else if row.verification.warn > 0 {
            items.push(ReviewItem {
                severity: "warn",
                title: format!("{title}: verified with warnings"),
                detail: format!("{} check(s) warned. The receipt may be structurally valid but incomplete or missing some evidence.", row.verification.warn),
                fix: Some(format!("treeship package verify {}", row.package_path)),
                href: href.clone(),
            });
        }
        if row.failed_commands > 0 {
            items.push(ReviewItem {
                severity: "warn",
                title: format!("{title}: failed command captured"),
                detail: format!("{} command(s) exited non-zero. Confirm the final output did not depend on a failed step.", row.failed_commands),
                fix: None,
                href: href.clone(),
            });
        }
        if row.sensitive_reads > 0 {
            items.push(ReviewItem {
                severity: "warn",
                title: format!("{title}: sensitive file read"),
                detail: format!("{} sensitive file read(s) were recorded. Review whether those reads were expected.", row.sensitive_reads),
                fix: None,
                href: href.clone(),
            });
        }
        if row.network_connections > 0 {
            items.push(ReviewItem {
                severity: "risk",
                title: format!("{title}: network access"),
                detail: format!("{} outbound network connection(s) were recorded. Check destination and intent.", row.network_connections),
                fix: None,
                href: href.clone(),
            });
        }
        if row.has_financial_mcp_evidence {
            items.push(ReviewItem {
                severity: "risk",
                title: format!("{title}: financial MCP activity"),
                detail: "Robinhood Trading MCP or order-like activity appears in this receipt. Confirm strategy intent, approval nonce, and account-data handling before trusting or sharing it.".into(),
                fix: Some("treeship template apply robinhood-agentic-trading".into()),
                href: href.clone(),
            });
        }
        if row.ports_opened > 0 {
            items.push(ReviewItem {
                severity: "warn",
                title: format!("{title}: local port opened"),
                detail: format!(
                    "{} port open event(s) were recorded. Confirm they were expected and closed.",
                    row.ports_opened
                ),
                fix: None,
                href: href.clone(),
            });
        }
        if !row.has_token_capture {
            missing_token_capture += 1;
            if first_missing_token_href.is_none() {
                first_missing_token_href = Some(href);
            }
        }
    }
    if missing_token_capture > 0 {
        items.push(ReviewItem {
            severity: "info",
            title: "Model/token capture missing".into(),
            detail: format!("{missing_token_capture} receipt(s) have no token counts. This is not a verification blocker, but builders lose cost, budget, and model accountability without this signal."),
            fix: Some("Set TREESHIP_MODEL, TREESHIP_TOKENS_IN, and TREESHIP_TOKENS_OUT in the agent runtime.".into()),
            href: first_missing_token_href.unwrap_or_else(|| "#coverage".into()),
        });
    }
    items
}

fn build_coverage_items(state: &DashboardState, rows: &[SessionRow]) -> Vec<CoverageItem> {
    let sealed = rows.len();
    let has_daemon = rows.iter().any(|r| r.has_daemon_evidence);
    let has_mcp = rows
        .iter()
        .any(|r| r.has_mcp_evidence || r.tool_invocations > 0);
    let has_financial_mcp = rows.iter().any(|r| r.has_financial_mcp_evidence);
    let has_tokens = rows.iter().any(|r| r.has_token_capture);
    let has_failed = rows.iter().any(|r| r.verification.fail > 0);
    let hub_attached = hub_is_attached(&state.treeship_dir);

    vec![
        CoverageItem {
            status: if sealed > 0 { "ok" } else { "risk" },
            title: "Sealed receipts",
            detail: if sealed > 0 {
                format!("{sealed} sealed .treeship package(s) found locally.")
            } else {
                "No sealed receipts found. Start, wrap, and close a session to create the first report.".into()
            },
            fix: if sealed > 0 {
                None
            } else {
                Some("treeship session start && treeship wrap -- <cmd> && treeship session close")
            },
        },
        CoverageItem {
            status: if has_failed { "risk" } else { "ok" },
            title: "Local verification",
            detail: if has_failed {
                "At least one indexed receipt has failed package checks.".into()
            } else {
                "No failed package checks in indexed receipts.".into()
            },
            fix: if has_failed {
                Some("treeship package verify <path-to-package>")
            } else {
                None
            },
        },
        CoverageItem {
            status: if has_daemon { "ok" } else { "warn" },
            title: "Daemon evidence",
            detail: if has_daemon {
                "Recent receipts include daemon-level evidence.".into()
            } else {
                "No daemon evidence found in indexed receipts. Sensitive reads and background file activity may be thin.".into()
            },
            fix: if has_daemon {
                None
            } else {
                Some("treeship daemon start")
            },
        },
        CoverageItem {
            status: if has_mcp { "ok" } else { "warn" },
            title: "Agent/tool capture",
            detail: if has_mcp {
                "Tool or MCP events appear in indexed receipts.".into()
            } else {
                "No MCP/tool events found. Attach agent runtimes so receipts show tool-level work."
                    .into()
            },
            fix: if has_mcp { None } else { Some("treeship add") },
        },
        CoverageItem {
            status: if has_financial_mcp { "warn" } else { "info" },
            title: "Financial MCP guardrails",
            detail: if has_financial_mcp {
                "Robinhood Trading MCP or order-like activity appears in indexed receipts. Review approvals and sensitive account-data handling.".into()
            } else {
                "No Robinhood Trading MCP activity found. Apply the template before connecting trading agents.".into()
            },
            fix: Some("treeship template apply robinhood-agentic-trading"),
        },
        CoverageItem {
            status: if has_tokens { "ok" } else { "warn" },
            title: "Model and token capture",
            detail: if has_tokens {
                "At least one receipt includes token usage.".into()
            } else {
                "No token usage found. Cost, budget, and model accountability will be weaker."
                    .into()
            },
            fix: if has_tokens {
                None
            } else {
                Some("export TREESHIP_MODEL=... TREESHIP_TOKENS_IN=... TREESHIP_TOKENS_OUT=...")
            },
        },
        CoverageItem {
            status: if hub_attached { "ok" } else { "info" },
            title: "Hub sharing",
            detail: if hub_attached {
                "A Hub connection is configured for publishing shareable receipt URLs.".into()
            } else {
                "Hub is not attached. Local verification works, but sharing URLs requires attach."
                    .into()
            },
            fix: if hub_attached {
                None
            } else {
                Some("treeship hub attach")
            },
        },
    ]
}

fn hub_is_attached(treeship_dir: &Path) -> bool {
    let path = treeship_dir.join("config.json");
    let Ok(bytes) = fs::read(&path) else {
        return false;
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    json.get("active_hub").and_then(|v| v.as_str()).is_some()
        || json.get("active_dock").and_then(|v| v.as_str()).is_some()
}

fn render_agent_work(agent: &AgentWorkSummary) -> String {
    let mut h = String::new();
    h.push_str("<article class=\"agent-card\"><div style=\"display:flex;justify-content:space-between;gap:10px;align-items:flex-start\"><div style=\"min-width:0\"><div class=\"agent-name\">");
    h.push_str(&esc(&agent.name));
    h.push_str("</div><div class=\"shell faint\" style=\"font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis\">");
    h.push_str(&esc(&agent.agent_key));
    h.push_str("</div></div>");
    if agent.warnings > 0 {
        h.push_str(&format!(
            "<span class=\"badge warn\">{} review</span>",
            agent.warnings
        ));
    } else {
        h.push_str("<span class=\"badge ok\">clean</span>");
    }
    h.push_str("</div>");
    if let Some(role) = &agent.role {
        h.push_str("<div class=\"issue-detail\">");
        h.push_str(&esc(role));
        h.push_str("</div>");
    }
    h.push_str("<div class=\"issue-detail\">Latest: ");
    h.push_str(&esc(&agent.latest_session_title));
    h.push_str("</div>");
    h.push_str("<div class=\"statline\"><span>");
    h.push_str(&format!("{} sessions", agent.sessions));
    h.push_str("</span><span>");
    h.push_str(&format!("{} actions", agent.tool_calls));
    h.push_str("</span><span>");
    h.push_str(&format!("{} writes", agent.files_written));
    h.push_str("</span><span>");
    h.push_str(&format!("{} reads", agent.files_read));
    h.push_str("</span><span>");
    h.push_str(&format!("{} commands", agent.commands));
    h.push_str("</span></div>");
    if !agent.models.is_empty() {
        h.push_str("<div class=\"issue-detail\">Model: ");
        h.push_str(&esc(&agent.models.join(", ")));
        h.push_str("</div>");
    }
    if agent.network_connections > 0 {
        h.push_str("<div class=\"issue-detail\" style=\"color:var(--warn)\">Network connections recorded for this agent.</div>");
    }
    h.push_str("<div class=\"actions\"><a class=\"btn primary\" href=\"");
    h.push_str(&esc(&agent.latest_receipt_url));
    h.push_str("\">Latest receipt</a><span class=\"btn shell\">");
    h.push_str(&esc(&agent.latest_session_id));
    h.push_str("</span></div></article>");
    h
}

fn render_collaboration(edge: &CollaborationSummary) -> String {
    let mut h = String::new();
    h.push_str("<div class=\"edge-row\"><div><div class=\"edge-node\">");
    h.push_str(&esc(&edge.from));
    h.push_str("</div><div class=\"shell faint\" style=\"font-size:11px\">");
    h.push_str(&esc(&edge.session_title));
    h.push_str("</div></div><div class=\"edge-type\">");
    h.push_str(&esc(&edge.edge_type));
    h.push_str("</div><div class=\"edge-node\">");
    h.push_str(&esc(&edge.to));
    h.push_str("</div><a class=\"btn\" href=\"");
    h.push_str(&esc(&edge.href));
    h.push_str("\">Receipt</a>");
    if edge.artifacts > 0 {
        h.push_str("<div class=\"shell faint\" style=\"grid-column:1/-1;font-size:11px\">");
        h.push_str(&format!(
            "{} artifact(s) attached - {}",
            edge.artifacts,
            esc(&edge.session_id)
        ));
        h.push_str("</div>");
    }
    h.push_str("</div>");
    h
}

fn render_receipt_anatomy(state: &DashboardState, row: &SessionRow) -> String {
    let receipt = read_receipt_for_row(state, row);
    let merkle_root = receipt
        .as_ref()
        .and_then(|r| r.merkle.root.as_deref())
        .unwrap_or("not present");
    let proof_count = receipt
        .as_ref()
        .map(|r| r.merkle.inclusion_proofs.len())
        .unwrap_or_default();
    let leaf_count = receipt
        .as_ref()
        .map(|r| r.merkle.leaf_count)
        .unwrap_or_default();
    let signatures = receipt
        .as_ref()
        .map(|r| r.proofs.signature_count)
        .unwrap_or_default();

    let mut h = String::new();
    h.push_str("<div class=\"proof-grid\">");
    h.push_str("<div class=\"proof-step\" data-step=\"1\"><div class=\"label\">Report</div><div style=\"font-weight:740;margin-top:4px\">Human-readable work record</div><div class=\"issue-detail\">Open this first to understand what happened, then drill into the JSON when you need exact evidence.</div></div>");
    h.push_str("<div class=\"proof-step\" data-step=\"2\"><div class=\"label\">Receipt JSON</div><div style=\"font-weight:740;margin-top:4px\">Canonical package record</div><div class=\"issue-detail\">Agents, timeline, files, commands, artifacts, participants, and proof metadata live here.</div></div>");
    h.push_str("<div class=\"proof-step\" data-step=\"3\"><div class=\"label\">Merkle</div><div style=\"font-weight:740;margin-top:4px\">Tamper-evident bundle</div><div class=\"issue-detail\">");
    h.push_str(&format!(
        "{} leaves - {} inclusion proofs - root {}",
        leaf_count,
        proof_count,
        esc(short_hash(merkle_root))
    ));
    h.push_str("</div></div>");
    h.push_str("<div class=\"proof-step\" data-step=\"4\"><div class=\"label\">Verify</div><div style=\"font-weight:740;margin-top:4px\">Trust without the dashboard</div><div class=\"issue-detail\">");
    h.push_str(&format!(
        "{} pass - {} warn - {} fail - {} signature(s)",
        row.verification.pass, row.verification.warn, row.verification.fail, signatures
    ));
    h.push_str("</div></div></div>");
    h.push_str("<div class=\"actions\"><a class=\"btn primary\" href=\"");
    h.push_str(&esc(&row.preview_url));
    h.push_str("\">Open report</a><a class=\"btn\" href=\"");
    h.push_str(&esc(&row.receipt_url));
    h.push_str("\">Open receipt.json</a><button class=\"fix\" onclick=\"navigator.clipboard.writeText('treeship package verify ");
    h.push_str(&esc_js(&row.package_path));
    h.push_str("');this.textContent='Copied';setTimeout(()=>this.textContent='treeship package verify ...',1500)\">treeship package verify ...</button></div>");
    h
}

fn render_review_item(item: &ReviewItem) -> String {
    let mut h = String::new();
    h.push_str("<div class=\"issue\" data-severity=\"");
    h.push_str(&esc(item.severity));
    h.push_str("\"><div>");
    h.push_str(&format!(
        "<span class=\"badge {}\">{}</span>",
        item.severity, item.severity
    ));
    h.push_str("</div><div><a class=\"issue-title\" href=\"");
    h.push_str(&esc(&item.href));
    h.push_str("\">");
    h.push_str(&esc(&item.title));
    h.push_str("</a><div class=\"issue-detail\">");
    h.push_str(&esc(&item.detail));
    h.push_str("</div></div>");
    if let Some(fix) = &item.fix {
        h.push_str("<button class=\"fix\" onclick=\"navigator.clipboard.writeText('");
        h.push_str(&esc_js(fix));
        h.push_str("');this.textContent='Copied';setTimeout(()=>this.textContent='");
        h.push_str(&esc_js(fix));
        h.push_str("',1500)\">");
        h.push_str(&esc(fix));
        h.push_str("</button>");
    } else {
        h.push_str("<a class=\"btn\" href=\"");
        h.push_str(&esc(&item.href));
        h.push_str("\">Open</a>");
    }
    h.push_str("</div>");
    h
}

fn render_coverage_item(item: &CoverageItem) -> String {
    let cls = match item.status {
        "ok" => "okish",
        "risk" => "riskish",
        _ => "warnish",
    };
    let badge = match item.status {
        "ok" => "ok",
        "risk" => "risk",
        "info" => "info",
        _ => "warn",
    };
    let mut h = String::new();
    h.push_str(&format!("<div class=\"health-row {cls}\"><div style=\"display:flex;justify-content:space-between;gap:10px;align-items:flex-start\"><div><div class=\"label\">{}</div><div style=\"font-weight:740;margin-top:4px\">{}</div></div><span class=\"badge {badge}\">{}</span></div><div class=\"issue-detail\">{}</div>",
        esc(item.title),
        esc(item.title),
        esc(item.status),
        esc(&item.detail),
    ));
    if let Some(fix) = item.fix {
        h.push_str("<div class=\"actions\"><button class=\"fix\" onclick=\"navigator.clipboard.writeText('");
        h.push_str(&esc_js(fix));
        h.push_str("');this.textContent='Copied';setTimeout(()=>this.textContent='");
        h.push_str(&esc_js(fix));
        h.push_str("',1500)\">");
        h.push_str(&esc(fix));
        h.push_str("</button></div>");
    }
    h.push_str("</div>");
    h
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn esc_js(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "")
}

fn short_hash(s: &str) -> &str {
    if s.len() > 18 {
        &s[..18]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> DashboardState {
        let root = PathBuf::from("/tmp/treeship-test/.treeship");
        DashboardState {
            treeship_dir: root.clone(),
            sessions_root: root.join("sessions"),
            treeships: vec![TreeshipRoot {
                treeship_dir: root.clone(),
                sessions_root: root.join("sessions"),
            }],
        }
    }

    fn test_row(session_id: &str, treeship_id: &str, agents: usize) -> SessionRow {
        SessionRow {
            treeship_id: treeship_id.into(),
            treeship_name: "test ship".into(),
            session_id: session_id.into(),
            name: Some("demo receipt".into()),
            status: Some("completed".into()),
            started_at: Some("2026-05-28T00:00:00Z".into()),
            ended_at: Some("2026-05-28T00:00:01Z".into()),
            duration_ms: Some(1000),
            package_path: format!("/tmp/{session_id}.treeship"),
            preview_url: format!("/session/{session_id}"),
            receipt_url: format!("/package/{session_id}/receipt.json"),
            verification: VerificationSummary {
                verdict: "verified".into(),
                pass: 3,
                warn: 0,
                fail: 0,
            },
            agents,
            artifacts: 1,
            events: 1,
            files_written: 0,
            files_read: 0,
            commands: 1,
            tool_invocations: 1,
            sensitive_reads: 0,
            network_connections: 0,
            ports_opened: 0,
            failed_commands: 0,
            has_token_capture: false,
            has_daemon_evidence: false,
            has_mcp_evidence: true,
            has_financial_mcp_evidence: false,
            findings: 0,
            updated_unix_ms: 1,
        }
    }

    #[test]
    fn route_serves_dashboard_and_read_only_apis() {
        let state = test_state();

        let (status, content_type, body) = route("/", &state);
        let html = String::from_utf8(body).expect("dashboard html");
        assert_eq!(status, 200);
        assert_eq!(content_type, "text/html; charset=utf-8");
        assert!(html.contains("Treeship instances"));
        assert!(html.contains("Agent evidence"));

        let (status, content_type, body) = route("/api/status", &state);
        let json = String::from_utf8(body).expect("status json");
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json; charset=utf-8");
        assert!(json.contains("\"runtime\": \"treeship-dashboard\""));
        assert!(json.contains("\"mode\": \"local-read-only\""));

        let (status, _, _) = route("/missing", &state);
        assert_eq!(status, 404);
    }

    #[test]
    fn route_serves_documented_json_endpoints() {
        let state = test_state();

        for path in [
            "/api/sessions",
            "/api/treeships",
            "/api/agents",
            "/api/collaboration",
            "/api/capabilities",
        ] {
            let (status, content_type, body) = route(path, &state);
            let json = String::from_utf8(body).expect("json body");

            assert_eq!(status, 200, "{path}");
            assert_eq!(content_type, "application/json; charset=utf-8", "{path}");
            assert!(
                json.trim_start().starts_with('['),
                "{path} should return a JSON array"
            );
        }
    }

    #[test]
    fn treeship_instances_keep_agents_inside_their_ship() {
        let state = test_state();
        let (ship_id, _) = ship_identity_from_dir(&state.treeships[0].treeship_dir);
        let rows = vec![test_row("ssn_demo", &ship_id, 1)];
        let agents = vec![AgentWorkSummary {
            agent_key: "agent://codex".into(),
            name: "Codex".into(),
            role: Some("agent".into()),
            sessions: 1,
            receipts: vec![AgentReceiptLink {
                session_id: "ssn_demo".into(),
                title: "demo receipt".into(),
                href: "/session/ssn_demo".into(),
            }],
            latest_session_id: "ssn_demo".into(),
            latest_session_title: "demo receipt".into(),
            latest_receipt_url: "/session/ssn_demo".into(),
            tool_calls: 7,
            files_written: 2,
            files_read: 3,
            commands: 4,
            network_connections: 0,
            warnings: 0,
            models: vec!["gpt-5".into()],
        }];

        let instances = build_treeship_instances(&state, &rows, &agents);

        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].receipts, 1);
        assert_eq!(instances[0].agents, 1);
        assert_eq!(instances[0].agent_members[0].name, "Codex");
        assert_eq!(
            instances[0].agent_members[0].latest_receipt_url,
            "/session/ssn_demo"
        );
    }
}
