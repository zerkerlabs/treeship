use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::tui::app::{self, App, View};
use crate::tui::widgets::status_bar;

const GREEN: Color = Color::Rgb(34, 197, 94);
const RED: Color = Color::Rgb(239, 68, 68);
const DIM: Color = Color::Rgb(100, 100, 100);
const WHITE: Color = Color::White;

pub fn render(frame: &mut Frame, app: &App) {
    let size = frame.area();

    // Top-level vertical split: header (3), body (rest), status bar (1)
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(size);

    render_header(frame, outer[0], app);
    render_body(frame, outer[1], app);
    status_bar::render(frame, outer[2], &View::Dashboard);
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let hub_indicator = if app.hub_status == "attached" {
        Span::styled("attached", Style::default().fg(GREEN))
    } else {
        Span::styled("not attached", Style::default().fg(DIM))
    };

    let dot = if app.hub_status == "attached" {
        Span::styled(" * ", Style::default().fg(GREEN))
    } else {
        Span::styled(" o ", Style::default().fg(DIM))
    };

    let line = Line::from(vec![
        Span::styled("  ship: ", Style::default().fg(DIM)),
        Span::styled(&app.ship_id, Style::default().fg(WHITE)),
        Span::styled("  |  key: ", Style::default().fg(DIM)),
        Span::styled(app::short_id(&app.key_id), Style::default().fg(WHITE)),
        Span::styled("  | ", Style::default().fg(DIM)),
        dot,
        hub_indicator,
    ]);

    let block = Block::default()
        .title(" TREESHIP ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM));

    let header = Paragraph::new(line).block(block);
    frame.render_widget(header, area);
}

fn render_body(frame: &mut Frame, area: Rect, app: &App) {
    // Horizontal split: left panel (30%), right panel (70%)
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    render_left_panel(frame, cols[0], app);
    render_right_panel(frame, cols[1], app);
}

fn render_left_panel(frame: &mut Frame, area: Rect, app: &App) {
    // Split left panel into: session, pending, hub
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Min(4),
        ])
        .split(area);

    // Session
    {
        let block = Block::default()
            .title(" SESSION ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(DIM));

        let lines = if let Some(ref s) = app.session {
            vec![
                Line::from(Span::styled(
                    s.name.as_deref().unwrap_or("(unnamed)"),
                    Style::default().fg(WHITE),
                )),
                Line::from(Span::styled(
                    format!("running {}", s.elapsed_str),
                    Style::default().fg(DIM),
                )),
                Line::from(Span::styled(
                    format!("{} artifacts", s.artifact_count),
                    Style::default().fg(DIM),
                )),
                Line::from(Span::styled(
                    format!("id: {}", app::short_id(&s.session_id)),
                    Style::default().fg(DIM),
                )),
            ]
        } else {
            vec![
                Line::from(Span::styled("no active session", Style::default().fg(DIM))),
                Line::from(""),
                Line::from(Span::styled(
                    "treeship session start",
                    Style::default().fg(DIM),
                )),
            ]
        };

        let para = Paragraph::new(lines).block(block);
        frame.render_widget(para, sections[0]);
    }

    // Pending approvals
    {
        let block = Block::default()
            .title(" PENDING ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(DIM));

        let lines = if app.pending.is_empty() {
            vec![Line::from(Span::styled("none", Style::default().fg(DIM)))]
        } else {
            vec![
                Line::from(Span::styled(
                    format!("{} pending", app.pending.len()),
                    Style::default().fg(Color::Rgb(250, 204, 21)),
                )),
                Line::from(Span::styled(
                    "press [a] to review",
                    Style::default().fg(DIM),
                )),
            ]
        };

        let para = Paragraph::new(lines).block(block);
        frame.render_widget(para, sections[1]);
    }

    // Hub status
    {
        let block = Block::default()
            .title(" HUB ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(DIM));

        let lines = if app.hub_status == "attached" {
            vec![
                Line::from(vec![
                    Span::styled("* ", Style::default().fg(GREEN)),
                    Span::styled(&app.hub_endpoint, Style::default().fg(WHITE)),
                ]),
                Line::from(Span::styled("attached", Style::default().fg(GREEN))),
            ]
        } else {
            vec![
                Line::from(Span::styled("o not attached", Style::default().fg(DIM))),
                Line::from(Span::styled(
                    "treeship hub attach",
                    Style::default().fg(DIM),
                )),
            ]
        };

        let para = Paragraph::new(lines).block(block);
        frame.render_widget(para, sections[2]);
    }
}

fn render_right_panel(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" RECENT ARTIFACTS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM));

    if app.artifacts.is_empty() {
        let para = Paragraph::new(Line::from(Span::styled(
            "  no artifacts yet",
            Style::default().fg(DIM),
        )))
        .block(block);
        frame.render_widget(para, area);
        return;
    }

    let items: Vec<ListItem> = app
        .artifacts
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let exit_style = if a.exit_code == 0 {
                Style::default().fg(GREEN)
            } else {
                Style::default().fg(RED)
            };

            let dot = if a.exit_code == 0 { "*" } else { "x" };

            let elapsed = app::format_elapsed(a.elapsed_ms);
            let short = app::short_id(&a.id);
            let ts = a.timestamp.split('T').next().unwrap_or(&a.timestamp);

            let line = Line::from(vec![
                Span::styled(
                    if i == app.selected { "> " } else { "  " },
                    Style::default().fg(WHITE),
                ),
                Span::styled(format!("{} ", dot), exit_style),
                Span::styled(format!("{:<16} ", short), Style::default().fg(DIM)),
                Span::styled(
                    format!("{:<5} ", a.artifact_type),
                    Style::default().fg(Color::Rgb(147, 197, 253)),
                ),
                Span::styled(
                    format!("{:<20} ", a.action),
                    Style::default().fg(WHITE),
                ),
                Span::styled(
                    format!("{:>3} ", a.exit_code),
                    exit_style,
                ),
                Span::styled(
                    format!("{:>7} ", elapsed),
                    Style::default().fg(DIM),
                ),
                Span::styled(ts, Style::default().fg(DIM)),
            ]);

            ListItem::new(line)
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.selected));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .fg(WHITE)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, area, &mut state);
}
