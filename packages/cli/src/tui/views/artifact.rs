use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::app::{self, App, View};
use crate::tui::widgets::status_bar;

const GREEN: Color = Color::Rgb(34, 197, 94);
const RED: Color = Color::Rgb(239, 68, 68);
const DIM: Color = Color::Rgb(100, 100, 100);
const WHITE: Color = Color::White;
const BLUE: Color = Color::Rgb(147, 197, 253);

pub fn render(frame: &mut Frame, app: &App, idx: usize) {
    let size = frame.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(1)])
        .split(size);

    render_detail(frame, outer[0], app, idx);
    status_bar::render(frame, outer[1], &View::ArtifactDetail(idx));
}

fn render_detail(frame: &mut Frame, area: ratatui::layout::Rect, app: &App, idx: usize) {
    let artifact = match app.artifacts.get(idx) {
        Some(a) => a,
        None => {
            let block = Block::default()
                .title(" ARTIFACT ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DIM));
            let para = Paragraph::new(Line::from(Span::styled(
                "  artifact not found",
                Style::default().fg(RED),
            )))
            .block(block);
            frame.render_widget(para, area);
            return;
        }
    };

    let title = format!(" ARTIFACT {} ", app::short_id(&artifact.id));
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM));

    let exit_style = if artifact.exit_code == 0 {
        Style::default().fg(GREEN)
    } else {
        Style::default().fg(RED)
    };

    let exit_label = if artifact.exit_code == 0 {
        "success"
    } else {
        "failure"
    };

    let elapsed_str = app::format_elapsed(artifact.elapsed_ms);

    let mut lines = vec![
        Line::from(""),
        field_line("  id:       ", &artifact.id, BLUE),
        field_line("  type:     ", &artifact.artifact_type, WHITE),
        field_line("  actor:    ", &artifact.actor, WHITE),
        field_line("  action:   ", &artifact.action, WHITE),
        field_line("  time:     ", &artifact.timestamp, DIM),
        field_line("  elapsed:  ", &elapsed_str, DIM),
        Line::from(vec![
            Span::styled("  exit:     ", Style::default().fg(DIM)),
            Span::styled(
                format!("{}  ({})", artifact.exit_code, exit_label),
                exit_style,
            ),
        ]),
        Line::from(""),
    ];

    // Chain info
    if let Some(ref parent) = artifact.parent_id {
        lines.push(field_line("  parent:   ", parent, DIM));
    } else {
        lines.push(field_line("  parent:   ", "(root)", DIM));
    }

    // Find chain depth
    let depth = app
        .artifacts
        .iter()
        .position(|a| a.id == artifact.id)
        .map(|i| i + 1)
        .unwrap_or(0);
    let depth_str = format!("{} of {}", depth, app.artifacts.len());
    lines.push(field_line("  depth:    ", &depth_str, DIM));

    lines.push(Line::from(""));

    let para = Paragraph::new(lines).block(block);
    frame.render_widget(para, area);
}

fn field_line<'a>(label: &'a str, value: &'a str, value_color: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(label, Style::default().fg(DIM)),
        Span::styled(value, Style::default().fg(value_color)),
    ])
}
