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

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(1)])
        .split(size);

    render_log_list(frame, outer[0], app);
    status_bar::render(frame, outer[1], &View::Log);
}

fn render_log_list(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" LOG ")
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

    // Show artifacts in reverse order (newest at bottom)
    let reversed: Vec<&crate::tui::app::ArtifactEntry> =
        app.artifacts.iter().rev().collect();

    let items: Vec<ListItem> = reversed
        .iter()
        .enumerate()
        .map(|(_i, a)| {
            let exit_style = if a.exit_code == 0 {
                Style::default().fg(GREEN)
            } else {
                Style::default().fg(RED)
            };

            let dot = if a.exit_code == 0 { "*" } else { "x" };
            let elapsed = app::format_elapsed(a.elapsed_ms);
            let short = app::short_id(&a.id);

            // Extract time portion from timestamp
            let time = a
                .timestamp
                .split('T')
                .nth(1)
                .and_then(|t| t.split('Z').next())
                .and_then(|t| t.split('.').next())
                .unwrap_or(&a.timestamp);

            let main_line = Line::from(vec![
                Span::styled(format!("  {} ", time), Style::default().fg(DIM)),
                Span::styled(format!("{} ", dot), exit_style),
                Span::styled(
                    format!("{:<7} ", a.artifact_type),
                    Style::default().fg(Color::Rgb(147, 197, 253)),
                ),
                Span::styled(
                    format!("{:<22} ", a.action),
                    Style::default().fg(WHITE),
                ),
                Span::styled(
                    format!("exit {} ", a.exit_code),
                    exit_style,
                ),
                Span::styled(format!("{:>7}  ", elapsed), Style::default().fg(DIM)),
                Span::styled(short, Style::default().fg(DIM)),
            ]);

            ListItem::new(main_line)
        })
        .collect();

    let mut state = ListState::default();
    // Select the corresponding item in the reversed list
    if !app.artifacts.is_empty() {
        let rev_idx = app.artifacts.len().saturating_sub(1).saturating_sub(app.selected);
        state.select(Some(rev_idx));
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .fg(WHITE)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, area, &mut state);
}
