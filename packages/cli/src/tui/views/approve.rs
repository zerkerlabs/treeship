use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::tui::app::{App, View};
use crate::tui::widgets::status_bar;

const GREEN: Color = Color::Rgb(34, 197, 94);
const YELLOW: Color = Color::Rgb(250, 204, 21);
const DIM: Color = Color::Rgb(100, 100, 100);
const WHITE: Color = Color::White;

pub fn render(frame: &mut Frame, app: &App) {
    let size = frame.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(1)])
        .split(size);

    render_pending_list(frame, outer[0], app);
    status_bar::render(frame, outer[1], &View::Approve);
}

fn render_pending_list(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let block = Block::default()
        .title(" PENDING APPROVALS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM));

    if app.pending.is_empty() {
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No pending approvals",
                Style::default().fg(DIM),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  When agents request approval, they will appear here.",
                Style::default().fg(DIM),
            )),
        ];
        let para = Paragraph::new(lines).block(block);
        frame.render_widget(para, area);
        return;
    }

    let items: Vec<ListItem> = app
        .pending
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let indicator = if i == app.pending_selected {
                "> "
            } else {
                "  "
            };
            let actor_str = p.actor.as_deref().unwrap_or("unknown");

            let line = Line::from(vec![
                Span::styled(indicator, Style::default().fg(WHITE)),
                Span::styled(
                    format!("#{} ", i + 1),
                    Style::default().fg(YELLOW),
                ),
                Span::styled(
                    format!("{} ", actor_str),
                    Style::default().fg(DIM),
                ),
                Span::styled("wants to: ", Style::default().fg(DIM)),
                Span::styled(&p.command, Style::default().fg(WHITE)),
                Span::styled(
                    format!("  (waiting {})", p.waiting_str),
                    Style::default().fg(DIM),
                ),
            ]);

            ListItem::new(vec![
                line,
                Line::from(vec![
                    Span::styled("     label: ", Style::default().fg(DIM)),
                    Span::styled(&p.label, Style::default().fg(WHITE)),
                ]),
                Line::from(""),
            ])
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.pending_selected));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .fg(WHITE)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, area, &mut state);
}
