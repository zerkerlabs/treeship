use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::tui::app::View;

const DIM: Color = Color::Rgb(100, 100, 100);
const KEY_COLOR: Color = Color::Rgb(180, 180, 180);

pub fn render(frame: &mut Frame, area: Rect, view: &View) {
    let hints: Vec<(&str, &str)> = match view {
        View::Dashboard => vec![
            ("^/v", "select"),
            ("enter", "detail"),
            ("l", "log"),
            ("a", "approve"),
            ("q", "quit"),
        ],
        View::Log => vec![
            ("^/v", "scroll"),
            ("enter", "detail"),
            ("d", "dashboard"),
            ("q", "quit"),
        ],
        View::ArtifactDetail(_) => vec![
            ("esc", "back"),
            ("d", "dashboard"),
            ("l", "log"),
            ("q", "quit"),
        ],
        View::Approve => vec![
            ("^/v", "select"),
            ("esc", "back"),
            ("d", "dashboard"),
            ("q", "quit"),
        ],
    };

    let mut spans = Vec::new();
    for (i, (key, desc)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", Style::default().fg(DIM)));
        }
        spans.push(Span::styled(
            format!("[{}]", key),
            Style::default().fg(KEY_COLOR),
        ));
        spans.push(Span::styled(
            format!(" {}", desc),
            Style::default().fg(DIM),
        ));
    }

    let bar = Paragraph::new(Line::from(spans));
    frame.render_widget(bar, area);
}
