use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    widgets::{Block, Borders, Clear, Paragraph},
    text::Line,
    Frame,
};

use crate::app::App;
use crate::commands::short_class;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;

    let popup_area = centered_rect(60, 30, area);
    frame.render_widget(Clear, popup_area);

    let sig = app.alias_target.as_deref().unwrap_or("?");
    let title = format!(" Rename: {} ", short_class(sig));

    let block = Block::default()
        .title(Line::from(title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.ui_accent))
        .style(Style::default().bg(t.ui_current_bg));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Full sig line for context
    let sig_para = Paragraph::new(sig)
        .style(Style::default().fg(t.ui_dim))
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(sig_para, Rect { x: inner.x, y: inner.y, width: inner.width, height: 1 });

    // Input box
    let cursor = app.comment_cursor.min(app.comment_input.len());
    let input_text = format!("{}\u{2502}{}", &app.comment_input[..cursor], &app.comment_input[cursor..]);
    let input_area = Rect { x: inner.x, y: inner.y + 2, width: inner.width, height: 3 };

    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.ui_accent));
    frame.render_widget(input_block, input_area);

    let text_area = Rect {
        x: input_area.x + 1,
        y: input_area.y + 1,
        width: input_area.width.saturating_sub(2),
        height: 1,
    };
    let input = Paragraph::new(input_text)
        .style(Style::default().fg(t.ui_text));
    frame.render_widget(input, text_area);

    // Help line
    let help = Paragraph::new("Enter to save  Esc to cancel  empty = remove alias")
        .style(Style::default().fg(t.ui_dim))
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(
        help,
        Rect { x: inner.x, y: inner.y + inner.height - 2, width: inner.width, height: 1 },
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
