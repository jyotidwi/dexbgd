pub mod alias_dialog;
pub mod bytecodes;
pub mod comment_dialog;
pub mod command;
pub mod locals;
pub mod log;
pub mod statusbar;
pub mod tabbed;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};

use crate::app::App;
use crate::theme::Theme;

/// Computed layout border positions (for mouse hit-testing).
pub struct LayoutGeometry {
    /// X position of the vertical border between left and right panels.
    pub vsplit_x: u16,
    /// Y range where the vertical split border is active (top panels area).
    pub vsplit_y_start: u16,
    pub vsplit_y_end: u16,

    /// Y position of the horizontal border between top panels and log.
    pub hsplit_y: u16,
    /// X range for the horizontal split (full width).
    pub hsplit_x_start: u16,
    pub hsplit_x_end: u16,

    /// Y position of the horizontal border between locals and tabbed (right panel).
    pub right_hsplit_y: u16,
    /// X range for the right panel horizontal split.
    pub right_hsplit_x_start: u16,
    pub right_hsplit_x_end: u16,

    /// Total area for ratio computation.
    pub total_width: u16,
    pub total_height: u16,

    /// Status bar area (for click hit-testing).
    pub statusbar_area: Rect,

    /// Individual panel areas (for tab click detection).
    pub bytecodes_area: Rect,
    pub locals_area: Rect,
    pub tabbed_area: Rect,
    pub log_area: Rect,
    pub command_area: Rect,
}

/// Draw the full TUI layout. Returns geometry for mouse hit-testing.
pub fn draw(f: &mut Frame, app: &App) -> LayoutGeometry {
    use ratatui::style::Style;
    use ratatui::widgets::Block;

    // Fill entire frame with the theme background so the TUI doesn't inherit
    // the terminal's system color (matters on Linux where the default is not black).
    let size = f.area();
    f.render_widget(Block::default().style(Style::default().bg(app.theme.ui_bg)), size);

    // Compute pixel sizes from ratios
    // Available height for top+log (minus 4 for command frame + status)
    let available_h = size.height.saturating_sub(4);
    let top_h = ((available_h as f32) * app.split_v).round() as u16;
    let top_h = top_h.max(3).min(available_h.saturating_sub(3));
    let log_h = available_h.saturating_sub(top_h);

    // Horizontal split
    let left_w = ((size.width as f32) * app.split_h).round() as u16;
    let left_w = left_w.max(10).min(size.width.saturating_sub(10));

    // Right panel vertical split
    let locals_h = ((top_h as f32) * app.split_right_v).round() as u16;
    let locals_h = locals_h.max(3).min(top_h.saturating_sub(3));
    let tabbed_h = top_h.saturating_sub(locals_h);

    // Main vertical split: top panels | log | command | status
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top_h),
            Constraint::Length(log_h),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(size);

    // Top area: left (bytecodes) | right (locals + tabbed)
    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(left_w),
            Constraint::Min(10),
        ])
        .split(main_chunks[0]);

    // Right panel: locals (top) | tabbed (bottom)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(locals_h),
            Constraint::Length(tabbed_h),
        ])
        .split(top_chunks[1]);

    // Compute geometry for mouse hit-testing
    let geom = LayoutGeometry {
        vsplit_x: top_chunks[1].x,
        vsplit_y_start: main_chunks[0].y,
        vsplit_y_end: main_chunks[0].y + main_chunks[0].height,

        hsplit_y: main_chunks[1].y,
        hsplit_x_start: size.x,
        hsplit_x_end: size.x + size.width,

        right_hsplit_y: right_chunks[1].y,
        right_hsplit_x_start: top_chunks[1].x,
        right_hsplit_x_end: top_chunks[1].x + top_chunks[1].width,

        total_width: size.width,
        total_height: size.height,

        statusbar_area: main_chunks[3],

        bytecodes_area: top_chunks[0],
        locals_area: right_chunks[0],
        tabbed_area: right_chunks[1],
        log_area: main_chunks[1],
        command_area: main_chunks[2],
    };

    // Draw each panel
    bytecodes::draw(f, app, top_chunks[0]);
    locals::draw(f, app, right_chunks[0]);
    tabbed::draw(f, app, right_chunks[1]);
    log::draw(f, app, main_chunks[1]);
    command::draw(f, app, main_chunks[2]);
    statusbar::draw(f, app, main_chunks[3]);

    // Draw context menu overlay (on top of everything)
    if let Some(menu) = &app.context_menu {
        draw_context_menu(f, menu, size, &app.theme);
    }

    // Draw comment dialog overlay (on top of everything)
    if app.comment_open {
        comment_dialog::render(f, size, app);
    }
    // Draw alias/rename dialog overlay
    if app.alias_open {
        alias_dialog::render(f, size, app);
    }

    geom
}

/// Render a context menu popup as an overlay.
fn draw_context_menu(f: &mut Frame, menu: &crate::app::ContextMenu, bounds: Rect, t: &Theme) {
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Clear, Paragraph};

    let max_item = menu.items.iter().map(|s| s.len()).max().unwrap_or(14);
    let menu_w = (max_item as u16 + 4).max(18); // +4 for borders + padding
    let menu_h = menu.items.len() as u16 + 2; // +2 for borders

    // Clamp position so menu stays within terminal
    let x = menu.x.min(bounds.width.saturating_sub(menu_w));
    let y = menu.y.min(bounds.height.saturating_sub(menu_h));

    let area = Rect::new(x, y, menu_w, menu_h);

    // Clear the area first
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.ui_accent))
        .style(Style::default().bg(t.ui_bg));

    let lines: Vec<Line> = menu.items.iter().enumerate().map(|(i, item)| {
        if i == menu.selected {
            Line::from(Span::styled(
                item.clone(),
                Style::default()
                    .fg(t.ui_bg)
                    .bg(t.ui_accent)
                    .add_modifier(Modifier::BOLD),
            ))
        } else {
            Line::from(Span::styled(
                item.clone(),
                Style::default().fg(t.ui_text).bg(t.ui_bg),
            ))
        }
    }).collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

/// Total number of focusable panels (0=bytecodes, 1=locals, 2=tabbed, 3=log, 4=command).
pub const PANEL_COUNT: usize = 5;

/// Helper to create a bordered block with optional highlight.
pub fn make_block<'a>(title: impl Into<ratatui::text::Line<'a>>, focused: bool, t: &Theme) -> ratatui::widgets::Block<'a> {
    use ratatui::style::Style;
    use ratatui::widgets::{Block, Borders};

    let border_style = if focused {
        Style::default().fg(t.ui_accent)
    } else {
        Style::default().fg(t.ui_dim)
    };

    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style)
}
