use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::ai::AiState;
use crate::app::{App, AppState, LeftTab, LocalsTab, RightTab};

/// Actions that can be triggered by clicking on status bar buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusBarAction {
    Connect,  // F1
    ToggleBp, // F2
    Run,      // F5
    Pause,    // F6
    StepIn,   // F7
    StepOver, // F8
    StepOut,  // F9
    Rec,      // F10
    Quit,     // q
}

/// Button definitions with their text and corresponding action.
const BUTTONS: &[(&str, StatusBarAction)] = &[
    ("F1:Conn", StatusBarAction::Connect),
    ("F2:BP", StatusBarAction::ToggleBp),
    ("F5:Run", StatusBarAction::Run),
    ("F6:Pause", StatusBarAction::Pause),
    ("F7:In", StatusBarAction::StepIn),
    ("F8:Over", StatusBarAction::StepOver),
    ("F9:Out", StatusBarAction::StepOut),
    ("S-F10:Rec", StatusBarAction::Rec),
    ("q:Quit", StatusBarAction::Quit),
];

/// Check if a click at (x, y) is on a status bar button and return the action.
pub fn get_clicked_action(x: u16, y: u16, area: Rect, app: &App) -> Option<StatusBarAction> {
    if y != area.y || x < area.x || x >= area.x + area.width {
        return None;
    }

    let prefix_len = calculate_prefix_length(app);
    let buttons_start_x = area.x + prefix_len as u16;

    if x < buttons_start_x {
        return None;
    }

    let rel_x = (x - buttons_start_x) as usize;

    let mut current_pos = 0usize;
    for (i, (text, action)) in BUTTONS.iter().enumerate() {
        let button_len = text.len();
        if rel_x >= current_pos && rel_x < current_pos + button_len {
            return Some(*action);
        }
        current_pos += button_len;
        if i < BUTTONS.len() - 1 {
            current_pos += 3; // " | "
        }
    }

    None
}

fn panel_name(app: &App) -> &'static str {
    if app.command_focused {
        return "Command";
    }
    match app.focus {
        0 => match app.left_tab {
            LeftTab::Bytecodes => "Bytecodes",
            LeftTab::Decompiler => "Decompiler",
            LeftTab::Trace => "Trace",
            LeftTab::Ai => "AI",
            LeftTab::JniMonitor => "JNI",
        },
        1 => match app.locals_tab {
            LocalsTab::Locals => "Locals",
            LocalsTab::Registers => "Registers",
        },
        2 => match app.right_tab {
            RightTab::Stack => "Stack",
            RightTab::Breakpoints => "Breakpoints",
            RightTab::Threads => "Threads",
            RightTab::Watch => "Watch",
            RightTab::Heap => "Heap",
            RightTab::Bookmarks => "Bookmarks",
        },
        3 => "Log",
        _ => "?",
    }
}

fn calculate_prefix_length(app: &App) -> usize {
    let status_text = match app.state {
        AppState::Disconnected => "DISCONNECTED",
        AppState::Connected => "RUNNING",
        AppState::Suspended => "SUSPENDED",
        AppState::Stepping => "STEPPING",
    };

    let panel = panel_name(app);

    // " STATUS " + optional " REC " + optional " AI " + " " + "Panel: X" + " │ "
    let mut len = format!(" {} ", status_text).len();
    if app.recording_active {
        len += " REC ".len();
    }
    match app.ai_state {
        AiState::Running => len += " AI ".len(),
        AiState::WaitingApproval => len += " AI? ".len(),
        AiState::Idle => {}
    }
    len += 1 + format!("Panel: {}", panel).len() + 3;

    // Thread + location
    let thread_name = app.current_thread.as_deref().unwrap_or("");
    if !thread_name.is_empty() {
        len += thread_name.len() + 1; // "thread "
    }

    let location = build_location(app);
    if !location.is_empty() {
        len += location.len() + 1;
    }

    len += 3; // " │ " before mouse

    // Mouse status
    if app.mouse_enabled {
        len += "[Mouse:ON] ".len();
    } else {
        len += "[Mouse:OFF] ".len();
        len += "(F12) ".len();
    }

    len
}

fn build_location(app: &App) -> String {
    if let (Some(cls), Some(meth)) = (&app.current_class, &app.current_method) {
        let short = crate::commands::short_class(cls);
        if let Some(line) = app.current_line {
            if line >= 0 {
                return format!("{}.{}:{}", short, meth, line);
            }
        }
        format!("{}.{}", short, meth)
    } else {
        String::new()
    }
}

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let (state_text, state_fg, state_bg) = match app.state {
        AppState::Disconnected => ("DISCONNECTED", Color::White, Color::Red),
        AppState::Connected => ("RUNNING", Color::Black, Color::Green),
        AppState::Suspended => ("SUSPENDED", Color::Black, Color::Yellow),
        AppState::Stepping => ("STEPPING", Color::White, Color::Magenta),
    };

    let panel = panel_name(app);
    let location = build_location(app);
    let thread_name = app.current_thread.as_deref().unwrap_or("");
    let mut spans = vec![
        // State badge
        Span::styled(
            format!(" {} ", state_text),
            Style::default()
                .fg(state_fg)
                .bg(state_bg)
                .add_modifier(Modifier::BOLD),
        ),
    ];

    // REC indicator when recording is active
    if app.recording_active {
        spans.push(Span::styled(
            " REC ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ));
    }

    // AI indicator
    match app.ai_state {
        AiState::Running => {
            spans.push(Span::styled(
                " AI ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        AiState::WaitingApproval => {
            spans.push(Span::styled(
                " AI? ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        AiState::Idle => {}
    }

    spans.push(Span::raw(" "));
    // Panel focus
    spans.push(Span::styled(
        format!("Panel: {}", panel),
        Style::default().fg(t.ui_accent),
    ));
    spans.push(Span::styled(" \u{2502} ", Style::default().fg(Color::Gray))); // │

    // Thread name
    if !thread_name.is_empty() {
        spans.push(Span::styled(
            thread_name.to_string(),
            Style::default().fg(Color::LightBlue),
        ));
        spans.push(Span::raw(" "));
    }

    // Location
    if !location.is_empty() {
        spans.push(Span::styled(
            location,
            Style::default().fg(t.ui_text),
        ));
        spans.push(Span::raw(" "));
    }

    spans.push(Span::styled(" \u{2502} ", Style::default().fg(Color::Gray))); // │

    // Mouse status
    if app.mouse_enabled {
        spans.push(Span::styled(
            "[Mouse:ON] ",
            Style::default().fg(Color::Green),
        ));
    } else {
        spans.push(Span::styled(
            "[Mouse:OFF] ",
            Style::default().fg(Color::Red).bg(Color::DarkGray),
        ));
        spans.push(Span::styled(
            "(F12) ",
            Style::default().fg(Color::Gray),
        ));
    }

    // Clickable button bar
    for (i, (text, _action)) in BUTTONS.iter().enumerate() {
        spans.push(Span::styled(
            text.to_string(),
            Style::default().fg(t.ui_text).add_modifier(Modifier::BOLD),
        ));
        if i < BUTTONS.len() - 1 {
            spans.push(Span::styled(
                " | ",
                Style::default().fg(t.ui_dim),
            ));
        }
    }

    let line = Line::from(spans);
    let bar = Paragraph::new(line)
        .style(Style::default().bg(t.ui_bg).fg(t.ui_dim));
    f.render_widget(bar, area);
}
