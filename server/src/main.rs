mod ai;
mod ai_claude;
mod ai_ollama;
mod ai_tools;
mod app;
mod commands;
mod condition;
mod config;
mod connection;
mod debugger;
mod dex_parser;
mod dex_patcher;
mod disassembler;
mod protocol;
mod session;
mod theme;
mod tui;

use std::io;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

fn main() -> io::Result<()> {
    let config = config::Config::load();

    // Setup terminal
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run app
    let result = run_app(&mut terminal, config);

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }

    Ok(())
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, config: config::Config) -> io::Result<()> {
    let mut app = app::App::new(config);

    while app.running {
        let geom_cell = std::cell::Cell::new(None);
        terminal.draw(|f| {
            geom_cell.set(Some(tui::draw(f, &app)));
        })?;
        app.layout_geom = geom_cell.into_inner();
        app.tick();

        // Handle mouse capture toggle (F12)
        if app.mouse_toggled {
            app.mouse_toggled = false;
            if app.mouse_enabled {
                execute!(terminal.backend_mut(), EnableMouseCapture)?;
            } else {
                execute!(terminal.backend_mut(), DisableMouseCapture)?;
            }
        }
    }

    Ok(())
}
