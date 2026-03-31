mod app;
mod views;
mod widgets;

use app::App;

pub fn run(config: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load context
    let ctx = crate::ctx::open(config)?;

    // 2. Build initial app state from local store
    let mut app = App::new(&ctx)?;

    // 3. Setup terminal
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    // 4. Main loop
    loop {
        terminal.draw(|frame| app.render(frame))?;

        if crossterm::event::poll(std::time::Duration::from_millis(500))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                app.handle_key(key);
            }
        }

        // Refresh data every 2 seconds
        app.maybe_refresh(&ctx)?;

        if app.should_quit {
            break;
        }
    }

    // 5. Restore terminal
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )?;

    Ok(())
}
