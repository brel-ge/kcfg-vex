use kcfg_vex::cli::run_cli;
use tracing::{error, info, Level};
use tracing_subscriber::fmt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    fmt().with_max_level(Level::DEBUG).init();

    info!("Starting kcfg-vex");

    if let Err(e) = run_cli() {
        error!("Application error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
