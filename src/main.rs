use rustyline::Result as RustylineResult;

mod cli;
mod network;

use cli::run_app;

fn main() -> RustylineResult<()> {
    run_app()
}
