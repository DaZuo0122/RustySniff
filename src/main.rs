use rustyline::Result as RustylineResult;

pub mod cli;

use cli::run_app;

fn main() -> RustylineResult<()> {
    run_app()
}
