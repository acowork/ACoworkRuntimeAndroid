//! acowork-runtime CLI entry point
use acowork_runtime::cli::Cli;
use clap::Parser;

fn main() -> acowork_runtime::error::Result<()> {
    let cli = Cli::parse();
    cli.run()
}
