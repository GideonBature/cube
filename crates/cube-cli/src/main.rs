//! `cube-cli`: scriptable regtest scenarios over the Cube ownership graph.
//!
//! The binary is deliberately thin: it parses the command line, dispatches one step, and prints the
//! resulting JSON artifact. The graph logic lives in `cube-scenario`.

mod cli;
mod run;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    match run::dispatch(cli) {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: cannot encode the result: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
