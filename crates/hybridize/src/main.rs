use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hybridize",
    version,
    about = "Policy-aware post-quantum TLS migration"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    // Analyze codebase for TLS key exchange configuration
    Scan {
        path: PathBuf,
    },
    Plan {
        path: PathBuf,
        #[arg(long, default_value = "general")]
        policy: String,
    },
    Apply {
        path: PathBuf,
    },
}

fn main() {
    match Cli::parse().command {
        Command::Scan { path } => println!("scan: {} (not implemented yet)", path.display()),
        Command::Plan { path, policy } => {
            println!(
                "plan: {} with policy {policy} (not implemented yet)",
                path.display()
            )
        }
        Command::Apply { path } => println!("apply: {} (not implemented yet)", path.display()),
    }
}
