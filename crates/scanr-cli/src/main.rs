use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "scanr", about = "Scanr CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a repository scan.
    Scan {
        /// Path to scan.
        path: PathBuf,
    },
    /// Software bill of materials operations.
    Sbom {
        #[command(subcommand)]
        command: SbomCommands,
    },
}

#[derive(Debug, Subcommand)]
enum SbomCommands {
    /// Generate an SBOM.
    Generate,
    /// Diff two SBOM documents.
    Diff {
        /// Path to the old SBOM.
        old: PathBuf,
        /// Path to the new SBOM.
        new: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path } => {
            println!(
                "Placeholder: scanning '{}' ({})",
                path.display(),
                scanr_core::placeholder_status()
            );
        }
        Commands::Sbom { command } => match command {
            SbomCommands::Generate => {
                println!(
                    "Placeholder: generating SBOM ({})",
                    scanr_core::placeholder_status()
                );
            }
            SbomCommands::Diff { old, new } => {
                println!(
                    "Placeholder: diffing SBOM '{}' -> '{}' ({})",
                    old.display(),
                    new.display(),
                    scanr_core::placeholder_status()
                );
            }
        },
    }
}
