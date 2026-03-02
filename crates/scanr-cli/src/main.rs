use std::path::PathBuf;
use std::process;

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
        /// Recursively scan subdirectories for supported manifest files.
        #[arg(short, long)]
        recursive: bool,
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
        Commands::Scan { path, recursive } => {
            match scanr_core::scan_dependencies_with_options(&path, recursive) {
                Ok(dependencies) => {
                    if dependencies.is_empty() {
                        println!("No dependencies found in '{}'.", path.display());
                    } else {
                        println!("Dependencies found in '{}':", path.display());
                        for dep in dependencies {
                            let kind = if dep.direct { "direct" } else { "transitive" };
                            println!(
                                "- [{}] {} {} ({})",
                                dep.ecosystem, dep.name, dep.version, kind
                            );
                        }
                    }
                }
                Err(error) => {
                    eprintln!("Scan failed: {error}");
                    process::exit(1);
                }
            }
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
