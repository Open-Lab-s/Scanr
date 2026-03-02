use std::fs;
use std::path::PathBuf;
use std::process;
use std::process;

use clap::{Parser, Subcommand};
use serde::Serialize;

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
        /// Print parsed dependencies before vulnerability output.
        #[arg(long)]
        list_deps: bool,
        /// Print raw JSON payload to stdout (for GUI integration).
        #[arg(long)]
        raw_json: bool,
        /// Write raw JSON payload to a file.
        #[arg(long, value_name = "FILE")]
        raw_json_out: Option<PathBuf>,
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

#[derive(Debug, Serialize)]
struct ScanRawOutput {
    target: String,
    path: String,
    dependencies_analyzed: usize,
    queried_dependencies: usize,
    failed_queries: usize,
    lookup_error: Option<String>,
    dependencies: Vec<scanr_core::Dependency>,
    vulnerabilities: Vec<scanr_core::Vulnerability>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            list_deps,
            raw_json,
            raw_json_out,
        } => match scanr_core::scan_dependencies(&path) {
            Ok(dependencies) => {
                if dependencies.is_empty() {
                    println!("No dependencies found in '{}'.", path.display());
                    return;
                }

                let target_name = resolve_target_name(&path);
                let target_path = resolve_target_path(&path);

                println!("Scanr Security Scan");
                println!("Target: {target_name}");
                println!("Path: {target_path}");
                println!("Dependencies analyzed: {}", dependencies.len());

                if list_deps {
                    println!();
                    println!("Dependencies:");
                    for dependency in &dependencies {
                        let kind = if dependency.direct {
                            "direct"
                        } else {
                            "transitive"
                        };
                        println!(
                            "- [{}] {} {} ({})",
                            dependency.ecosystem, dependency.name, dependency.version, kind
                        );
                    }
                }

                let (vulnerability_report, lookup_error) =
                    match scanr_core::investigate_vulnerabilities(&dependencies).await {
                        Ok(report) => (report, None),
                        Err(error) => (
                            scanr_core::VulnerabilityReport {
                                vulnerabilities: Vec::new(),
                                queried_dependencies: 0,
                                failed_queries: 0,
                            },
                            Some(error.to_string()),
                        ),
                    };

                if vulnerability_report.vulnerabilities.is_empty() {
                    println!();
                    println!("No known vulnerabilities found in OSV responses.");
                } else {
                    println!();
                    println!(
                        "Vulnerabilities found: {}",
                        vulnerability_report.vulnerabilities.len()
                    );
                    print_vulnerability_table(&vulnerability_report.vulnerabilities);
                    println!();
                    println!(
                        "Use --raw-json or --raw-json-out <file> for full advisory details/references."
                    );
                }

                if vulnerability_report.failed_queries > 0 {
                    println!();
                    eprintln!(
                        "Warning: OSV lookup failed for {}/{} dependencies. Results may be incomplete.",
                        vulnerability_report.failed_queries,
                        vulnerability_report.queried_dependencies
                    );
                }

                if let Some(error) = &lookup_error {
                    println!();
                    eprintln!(
                        "Warning: vulnerability lookup unavailable ({error}). Dependencies were scanned successfully."
                    );
                }

                let payload = ScanRawOutput {
                    target: target_name,
                    path: target_path,
                    dependencies_analyzed: dependencies.len(),
                    queried_dependencies: vulnerability_report.queried_dependencies,
                    failed_queries: vulnerability_report.failed_queries,
                    lookup_error,
                    dependencies,
                    vulnerabilities: vulnerability_report.vulnerabilities,
                };

                if let Err(error) = emit_raw_output(&payload, raw_json, &raw_json_out) {
                    eprintln!("Failed to emit raw JSON: {error}");
                    process::exit(1);
                }
            }
            Err(error) => {
                eprintln!("Scan failed: {error}");
                process::exit(1);
            }
        },
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

fn resolve_target_name(path: &PathBuf) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
    resolved
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| resolved.display().to_string())
}

fn resolve_target_path(path: &PathBuf) -> String {
    let raw = std::fs::canonicalize(path)
        .map(|resolved| resolved.display().to_string())
        .unwrap_or_else(|_| path.display().to_string());
    normalize_windows_verbatim_path(raw)
}

fn normalize_windows_verbatim_path(path: String) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = path.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    path
}

fn print_vulnerability_table(vulnerabilities: &[scanr_core::Vulnerability]) {
    let header = format!(
        "{:<4} {:<20} {:<8} {:<8} {:<14} {:<18} {}",
        "#", "CVE", "SEV", "SCORE", "AFFECTED", "PACKAGE", "FIX"
    );
    println!("{header}");
    println!("{}", "-".repeat(header.len()));

    for (index, vulnerability) in vulnerabilities.iter().enumerate() {
        let package = package_name_from_description(&vulnerability.description);
        let fix_hint = fix_hint_from_remediation(vulnerability.remediation.as_deref());
        let score = score_short(vulnerability.score.as_deref().unwrap_or("n/a"));

        println!(
            "{:<4} {:<20} {:<8} {:<8} {:<14} {:<18} {}",
            index + 1,
            truncate_cell(&vulnerability.cve_id, 20),
            truncate_cell(&vulnerability.severity.to_string(), 8),
            truncate_cell(&score, 8),
            truncate_cell(&vulnerability.affected_version, 14),
            truncate_cell(&package, 18),
            truncate_cell(&fix_hint, 46),
        );
    }
}

fn package_name_from_description(description: &str) -> String {
    description
        .split_once(':')
        .map(|(name, _)| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn fix_hint_from_remediation(remediation: Option<&str>) -> String {
    let Some(remediation) = remediation else {
        return "see advisory".to_string();
    };

    if let Some((_, tail)) = remediation.split_once("one of:") {
        return tail
            .trim()
            .trim_end_matches(')')
            .trim_end_matches('.')
            .to_string();
    }

    remediation.to_string()
}

fn score_short(score: &str) -> String {
    if let Some(rest) = score.strip_prefix("CVSS:") {
        return rest
            .split('/')
            .next()
            .map(ToString::to_string)
            .unwrap_or_else(|| score.to_string());
    }
    score.to_string()
}

fn truncate_cell(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    if max_len <= 1 {
        return "…".to_string();
    }

    let mut truncated = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= max_len - 1 {
            break;
        }
        truncated.push(ch);
    }
    truncated.push('…');
    truncated
}

fn emit_raw_output(
    payload: &ScanRawOutput,
    print_raw: bool,
    out_path: &Option<PathBuf>,
) -> Result<(), String> {
    if !print_raw && out_path.is_none() {
        return Ok(());
    }

    let json = serde_json::to_string_pretty(payload)
        .map_err(|error| format!("failed to serialize payload: {error}"))?;

    if print_raw {
        println!();
        println!("Raw JSON:");
        println!("{json}");
    }

    if let Some(path) = out_path {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create output directory: {error}"))?;
        }

        fs::write(path, json)
            .map_err(|error| format!("failed to write '{}': {error}", path.display()))?;
        println!("Raw JSON written to: {}", path.display());
    }

    Ok(())
}
