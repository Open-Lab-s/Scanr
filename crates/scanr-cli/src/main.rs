use std::fs;
use std::path::PathBuf;
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
        /// Enable CI mode with policy enforcement from scanr.toml.
        #[arg(short = 'c', long = "ci")]
        ci: bool,
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
    Generate {
        /// Path to generate SBOM from.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output CycloneDX JSON file.
        #[arg(
            short,
            long,
            value_name = "FILE",
            default_value = "scanr.sbom.cdx.json"
        )]
        output: PathBuf,
    },
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
    ci_mode: bool,
    dependencies_analyzed: usize,
    queried_dependencies: usize,
    failed_queries: usize,
    lookup_error: Option<String>,
    risk_summary: scanr_core::RiskSummary,
    policy_path: Option<String>,
    policy: Option<scanr_core::PolicyConfig>,
    policy_evaluation: Option<scanr_core::PolicyEvaluation>,
    dependencies: Vec<scanr_core::Dependency>,
    vulnerabilities: Vec<scanr_core::Vulnerability>,
    upgrade_recommendations: Vec<scanr_core::UpgradeRecommendation>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            ci,
            list_deps,
            raw_json,
            raw_json_out,
            recursive: _,
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
                                upgrade_recommendations: Vec::new(),
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

                if !vulnerability_report.upgrade_recommendations.is_empty() {
                    println!();
                    println!(
                        "Upgrade recommendations: {}",
                        vulnerability_report.upgrade_recommendations.len()
                    );
                    print_upgrade_recommendations_table(
                        &vulnerability_report.upgrade_recommendations,
                    );
                }

                let risk_summary =
                    scanr_core::summarize_risk(&vulnerability_report.vulnerabilities);
                print_risk_summary(&risk_summary);

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

                let mut ci_exit_code = 0i32;
                let mut policy_path_display = None;
                let mut policy = None;
                let mut policy_evaluation = None;

                if ci {
                    println!();
                    println!("CI Policy Check");
                    match scanr_core::load_policy_for_target(&path) {
                        Ok((loaded_policy, loaded_policy_path)) => {
                            if let Some(policy_path) = loaded_policy_path {
                                let normalized = normalize_windows_verbatim_path(
                                    policy_path.display().to_string(),
                                );
                                println!("Policy file: {normalized}");
                                policy_path_display = Some(normalized);
                            } else {
                                println!(
                                    "Policy file: not found (using defaults max_critical=0, max_high=0)"
                                );
                            }
                            println!(
                                "Rules: max_critical={} | max_high={}",
                                loaded_policy.max_critical, loaded_policy.max_high
                            );

                            let evaluation =
                                scanr_core::evaluate_policy(&risk_summary, &loaded_policy);
                            if evaluation.passed {
                                println!("Result: PASS");
                            } else {
                                println!("Result: FAIL");
                                println!("Violations:");
                                for violation in &evaluation.violations {
                                    println!("- {violation}");
                                }
                                ci_exit_code = 2;
                            }

                            if lookup_error.is_some() || vulnerability_report.failed_queries > 0 {
                                println!("Result: FAIL");
                                println!(
                                    "- vulnerability lookup incomplete; CI mode requires complete OSV results"
                                );
                                ci_exit_code = 3;
                            }

                            policy = Some(loaded_policy);
                            policy_evaluation = Some(evaluation);
                        }
                        Err(error) => {
                            eprintln!("Failed to load policy: {error}");
                            process::exit(2);
                        }
                    }
                }

                let payload = ScanRawOutput {
                    target: target_name,
                    path: target_path,
                    ci_mode: ci,
                    dependencies_analyzed: dependencies.len(),
                    queried_dependencies: vulnerability_report.queried_dependencies,
                    failed_queries: vulnerability_report.failed_queries,
                    lookup_error: lookup_error.clone(),
                    risk_summary,
                    policy_path: policy_path_display,
                    policy,
                    policy_evaluation,
                    dependencies,
                    vulnerabilities: vulnerability_report.vulnerabilities,
                    upgrade_recommendations: vulnerability_report.upgrade_recommendations,
                };

                if let Err(error) = emit_raw_output(&payload, raw_json, &raw_json_out) {
                    eprintln!("Failed to emit raw JSON: {error}");
                    process::exit(1);
                }

                if ci_exit_code != 0 {
                    process::exit(ci_exit_code);
                }
            }
            Err(error) => {
                eprintln!("Scan failed: {error}");
                process::exit(1);
            }
        },
        Commands::Sbom { command } => match command {
            SbomCommands::Generate { path, output } => {
                match scanr_core::generate_cyclonedx_sbom(&path) {
                    Ok(sbom) => {
                        if let Some(parent) = output.parent()
                            && !parent.as_os_str().is_empty()
                        {
                            if let Err(error) = fs::create_dir_all(parent) {
                                eprintln!(
                                    "SBOM generation failed: could not create output directory '{}': {error}",
                                    parent.display()
                                );
                                process::exit(1);
                            }
                        }

                        if let Err(error) = fs::write(&output, &sbom.json) {
                            eprintln!(
                                "SBOM generation failed: could not write '{}': {error}",
                                output.display()
                            );
                            process::exit(1);
                        }

                        println!("CycloneDX SBOM generated");
                        println!("Target: {}", sbom.target);
                        println!("Path: {}", sbom.path);
                        println!("Components: {}", sbom.component_count);
                        println!("Output: {}", output.display());
                    }
                    Err(error) => {
                        eprintln!("SBOM generation failed: {error}");
                        process::exit(1);
                    }
                }
            }
            SbomCommands::Diff { old, new } => {
                match scanr_core::diff_cyclonedx_sbom_files(&old, &new) {
                    Ok(diff) => {
                        println!("SBOM Diff");
                        println!("Old: {}", old.display());
                        println!("New: {}", new.display());
                        println!(
                            "Components: {} -> {}",
                            diff.old_components, diff.new_components
                        );

                        println!();
                        print_dependency_delta_section("Added", &diff.added_dependencies, 100);
                        print_dependency_delta_section("Removed", &diff.removed_dependencies, 100);
                        print_version_change_section(&diff.version_changes, 100);

                        println!();
                        println!(
                            "Introduced package versions: {}",
                            diff.introduced_dependencies.len()
                        );

                        if diff.introduced_dependencies.is_empty() {
                            println!("New Vulnerabilities: 0");
                        } else {
                            match scanr_core::investigate_vulnerabilities(
                                &diff.introduced_dependencies,
                            )
                            .await
                            {
                                Ok(report) => {
                                    let summary =
                                        scanr_core::summarize_risk(&report.vulnerabilities);
                                    println!(
                                        "New Vulnerabilities: {} {}",
                                        summary.total,
                                        summarize_severity_for_delta(&summary.counts)
                                    );
                                    if report.failed_queries > 0 {
                                        eprintln!(
                                            "Warning: vulnerability lookup failed for {}/{} introduced dependencies.",
                                            report.failed_queries, report.queried_dependencies
                                        );
                                    }
                                }
                                Err(error) => {
                                    eprintln!(
                                        "Warning: vulnerability lookup unavailable for introduced dependencies ({error})."
                                    );
                                }
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("SBOM diff failed: {error}");
                        process::exit(1);
                    }
                }
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

fn print_risk_summary(summary: &scanr_core::RiskSummary) {
    println!();
    println!("Risk Summary");
    println!(
        "critical: {} | high: {} | medium: {} | low: {} | unknown: {}",
        summary.counts.critical,
        summary.counts.high,
        summary.counts.medium,
        summary.counts.low,
        summary.counts.unknown
    );
    println!("risk level: {}", summary.risk_level);
}

fn print_upgrade_recommendations_table(recommendations: &[scanr_core::UpgradeRecommendation]) {
    let header = format!(
        "{:<4} {:<18} {:<8} {:<14} {:<14} {}",
        "#", "PACKAGE", "ECO", "CURRENT", "SUGGESTED", "STATUS"
    );
    println!("{header}");
    println!("{}", "-".repeat(header.len()));

    for (index, recommendation) in recommendations.iter().enumerate() {
        let status = if recommendation.major_bump {
            "safe (major upgrade)"
        } else {
            "safe"
        };

        println!(
            "{:<4} {:<18} {:<8} {:<14} {:<14} {}",
            index + 1,
            truncate_cell(&recommendation.package_name, 18),
            truncate_cell(&recommendation.ecosystem.to_string(), 8),
            truncate_cell(&recommendation.current_version, 14),
            truncate_cell(&recommendation.suggested_version, 14),
            status,
        );
    }
}

fn print_dependency_delta_section(
    label: &str,
    dependencies: &[scanr_core::Dependency],
    max_rows: usize,
) {
    println!("{label}: {}", dependencies.len());
    for dependency in dependencies.iter().take(max_rows) {
        println!(
            "- {}@{} [{}]",
            dependency.name, dependency.version, dependency.ecosystem
        );
    }
    if dependencies.len() > max_rows {
        println!("- ... and {} more", dependencies.len() - max_rows);
    }
}

fn print_version_change_section(changes: &[scanr_core::SbomVersionChange], max_rows: usize) {
    println!("Version changes: {}", changes.len());
    for change in changes.iter().take(max_rows) {
        let old_versions = change.old_versions.join(", ");
        let new_versions = change.new_versions.join(", ");
        println!(
            "- {} [{}]: {} -> {}",
            change.name, change.ecosystem, old_versions, new_versions
        );
    }
    if changes.len() > max_rows {
        println!("- ... and {} more", changes.len() - max_rows);
    }
}

fn summarize_severity_for_delta(counts: &scanr_core::SeverityCounts) -> String {
    if counts.critical > 0 {
        return "CRITICAL".to_string();
    }
    if counts.high > 0 {
        return "HIGH".to_string();
    }
    if counts.medium > 0 {
        return "MODERATE".to_string();
    }
    if counts.low > 0 {
        return "LOW".to_string();
    }
    "NONE".to_string()
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
            .trim_end_matches('.')
            .trim_end_matches(')')
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
