use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use serde::Serialize;

mod tui;

#[derive(Debug, Parser)]
#[command(name = "scanr", about = "Scanr CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a repository scan.
    Scan {
        /// Path to scan.
        path: PathBuf,
        /// Enable CI mode with policy enforcement from scanr.toml.
        #[arg(short = 'c', long = "ci", conflicts_with_all = ["json", "sarif"])]
        ci: bool,
        /// Print canonical ScanResult JSON only (machine-readable).
        #[arg(long = "json", conflicts_with = "sarif")]
        json: bool,
        /// Print SARIF v2.1.0 JSON only (machine-readable).
        #[arg(long = "sarif", conflicts_with = "json")]
        sarif: bool,
        /// Print parsed dependencies before vulnerability output.
        #[arg(long, conflicts_with_all = ["json", "sarif"])]
        list_deps: bool,
        /// Print raw JSON payload to stdout (for GUI integration).
        #[arg(long, conflicts_with_all = ["json", "sarif"])]
        raw_json: bool,
        /// Write raw JSON payload to a file.
        #[arg(long, value_name = "FILE", conflicts_with_all = ["json", "sarif"])]
        raw_json_out: Option<PathBuf>,
        /// Compare current findings against .scanr/baseline.json.
        #[arg(long, conflicts_with_all = ["json", "sarif"])]
        baseline: bool,
        /// Use only local cache; do not call OSV.
        #[arg(long, conflicts_with = "refresh")]
        offline: bool,
        /// Force refresh OSV cache, ignoring TTL.
        #[arg(long, conflicts_with = "offline")]
        refresh: bool,
        /// Recursively scan subdirectories for supported manifest files.
        #[arg(short, long)]
        recursive: bool,
    },
    /// Software bill of materials operations.
    Sbom {
        #[command(subcommand)]
        command: SbomCommands,
    },
    /// Baseline operations.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommands,
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

#[derive(Debug, Subcommand)]
enum BaselineCommands {
    /// Save baseline snapshot to .scanr/baseline.json.
    Save {
        /// Target path to scan for baseline creation.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Show baseline delta compared with current scan.
    Status {
        /// Target path to compare with baseline.
        #[arg(default_value = ".")]
        path: PathBuf,
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
    offline_missing: usize,
    lookup_error: Option<String>,
    cache_events: Vec<String>,
    risk_summary: scanr_core::RiskSummary,
    policy_path: Option<String>,
    policy: Option<scanr_core::PolicyConfig>,
    policy_evaluation: Option<scanr_core::PolicyEvaluation>,
    baseline: Option<BaselineSummaryOutput>,
    dependencies: Vec<scanr_core::Dependency>,
    vulnerabilities: Vec<scanr_core::Vulnerability>,
    upgrade_recommendations: Vec<scanr_core::UpgradeRecommendation>,
}

#[derive(Debug, Serialize)]
struct BaselineSummaryOutput {
    enabled: bool,
    found: bool,
    path: String,
    baseline_version: Option<String>,
    current_scanr_version: String,
    version_mismatch: bool,
    baseline_vulnerabilities: usize,
    current_vulnerabilities: usize,
    new_vulnerabilities: usize,
    fixed_vulnerabilities: usize,
    new_severity: scanr_core::SeverityCounts,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        None => {
            if let Err(error) = tui::run_tui(PathBuf::from(".")) {
                eprintln!("TUI failed: {error}");
                process::exit(1);
            }
        }
        Some(Commands::Scan {
            path,
            ci,
            json,
            sarif,
            list_deps,
            raw_json,
            raw_json_out,
            baseline,
            offline,
            refresh,
            recursive: _,
        }) => {
            let loaded_policy = scanr_core::load_policy_for_target(&path);
            let cache_settings = match &loaded_policy {
                Ok((policy, _)) => (policy.cache_enabled, policy.cache_ttl_hours),
                Err(error) => {
                    eprintln!(
                        "Warning: failed to load scanr.toml for cache settings ({error}); using defaults cache_enabled=true cache_ttl_hours=24."
                    );
                    (true, 24)
                }
            };

            let scan_options = scanr_core::ScanOptions {
                cache_enabled: cache_settings.0,
                cache_ttl_hours: cache_settings.1,
                offline,
                force_refresh: refresh,
            };

            let scan_result = match scanr_core::scan_path_with_options(&path, &scan_options).await {
                Ok(scan_result) => scan_result,
                Err(error) => {
                    eprintln!("Scan failed: {error}");
                    process::exit(1);
                }
            };

            if json {
                match serde_json::to_string_pretty(&scan_result) {
                    Ok(payload) => println!("{payload}"),
                    Err(error) => {
                        eprintln!("failed to serialize scan result: {error}");
                        process::exit(1);
                    }
                }
                return;
            }

            if sarif {
                let sarif_report = scanr_core::scan_result_to_sarif(&scan_result);
                match serde_json::to_string_pretty(&sarif_report) {
                    Ok(payload) => println!("{payload}"),
                    Err(error) => {
                        eprintln!("failed to serialize SARIF report: {error}");
                        process::exit(1);
                    }
                }
                return;
            }

            if scan_result.dependencies.is_empty() {
                println!("No dependencies found in '{}'.", path.display());
            } else {
                println!("Scanr Security Scan");
                println!("Target: {}", scan_result.target);
                println!("Path: {}", scan_result.path);
                println!("Dependencies analyzed: {}", scan_result.total_dependencies);

                if !scan_result.cache_events.is_empty() {
                    println!();
                    for event in &scan_result.cache_events {
                        println!("{event}");
                    }
                }

                if list_deps {
                    println!();
                    println!("Dependencies:");
                    for dependency in &scan_result.dependencies {
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

                if scan_result.vulnerabilities.is_empty() {
                    println!();
                    println!("No known vulnerabilities found in OSV responses.");
                } else {
                    println!();
                    println!(
                        "Vulnerabilities found: {}",
                        scan_result.vulnerabilities.len()
                    );
                    print_vulnerability_table(&scan_result.vulnerabilities);
                    println!();
                    println!(
                        "Use --raw-json or --raw-json-out <file> for full advisory details/references."
                    );
                }

                if !scan_result.upgrade_recommendations.is_empty() {
                    println!();
                    println!(
                        "Upgrade recommendations: {}",
                        scan_result.upgrade_recommendations.len()
                    );
                    print_upgrade_recommendations_table(&scan_result.upgrade_recommendations);
                }

                print_risk_summary(&scan_result);

                if scan_result.failed_queries > 0 {
                    println!();
                    eprintln!(
                        "Warning: OSV lookup failed for {}/{} dependencies. Results may be incomplete.",
                        scan_result.failed_queries, scan_result.queried_dependencies
                    );
                }

                if scan_result.offline_missing > 0 {
                    println!();
                    eprintln!(
                        "Warning: offline cache miss for {} dependencies. Vulnerability status unknown (offline).",
                        scan_result.offline_missing
                    );
                }

                if let Some(error) = &scan_result.lookup_error {
                    println!();
                    eprintln!(
                        "Warning: vulnerability lookup unavailable ({error}). Dependencies were scanned successfully."
                    );
                }
            }

            let mut ci_exit_code = 0i32;
            let mut policy_path_display = None;
            let mut policy = None;
            let mut policy_evaluation = None;
            let mut baseline_summary = None;
            let mut baseline_delta = None;

            if baseline {
                let baseline_path = scanr_core::baseline_path_for_target(&path);
                let baseline_path_display =
                    normalize_windows_verbatim_path(baseline_path.display().to_string());
                match scanr_core::load_baseline_for_target(&path) {
                    Ok(Some((loaded_baseline, loaded_baseline_path))) => {
                        let delta = scanr_core::compare_scan_result_to_baseline(
                            &scan_result,
                            &loaded_baseline,
                        );
                        let loaded_path_display = normalize_windows_verbatim_path(
                            loaded_baseline_path.display().to_string(),
                        );
                        let version_mismatch =
                            loaded_baseline.version != scanr_core::current_scanr_version();

                        println!();
                        println!("Baseline Comparison");
                        println!("Baseline file: {}", loaded_path_display);
                        if version_mismatch {
                            eprintln!(
                                "Warning: baseline version '{}' differs from current Scanr '{}'.",
                                loaded_baseline.version,
                                scanr_core::current_scanr_version()
                            );
                        }
                        println!("Baseline: {} vulnerabilities", delta.baseline_total);
                        println!("Current: {} vulnerabilities", delta.current_total);
                        println!();
                        println!("New: {}", delta.new_vulnerabilities.len());
                        println!("Fixed: {}", delta.fixed_vulnerabilities.len());
                        println!();
                        println!(
                            "Security debt delta: +{} new, -{} fixed",
                            delta.new_vulnerabilities.len(),
                            delta.fixed_vulnerabilities.len()
                        );
                        println!(
                            "Risk change: +{} CRITICAL, +{} HIGH, +{} MEDIUM, +{} LOW, +{} UNKNOWN",
                            delta.new_severity.critical,
                            delta.new_severity.high,
                            delta.new_severity.medium,
                            delta.new_severity.low,
                            delta.new_severity.unknown
                        );

                        baseline_summary = Some(BaselineSummaryOutput {
                            enabled: true,
                            found: true,
                            path: loaded_path_display,
                            baseline_version: Some(loaded_baseline.version.clone()),
                            current_scanr_version: scanr_core::current_scanr_version().to_string(),
                            version_mismatch,
                            baseline_vulnerabilities: delta.baseline_total,
                            current_vulnerabilities: delta.current_total,
                            new_vulnerabilities: delta.new_vulnerabilities.len(),
                            fixed_vulnerabilities: delta.fixed_vulnerabilities.len(),
                            new_severity: delta.new_severity,
                        });
                        baseline_delta = Some(delta);
                    }
                    Ok(None) => {
                        println!();
                        eprintln!(
                            "Warning: baseline file not found at '{}'. Continuing without baseline comparison.",
                            baseline_path_display
                        );

                        baseline_summary = Some(BaselineSummaryOutput {
                            enabled: true,
                            found: false,
                            path: baseline_path_display,
                            baseline_version: None,
                            current_scanr_version: scanr_core::current_scanr_version().to_string(),
                            version_mismatch: false,
                            baseline_vulnerabilities: 0,
                            current_vulnerabilities: 0,
                            new_vulnerabilities: 0,
                            fixed_vulnerabilities: 0,
                            new_severity: scanr_core::SeverityCounts::default(),
                        });
                    }
                    Err(error) => {
                        eprintln!("Failed to load baseline: {error}");
                        process::exit(2);
                    }
                }
            }

            if ci {
                println!();
                if let Some(delta) = baseline_delta.as_ref() {
                    println!("CI Baseline Check");
                    if delta.new_vulnerabilities.is_empty() {
                        println!("Result: PASS");
                        if !delta.fixed_vulnerabilities.is_empty() {
                            println!(
                                "Improvement: {} vulnerabilities fixed since baseline.",
                                delta.fixed_vulnerabilities.len()
                            );
                        }
                    } else {
                        println!("Result: FAIL");
                        println!(
                            "- new vulnerabilities detected: {}",
                            delta.new_vulnerabilities.len()
                        );
                        ci_exit_code = 2;
                    }
                } else {
                    println!("CI Policy Check");
                    match &loaded_policy {
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

                            let risk_summary = risk_summary_from_scan_result(&scan_result);
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

                            policy = Some(*loaded_policy);
                            policy_evaluation = Some(evaluation);
                        }
                        Err(error) => {
                            eprintln!("Failed to load policy: {error}");
                            process::exit(2);
                        }
                    }
                }

                if scan_result.lookup_error.is_some()
                    || scan_result.failed_queries > 0
                    || scan_result.offline_missing > 0
                {
                    println!("Result: FAIL");
                    println!(
                        "- vulnerability lookup incomplete; CI mode requires complete OSV results"
                    );
                    ci_exit_code = 3;
                }
            }

            let payload = ScanRawOutput {
                target: scan_result.target.clone(),
                path: scan_result.path.clone(),
                ci_mode: ci,
                dependencies_analyzed: scan_result.total_dependencies as usize,
                queried_dependencies: scan_result.queried_dependencies as usize,
                failed_queries: scan_result.failed_queries as usize,
                offline_missing: scan_result.offline_missing as usize,
                lookup_error: scan_result.lookup_error.clone(),
                cache_events: scan_result.cache_events.clone(),
                risk_summary: risk_summary_from_scan_result(&scan_result),
                policy_path: policy_path_display,
                policy,
                policy_evaluation,
                baseline: baseline_summary,
                dependencies: scan_result.dependencies.clone(),
                vulnerabilities: scan_result.vulnerabilities.clone(),
                upgrade_recommendations: scan_result.upgrade_recommendations.clone(),
            };

            if let Err(error) = emit_raw_output(&payload, raw_json, &raw_json_out) {
                eprintln!("Failed to emit raw JSON: {error}");
                process::exit(1);
            }

            if ci_exit_code != 0 {
                process::exit(ci_exit_code);
            }
        }
        Some(Commands::Sbom { command }) => match command {
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
        Some(Commands::Baseline { command }) => match command {
            BaselineCommands::Save { path } => {
                let loaded_policy = scanr_core::load_policy_for_target(&path);
                let (cache_enabled, cache_ttl_hours) = match &loaded_policy {
                    Ok((policy, _)) => (policy.cache_enabled, policy.cache_ttl_hours),
                    Err(_) => (true, 24),
                };
                let scan_options = scanr_core::ScanOptions {
                    cache_enabled,
                    cache_ttl_hours,
                    offline: false,
                    force_refresh: false,
                };

                let scan_result =
                    match scanr_core::scan_path_with_options(&path, &scan_options).await {
                        Ok(scan_result) => scan_result,
                        Err(error) => {
                            eprintln!("Scan failed: {error}");
                            process::exit(1);
                        }
                    };

                if scan_result.lookup_error.is_some() || scan_result.failed_queries > 0 {
                    eprintln!(
                        "Baseline save failed: vulnerability lookup incomplete. Run again when OSV is reachable."
                    );
                    process::exit(1);
                }

                let baseline = scanr_core::build_baseline_from_scan_result(&scan_result);
                let baseline_path = match scanr_core::save_baseline_for_target(&path, &scan_result)
                {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Failed to save baseline: {error}");
                        process::exit(1);
                    }
                };

                println!("Baseline saved");
                println!(
                    "Path: {}",
                    normalize_windows_verbatim_path(baseline_path.display().to_string())
                );
                println!("Entries: {}", baseline.vulnerabilities.len());
                println!("Generated at: {}", baseline.generated_at);
                println!("Scanr version: {}", baseline.version);
            }
            BaselineCommands::Status { path } => {
                let (baseline, baseline_path) = match scanr_core::load_baseline_for_target(&path) {
                    Ok(Some(payload)) => payload,
                    Ok(None) => {
                        let expected = scanr_core::baseline_path_for_target(&path);
                        eprintln!(
                            "Baseline not found at '{}'. Run `scanr baseline save` first.",
                            normalize_windows_verbatim_path(expected.display().to_string())
                        );
                        process::exit(1);
                    }
                    Err(error) => {
                        eprintln!("Failed to load baseline: {error}");
                        process::exit(1);
                    }
                };

                let loaded_policy = scanr_core::load_policy_for_target(&path);
                let (cache_enabled, cache_ttl_hours) = match &loaded_policy {
                    Ok((policy, _)) => (policy.cache_enabled, policy.cache_ttl_hours),
                    Err(_) => (true, 24),
                };
                let scan_options = scanr_core::ScanOptions {
                    cache_enabled,
                    cache_ttl_hours,
                    offline: false,
                    force_refresh: false,
                };

                let scan_result =
                    match scanr_core::scan_path_with_options(&path, &scan_options).await {
                        Ok(scan_result) => scan_result,
                        Err(error) => {
                            eprintln!("Scan failed: {error}");
                            process::exit(1);
                        }
                    };
                let delta = scanr_core::compare_scan_result_to_baseline(&scan_result, &baseline);

                println!("Baseline Status");
                println!(
                    "Baseline file: {}",
                    normalize_windows_verbatim_path(baseline_path.display().to_string())
                );
                println!("Baseline version: {}", baseline.version);
                println!(
                    "Current Scanr version: {}",
                    scanr_core::current_scanr_version()
                );
                if baseline.version != scanr_core::current_scanr_version() {
                    eprintln!(
                        "Warning: baseline version '{}' differs from current Scanr '{}'.",
                        baseline.version,
                        scanr_core::current_scanr_version()
                    );
                }
                println!();
                println!("Baseline: {} vulnerabilities", delta.baseline_total);
                println!("Current: {} vulnerabilities", delta.current_total);
                println!();
                println!("New: {}", delta.new_vulnerabilities.len());
                println!("Fixed: {}", delta.fixed_vulnerabilities.len());
                println!();
                println!(
                    "Security debt delta: +{} new, -{} fixed",
                    delta.new_vulnerabilities.len(),
                    delta.fixed_vulnerabilities.len()
                );
                println!(
                    "Risk change: +{} CRITICAL, +{} HIGH, +{} MEDIUM, +{} LOW, +{} UNKNOWN",
                    delta.new_severity.critical,
                    delta.new_severity.high,
                    delta.new_severity.medium,
                    delta.new_severity.low,
                    delta.new_severity.unknown
                );

                if scan_result.lookup_error.is_some() || scan_result.failed_queries > 0 {
                    eprintln!(
                        "Warning: current scan lookup incomplete; baseline status may be incomplete."
                    );
                }
            }
        },
    }
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

fn print_risk_summary(scan_result: &scanr_core::ScanResult) {
    println!();
    println!("Risk Summary");
    println!(
        "critical: {} | high: {} | medium: {} | low: {} | unknown: {}",
        scan_result.severity_summary.critical,
        scan_result.severity_summary.high,
        scan_result.severity_summary.medium,
        scan_result.severity_summary.low,
        scan_result.severity_summary.unknown
    );
    println!("risk level: {}", scan_result.risk_level);
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

fn risk_summary_from_scan_result(scan_result: &scanr_core::ScanResult) -> scanr_core::RiskSummary {
    scanr_core::RiskSummary {
        total: scan_result.vulnerabilities.len(),
        counts: scanr_core::SeverityCounts {
            critical: scan_result.severity_summary.critical as usize,
            high: scan_result.severity_summary.high as usize,
            medium: scan_result.severity_summary.medium as usize,
            low: scan_result.severity_summary.low as usize,
            unknown: scan_result.severity_summary.unknown as usize,
        },
        risk_level: scan_result.risk_level,
    }
}
