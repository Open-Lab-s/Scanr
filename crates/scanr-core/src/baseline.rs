use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{ScanError, ScanResult, Severity, SeverityCounts, Vulnerability};

pub const BASELINE_RELATIVE_PATH: &str = ".scanr/baseline.json";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub cve: String,
    pub package: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub version: String,
    pub generated_at: String,
    pub vulnerabilities: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaselineDelta {
    pub baseline_total: usize,
    pub current_total: usize,
    pub new_vulnerabilities: Vec<BaselineEntry>,
    pub fixed_vulnerabilities: Vec<BaselineEntry>,
    pub new_severity: SeverityCounts,
}

pub fn current_scanr_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn baseline_path_for_target(target_path: &Path) -> PathBuf {
    resolve_baseline_root(target_path).join(BASELINE_RELATIVE_PATH)
}

pub fn save_baseline_for_target(
    target_path: &Path,
    scan_result: &ScanResult,
) -> Result<PathBuf, ScanError> {
    let baseline = build_baseline_from_scan_result(scan_result);
    let baseline_path = baseline_path_for_target(target_path);

    if let Some(parent) = baseline_path.parent() {
        fs::create_dir_all(parent).map_err(|source| ScanError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let payload = serde_json::to_string_pretty(&baseline).map_err(|source| ScanError::Json {
        path: baseline_path.clone(),
        source,
    })?;

    fs::write(&baseline_path, payload).map_err(|source| ScanError::Io {
        path: baseline_path.clone(),
        source,
    })?;

    Ok(baseline_path)
}

pub fn load_baseline_for_target(
    target_path: &Path,
) -> Result<Option<(Baseline, PathBuf)>, ScanError> {
    let baseline_path = baseline_path_for_target(target_path);
    match fs::read_to_string(&baseline_path) {
        Ok(contents) => {
            let mut baseline: Baseline =
                serde_json::from_str(&contents).map_err(|source| ScanError::Json {
                    path: baseline_path.clone(),
                    source,
                })?;
            baseline.vulnerabilities = normalize_entries(&baseline.vulnerabilities);
            Ok(Some((baseline, baseline_path)))
        }
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ScanError::Io {
            path: baseline_path,
            source,
        }),
    }
}

pub fn build_baseline_from_scan_result(scan_result: &ScanResult) -> Baseline {
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    Baseline {
        version: current_scanr_version().to_string(),
        generated_at,
        vulnerabilities: entries_from_vulnerabilities(&scan_result.vulnerabilities),
    }
}

pub fn compare_scan_result_to_baseline(
    scan_result: &ScanResult,
    baseline: &Baseline,
) -> BaselineDelta {
    let baseline_entries = normalize_entries(&baseline.vulnerabilities);
    let current_entries = entries_from_vulnerabilities(&scan_result.vulnerabilities);

    let baseline_set = entry_set(&baseline_entries);
    let current_set = entry_set(&current_entries);
    let severity_by_key = severity_map_for_scan(scan_result);

    let new_vulnerabilities = current_entries
        .into_iter()
        .filter(|entry| !baseline_set.contains(&entry_key(entry)))
        .collect::<Vec<_>>();
    let fixed_vulnerabilities = baseline_entries
        .into_iter()
        .filter(|entry| !current_set.contains(&entry_key(entry)))
        .collect::<Vec<_>>();

    let mut new_severity = SeverityCounts::default();
    for entry in &new_vulnerabilities {
        let key = entry_key(entry);
        if let Some(severity) = severity_by_key.get(&key) {
            increment_severity(&mut new_severity, *severity);
        }
    }

    BaselineDelta {
        baseline_total: baseline_set.len(),
        current_total: current_set.len(),
        new_vulnerabilities,
        fixed_vulnerabilities,
        new_severity,
    }
}

fn resolve_baseline_root(target_path: &Path) -> PathBuf {
    if target_path.is_file() {
        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
        return fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    }
    fs::canonicalize(target_path).unwrap_or_else(|_| target_path.to_path_buf())
}

fn entries_from_vulnerabilities(vulnerabilities: &[Vulnerability]) -> Vec<BaselineEntry> {
    let mut set = BTreeSet::new();
    for vulnerability in vulnerabilities {
        let package = package_name_from_description(&vulnerability.description);
        set.insert(BaselineEntry {
            cve: vulnerability.cve_id.clone(),
            package,
            version: vulnerability.affected_version.clone(),
        });
    }

    set.into_iter().collect()
}

fn normalize_entries(entries: &[BaselineEntry]) -> Vec<BaselineEntry> {
    let mut set = BTreeSet::new();
    set.extend(entries.iter().cloned());
    set.into_iter().collect()
}

fn entry_set(entries: &[BaselineEntry]) -> HashSet<String> {
    entries.iter().map(entry_key).collect()
}

fn entry_key(entry: &BaselineEntry) -> String {
    format!("{}|{}|{}", entry.cve, entry.package, entry.version)
}

fn severity_map_for_scan(scan_result: &ScanResult) -> HashMap<String, Severity> {
    let mut map = HashMap::new();
    for vulnerability in &scan_result.vulnerabilities {
        let entry = BaselineEntry {
            cve: vulnerability.cve_id.clone(),
            package: package_name_from_description(&vulnerability.description),
            version: vulnerability.affected_version.clone(),
        };
        map.insert(entry_key(&entry), vulnerability.severity);
    }
    map
}

fn increment_severity(counts: &mut SeverityCounts, severity: Severity) {
    match severity {
        Severity::Critical => counts.critical += 1,
        Severity::High => counts.high += 1,
        Severity::Medium => counts.medium += 1,
        Severity::Low => counts.low += 1,
        Severity::Unknown => counts.unknown += 1,
    }
}

fn package_name_from_description(description: &str) -> String {
    description
        .split_once(':')
        .map(|(name, _)| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
