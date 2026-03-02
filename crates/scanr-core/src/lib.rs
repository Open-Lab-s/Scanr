use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Map, Value as JsonValue};
use toml::Value as TomlValue;
use walkdir::{DirEntry, WalkDir};

const SUPPORTED_MANIFESTS: [&str; 8] = [
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Cargo.toml",
    "Cargo.lock",
];

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use reqwest::StatusCode;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};
use tokio::time::sleep;
use toml::Value as TomlValue;

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const OSV_CONCURRENCY_LIMIT: usize = 8;
const OSV_MAX_RETRIES: usize = 4;
const SUPPORTED_MANIFESTS: [&str; 6] = [
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "Cargo.toml",
    "Cargo.lock",
];

pub fn placeholder_status() -> &'static str {
    "scanr-core placeholder"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Node,
    Python,
    Rust,
}

impl Display for Ecosystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node => write!(f, "node"),
            Self::Python => write!(f, "python"),
            Self::Rust => write!(f, "rust"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub direct: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub severity: Severity,
    pub score: Option<String>,
    pub affected_version: String,
    pub description: String,
    pub references: Vec<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VulnerabilityReport {
    pub vulnerabilities: Vec<Vulnerability>,
    pub queried_dependencies: usize,
    pub failed_queries: usize,
}

#[derive(Debug)]
pub enum ScanError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },
    Http(reqwest::Error),
}

impl Display for ScanError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read '{}': {}", path.display(), source)
            }
            Self::Json { path, source } => {
                write!(f, "failed to parse JSON '{}': {}", path.display(), source)
            }
            Self::Toml { path, source } => {
                write!(f, "failed to parse TOML '{}': {}", path.display(), source)
            }
            Self::Http(source) => write!(f, "HTTP request failed: {source}"),
        }
    }
}

impl Error for ScanError {}

impl From<reqwest::Error> for ScanError {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(value)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PackageJson {
    dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies")]
    dev_dependencies: HashMap<String, String>,
    #[serde(rename = "peerDependencies")]
    peer_dependencies: HashMap<String, String>,
    #[serde(rename = "optionalDependencies")]
    optional_dependencies: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvPackageQuery,
}

#[derive(Debug, Serialize)]
struct OsvPackageQuery {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize, Default)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct OsvVulnerability {
    id: String,
    aliases: Vec<String>,
    summary: Option<String>,
    details: Option<String>,
    severity: Vec<OsvSeverity>,
    references: Vec<OsvReference>,
    affected: Vec<OsvAffected>,
    database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct OsvSeverity {
    score: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct OsvReference {
    url: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct OsvAffected {
    package: Option<OsvAffectedPackage>,
    ranges: Vec<OsvRange>,
    versions: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct OsvAffectedPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: String,
    events: Vec<OsvRangeEvent>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct OsvRangeEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    #[serde(rename = "last_affected")]
    last_affected: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct OsvDatabaseSpecific {
    severity: Option<String>,
}

pub fn scan_dependencies(path: &Path) -> Result<Vec<Dependency>, ScanError> {
    if !path.exists() {
        return Err(ScanError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(ErrorKind::NotFound, "path does not exist"),
        });
    }

    let mut dependencies = Vec::new();

    if path.is_file() {
        dependencies.extend(parse_manifest_file(path)?);
    } else {
        for file_name in SUPPORTED_MANIFESTS {
            let candidate = path.join(file_name);
            if candidate.is_file() {
                dependencies.extend(parse_manifest_file(&candidate)?);
            }
        }
    }

    Ok(dedupe_and_sort(dependencies))
}

pub async fn investigate_vulnerabilities(
    dependencies: &[Dependency],
) -> Result<VulnerabilityReport, ScanError> {
    if dependencies.is_empty() {
        return Ok(VulnerabilityReport {
            vulnerabilities: Vec::new(),
            queried_dependencies: 0,
            failed_queries: 0,
        });
    }

    let client = reqwest::Client::builder()
        .user_agent("scanr/0.1.0")
        .build()?;

    let targets = prepare_vulnerability_targets(dependencies);
    let queried_dependencies = targets.len();
    let mut failed_queries = 0usize;
    let mut vulnerabilities = Vec::new();

    let mut tasks = stream::iter(targets.into_iter().map(|target| {
        let client = client.clone();
        async move { fetch_vulnerabilities_for_dependency(&client, target).await }
    }))
    .buffer_unordered(OSV_CONCURRENCY_LIMIT);

    while let Some(result) = tasks.next().await {
        match result {
            Ok(vulns) => vulnerabilities.extend(vulns),
            Err(_) => failed_queries += 1,
        }
    }

    vulnerabilities.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
    vulnerabilities.dedup_by(|a, b| {
        a.cve_id == b.cve_id
            && a.affected_version == b.affected_version
            && a.description == b.description
    });

    Ok(VulnerabilityReport {
        vulnerabilities,
        queried_dependencies,
        failed_queries,
    })
}

#[derive(Debug, Clone)]
struct VulnerabilityTarget {
    dependency: Dependency,
    version: Version,
}

fn prepare_vulnerability_targets(dependencies: &[Dependency]) -> Vec<VulnerabilityTarget> {
    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();

    for dependency in dependencies {
        let Some(version) = parse_semverish(&dependency.version) else {
            continue;
        };

        let key = (
            dependency.ecosystem,
            dependency.name.clone(),
            dependency.version.clone(),
        );
        if seen.insert(key) {
            targets.push(VulnerabilityTarget {
                dependency: dependency.clone(),
                version,
            });
        }
    }

    targets
}

async fn fetch_vulnerabilities_for_dependency(
    client: &reqwest::Client,
    target: VulnerabilityTarget,
) -> Result<Vec<Vulnerability>, ScanError> {
    let ecosystem = osv_ecosystem(target.dependency.ecosystem);
    let request = OsvQueryRequest {
        package: OsvPackageQuery {
            name: target.dependency.name.clone(),
            ecosystem: ecosystem.to_string(),
        },
    };

    let payload = query_osv_with_retry(client, &request).await?;

    let mut vulnerabilities = Vec::new();
    for vuln in payload.vulns {
        if !vulnerability_applies_to_dependency(&vuln, &target.dependency, &target.version) {
            continue;
        }

        let cve_id = extract_cve_id(&vuln);
        let severity = extract_severity(&vuln);
        let score = extract_score(&vuln);
        let remediation = extract_remediation(&vuln, &target.dependency);
        let mut description = vuln
            .summary
            .clone()
            .or(vuln.details.clone())
            .unwrap_or_else(|| "No description provided".to_string());
        description = format!("{}: {description}", target.dependency.name);

        let references = vuln
            .references
            .iter()
            .map(|reference| reference.url.clone())
            .filter(|url| !url.is_empty())
            .collect::<Vec<_>>();

        vulnerabilities.push(Vulnerability {
            cve_id,
            severity,
            score,
            affected_version: target.dependency.version.clone(),
            description,
            references,
            remediation,
        });
    }

    Ok(vulnerabilities)
}

async fn query_osv_with_retry(
    client: &reqwest::Client,
    request: &OsvQueryRequest,
) -> Result<OsvQueryResponse, ScanError> {
    for attempt in 0..=OSV_MAX_RETRIES {
        let result = client.post(OSV_QUERY_URL).json(request).send().await;
        match result {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    let payload: OsvQueryResponse = response.json().await?;
                    return Ok(payload);
                }

                if attempt < OSV_MAX_RETRIES && is_retryable_status(status) {
                    sleep(backoff_for_attempt(attempt)).await;
                    continue;
                }

                let error = response.error_for_status().unwrap_err();
                return Err(ScanError::Http(error));
            }
            Err(error) => {
                if attempt < OSV_MAX_RETRIES && is_retryable_error(&error) {
                    sleep(backoff_for_attempt(attempt)).await;
                    continue;
                }
                return Err(ScanError::Http(error));
            }
        }
    }

    Err(ScanError::Io {
        path: PathBuf::from(OSV_QUERY_URL),
        source: std::io::Error::other("OSV query retry loop exhausted"),
    })
}

fn backoff_for_attempt(attempt: usize) -> Duration {
    let capped = attempt.min(6) as u32;
    Duration::from_millis(250 * (1u64 << capped))
}

fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn is_retryable_error(error: &reqwest::Error) -> bool {
    error.is_timeout()
        || error.is_connect()
        || error.is_request()
        || error.status().is_some_and(is_retryable_status)
}

fn vulnerability_applies_to_dependency(
    vulnerability: &OsvVulnerability,
    dependency: &Dependency,
    dependency_version: &Version,
) -> bool {
    for affected in &vulnerability.affected {
        if let Some(package) = &affected.package {
            if !package.name.is_empty() && !package.name.eq_ignore_ascii_case(&dependency.name) {
                continue;
            }
            if !package.ecosystem.is_empty()
                && !package
                    .ecosystem
                    .eq_ignore_ascii_case(osv_ecosystem(dependency.ecosystem))
            {
                continue;
            }
        }

        if affected_versions_match(affected, dependency_version, &dependency.version) {
            return true;
        }
    }

    false
}

fn affected_versions_match(
    affected: &OsvAffected,
    dependency_version: &Version,
    raw_dependency_version: &str,
) -> bool {
    for explicit in &affected.versions {
        if explicit == raw_dependency_version {
            return true;
        }
        if let Some(parsed) = parse_semverish(explicit) {
            if &parsed == dependency_version {
                return true;
            }
        }
    }

    for range in &affected.ranges {
        let kind = range.kind.to_ascii_uppercase();
        if (kind == "SEMVER" || kind == "ECOSYSTEM")
            && version_matches_range_events(dependency_version, &range.events)
        {
            return true;
        }
    }

    false
}

fn version_matches_range_events(version: &Version, events: &[OsvRangeEvent]) -> bool {
    let mut start: Option<Version> = None;

    for event in events {
        if let Some(introduced) = event.introduced.as_deref() {
            start = parse_event_bound(introduced).or_else(|| Some(Version::new(0, 0, 0)));
        }

        if let Some(fixed) = event.fixed.as_deref() {
            let lower = start.clone().unwrap_or_else(|| Version::new(0, 0, 0));
            if let Some(upper) = parse_event_bound(fixed) {
                if version >= &lower && version < &upper {
                    return true;
                }
            }
            start = None;
        }

        if let Some(last_affected) = event.last_affected.as_deref() {
            let lower = start.clone().unwrap_or_else(|| Version::new(0, 0, 0));
            if let Some(upper) = parse_event_bound(last_affected) {
                if version >= &lower && version <= &upper {
                    return true;
                }
            }
            start = None;
        }

        if let Some(limit) = event.limit.as_deref() {
            let lower = start.clone().unwrap_or_else(|| Version::new(0, 0, 0));
            if let Some(upper) = parse_event_bound(limit) {
                if version >= &lower && version < &upper {
                    return true;
                }
            }
            start = None;
        }
    }

    if let Some(lower) = start {
        return version >= &lower;
    }

    false
}

fn parse_event_bound(raw: &str) -> Option<Version> {
    if raw == "0" {
        return Some(Version::new(0, 0, 0));
    }
    parse_semverish(raw)
}

fn extract_cve_id(vulnerability: &OsvVulnerability) -> String {
    for alias in &vulnerability.aliases {
        if alias.starts_with("CVE-") {
            return alias.clone();
        }
    }

    if vulnerability.id.starts_with("CVE-") {
        return vulnerability.id.clone();
    }

    vulnerability
        .aliases
        .first()
        .cloned()
        .unwrap_or_else(|| vulnerability.id.clone())
}

fn extract_severity(vulnerability: &OsvVulnerability) -> Severity {
    if let Some(label) = vulnerability
        .database_specific
        .as_ref()
        .and_then(|database_specific| database_specific.severity.as_deref())
    {
        let severity = Severity::from_label(label);
        if severity != Severity::Unknown {
            return severity;
        }
    }

    for entry in &vulnerability.severity {
        let by_label = Severity::from_label(&entry.score);
        if by_label != Severity::Unknown {
            return by_label;
        }

        if let Ok(score) = entry.score.parse::<f32>() {
            return Severity::from_cvss_score(score);
        }
    }

    Severity::Unknown
}

fn extract_score(vulnerability: &OsvVulnerability) -> Option<String> {
    vulnerability
        .severity
        .first()
        .map(|entry| entry.score.trim().to_string())
        .filter(|score| !score.is_empty())
}

fn extract_remediation(
    vulnerability: &OsvVulnerability,
    dependency: &Dependency,
) -> Option<String> {
    let mut fixed_versions = Vec::new();
    for affected in &vulnerability.affected {
        if let Some(package) = &affected.package {
            if !package.name.is_empty() && !package.name.eq_ignore_ascii_case(&dependency.name) {
                continue;
            }
            if !package.ecosystem.is_empty()
                && !package
                    .ecosystem
                    .eq_ignore_ascii_case(osv_ecosystem(dependency.ecosystem))
            {
                continue;
            }
        }

        for range in &affected.ranges {
            for event in &range.events {
                if let Some(fixed) = event.fixed.as_ref()
                    && !fixed.trim().is_empty()
                {
                    fixed_versions.push(fixed.trim().to_string());
                }
            }
        }
    }

    fixed_versions.sort();
    fixed_versions.dedup();

    if fixed_versions.is_empty() {
        return Some(format!(
            "Check advisory references and upgrade '{}' to a patched release.",
            dependency.name
        ));
    }

    let mut semver_versions = fixed_versions
        .iter()
        .filter_map(|candidate| parse_semverish(candidate).map(|parsed| (candidate, parsed)))
        .collect::<Vec<_>>();

    semver_versions.sort_by(|(_, left), (_, right)| left.cmp(right));

    let ordered_fixed = if semver_versions.is_empty() {
        fixed_versions
    } else {
        semver_versions
            .into_iter()
            .map(|(raw, _)| raw.to_string())
            .collect::<Vec<_>>()
    };

    Some(format!(
        "Upgrade '{}' to a fixed version (one of: {}).",
        dependency.name,
        ordered_fixed.join(", ")
    ))
}

impl Severity {
    fn from_label(label: &str) -> Severity {
        let normalized = label.to_ascii_lowercase();
        if normalized.contains("critical") {
            Severity::Critical
        } else if normalized.contains("high") {
            Severity::High
        } else if normalized.contains("medium") || normalized.contains("moderate") {
            Severity::Medium
        } else if normalized.contains("low") {
            Severity::Low
        } else {
            Severity::Unknown
        }
    }

    fn from_cvss_score(score: f32) -> Severity {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Unknown
        }
    }
}

fn osv_ecosystem(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Node => "npm",
        Ecosystem::Python => "PyPI",
        Ecosystem::Rust => "crates.io",
    }
}

fn parse_manifest_file(path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let contents = read_file(path)?;

    match file_name {
        "package.json" => parse_package_json(&contents, path),
        "package-lock.json" => parse_package_lock(&contents, path),
        "requirements.txt" => Ok(parse_requirements(&contents)),
        "pyproject.toml" => parse_pyproject(&contents, path),
        "Cargo.toml" => parse_cargo_toml(&contents, path),
        "Cargo.lock" => parse_cargo_lock(&contents, path),
        _ => Ok(Vec::new()),
    }
}

fn read_file(path: &Path) -> Result<String, ScanError> {
    fs::read_to_string(path).map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_package_json(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let package_json: PackageJson =
        serde_json::from_str(contents).map_err(|source| ScanError::Json {
            path: path.to_path_buf(),
            source,
        })?;

    let mut dependencies = Vec::new();
    dependencies.extend(node_dependencies_from_map(package_json.dependencies));
    dependencies.extend(node_dependencies_from_map(package_json.dev_dependencies));
    dependencies.extend(node_dependencies_from_map(package_json.peer_dependencies));
    dependencies.extend(node_dependencies_from_map(
        package_json.optional_dependencies,
    ));

    Ok(dependencies)
}

fn node_dependencies_from_map(map: HashMap<String, String>) -> Vec<Dependency> {
    map.into_iter()
        .map(|(name, version)| Dependency {
            name,
            version,
            ecosystem: Ecosystem::Node,
            direct: true,
        })
        .collect()
}

fn parse_package_lock(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let json: JsonValue = serde_json::from_str(contents).map_err(|source| ScanError::Json {
        path: path.to_path_buf(),
        source,
    })?;

    let mut dependencies = Vec::new();

    if let Some(packages) = json.get("packages").and_then(JsonValue::as_object) {
        for (package_path, metadata) in packages {
            if package_path.is_empty() {
                continue;
            }
            let Some(version) = metadata.get("version").and_then(JsonValue::as_str) else {
                continue;
            };

            let name = metadata
                .get("name")
                .and_then(JsonValue::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| infer_name_from_package_path(package_path));

            if name.is_empty() {
                continue;
            }

            dependencies.push(Dependency {
                name,
                version: version.to_string(),
                ecosystem: Ecosystem::Node,
                direct: is_direct_lockfile_entry(package_path),
            });
        }
    }

    if dependencies.is_empty()
        && let Some(v1_dependencies) = json.get("dependencies").and_then(JsonValue::as_object)
    {
        collect_v1_lock_dependencies(v1_dependencies, true, &mut dependencies);
    }

    Ok(dependencies)
}

fn infer_name_from_package_path(package_path: &str) -> String {
    if let Some((_, tail)) = package_path.rsplit_once("node_modules/") {
        return tail.to_string();
    }
    package_path.to_string()
}

fn is_direct_lockfile_entry(package_path: &str) -> bool {
    package_path.starts_with("node_modules/") && package_path.matches("node_modules/").count() == 1
}

fn collect_v1_lock_dependencies(
    dependencies: &Map<String, JsonValue>,
    direct: bool,
    out: &mut Vec<Dependency>,
) {
    for (name, metadata) in dependencies {
        let version = metadata
            .get("version")
            .and_then(JsonValue::as_str)
            .unwrap_or("*")
            .to_string();

        out.push(Dependency {
            name: name.to_string(),
            version,
            ecosystem: Ecosystem::Node,
            direct,
        });

        if let Some(children) = metadata.get("dependencies").and_then(JsonValue::as_object) {
            collect_v1_lock_dependencies(children, false, out);
        }
    }
}

fn parse_requirements(contents: &str) -> Vec<Dependency> {
    contents
        .lines()
        .filter_map(parse_python_requirement_line)
        .collect()
}

fn parse_python_requirement_line(line: &str) -> Option<Dependency> {
    let mut trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
        return None;
    }

    if let Some((before_comment, _)) = trimmed.split_once('#') {
        trimmed = before_comment.trim();
    }

    if trimmed.is_empty() {
        return None;
    }

    parse_python_requirement(trimmed)
}

fn parse_python_requirement(requirement: &str) -> Option<Dependency> {
    let requirement = if let Some((lhs, _rhs)) = requirement.split_once(';') {
        lhs.trim()
    } else {
        requirement
    };

    if requirement.is_empty() {
        return None;
    }

    if let Some((name, version)) = split_name_and_constraint(requirement) {
        return Some(Dependency {
            name,
            version,
            ecosystem: Ecosystem::Python,
            direct: true,
        });
    }

    let name = if let Some((lhs, _rhs)) = requirement.split_once(" @ ") {
        lhs.trim().to_string()
    } else {
        requirement.to_string()
    };

    if name.is_empty() {
        return None;
    }

    Some(Dependency {
        name,
        version: "*".to_string(),
        ecosystem: Ecosystem::Python,
        direct: true,
    })
}

fn parse_pyproject(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let value: TomlValue = toml::from_str(contents).map_err(|source| ScanError::Toml {
        path: path.to_path_buf(),
        source,
    })?;

    let mut dependencies = Vec::new();

    if let Some(project) = value.get("project").and_then(TomlValue::as_table)
        && let Some(list) = project.get("dependencies").and_then(TomlValue::as_array)
    {
        for entry in list {
            if let Some(requirement) = entry.as_str()
                && let Some(dep) = parse_python_requirement(requirement)
            {
                dependencies.push(dep);
            }
        }
    }

    if let Some(poetry) = value
        .get("tool")
        .and_then(TomlValue::as_table)
        .and_then(|tool| tool.get("poetry"))
        .and_then(TomlValue::as_table)
        && let Some(poetry_dependencies) = poetry.get("dependencies").and_then(TomlValue::as_table)
    {
        for (name, item) in poetry_dependencies {
            if name == "python" {
                continue;
            }
            let version = match item {
                TomlValue::String(raw) => raw.to_string(),
                TomlValue::Table(details) => details
                    .get("version")
                    .and_then(TomlValue::as_str)
                    .unwrap_or("*")
                    .to_string(),
                _ => "*".to_string(),
            };
            dependencies.push(Dependency {
                name: name.to_string(),
                version,
                ecosystem: Ecosystem::Python,
                direct: true,
            });
        }
    }

    Ok(dependencies)
}

fn parse_cargo_toml(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let value: TomlValue = toml::from_str(contents).map_err(|source| ScanError::Toml {
        path: path.to_path_buf(),
        source,
    })?;

    let Some(root) = value.as_table() else {
        return Ok(Vec::new());
    };

    let mut dependencies = Vec::new();
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = root.get(key).and_then(TomlValue::as_table) {
            dependencies.extend(parse_cargo_dependency_table(table));
        }
    }

    Ok(dependencies)
}

fn parse_cargo_dependency_table(table: &toml::map::Map<String, TomlValue>) -> Vec<Dependency> {
    let mut dependencies = Vec::new();

    for (key, value) in table {
        let (name, version) = match value {
            TomlValue::String(version) => (key.to_string(), version.to_string()),
            TomlValue::Table(details) => {
                let name = details
                    .get("package")
                    .and_then(TomlValue::as_str)
                    .unwrap_or(key)
                    .to_string();
                let version = details
                    .get("version")
                    .and_then(TomlValue::as_str)
                    .unwrap_or("*")
                    .to_string();
                (name, version)
            }
            _ => (key.to_string(), "*".to_string()),
        };

        dependencies.push(Dependency {
            name,
            version,
            ecosystem: Ecosystem::Rust,
            direct: true,
        });
    }

    dependencies
}

fn parse_cargo_lock(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let value: TomlValue = toml::from_str(contents).map_err(|source| ScanError::Toml {
        path: path.to_path_buf(),
        source,
    })?;

    let direct_dependencies = path
        .parent()
        .map(collect_cargo_direct_names)
        .transpose()?
        .unwrap_or_default();

    let mut dependencies = Vec::new();
    if let Some(packages) = value.get("package").and_then(TomlValue::as_array) {
        for package in packages {
            let Some(table) = package.as_table() else {
                continue;
            };
            let Some(name) = table.get("name").and_then(TomlValue::as_str) else {
                continue;
            };

            let version = table
                .get("version")
                .and_then(TomlValue::as_str)
                .unwrap_or("*")
                .to_string();

            dependencies.push(Dependency {
                name: name.to_string(),
                version,
                ecosystem: Ecosystem::Rust,
                direct: direct_dependencies.contains(name),
            });
        }
    }

    Ok(dependencies)
}

fn collect_cargo_direct_names(project_root: &Path) -> Result<HashSet<String>, ScanError> {
    let manifest_path = project_root.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Ok(HashSet::new());
    }

    let contents = read_file(&manifest_path)?;
    let dependencies = parse_cargo_toml(&contents, &manifest_path)?;
    Ok(dependencies
        .into_iter()
        .map(|dependency| dependency.name)
        .collect())
}

fn split_name_and_constraint(requirement: &str) -> Option<(String, String)> {
    const OPS: [&str; 7] = ["==", ">=", "<=", "~=", "!=", ">", "<"];
    let mut earliest: Option<(usize, &str)> = None;

    for op in OPS {
        if let Some(index) = requirement.find(op) {
            match earliest {
                Some((current, _)) if index >= current => {}
                _ => earliest = Some((index, op)),
            }
        }
    }

    let (index, op) = earliest?;
    let name = requirement[..index].trim().to_string();
    let tail = requirement[index + op.len()..].trim();
    if name.is_empty() || tail.is_empty() {
        return None;
    }

    Some((name, format!("{op}{tail}")))
}

fn parse_semverish(raw: &str) -> Option<Version> {
    let mut normalized = raw.trim();
    if normalized.is_empty() {
        return None;
    }

    if let Some((head, _)) = normalized.split_once(',') {
        normalized = head.trim();
    }
    if let Some((head, _)) = normalized.split_once("||") {
        normalized = head.trim();
    }

    for op in ["==", ">=", "<=", "~=", "!=", "^", "~", "=", ">", "<"] {
        if normalized.starts_with(op) {
            normalized = normalized[op.len()..].trim();
            break;
        }
    }

    if let Some(stripped) = normalized.strip_prefix('v') {
        normalized = stripped;
    }

    if let Some((head, _)) = normalized.split_once(' ') {
        normalized = head.trim();
    }

    if normalized.is_empty()
        || normalized.contains('*')
        || normalized.contains('x')
        || normalized.contains('X')
    {
        return None;
    }

    if let Ok(version) = Version::parse(normalized) {
        return Some(version);
    }

    let dot_count = normalized.matches('.').count();
    let coerced = if dot_count == 0 {
        format!("{normalized}.0.0")
    } else if dot_count == 1 {
        format!("{normalized}.0")
    } else {
        return None;
    };

    Version::parse(&coerced).ok()
}

fn dedupe_and_sort(dependencies: Vec<Dependency>) -> Vec<Dependency> {
    let mut merged_map: BTreeMap<(Ecosystem, String, String), bool> = BTreeMap::new();
    for dependency in dependencies {
        let key = (
            dependency.ecosystem,
            dependency.name.clone(),
            dependency.version.clone(),
        );
        merged_map
            .entry(key)
            .and_modify(|direct| *direct = *direct || dependency.direct)
            .or_insert(dependency.direct);
    }

    let mut merged = merged_map
        .into_iter()
        .map(|((ecosystem, name, version), direct)| Dependency {
            name,
            version,
            ecosystem,
            direct,
        })
        .collect::<Vec<_>>();

    let exact_direct = merged
        .iter()
        .filter(|dependency| dependency.direct && !looks_like_version_spec(&dependency.version))
        .map(|dependency| (dependency.ecosystem, dependency.name.clone()))
        .collect::<BTreeSet<_>>();

    merged.retain(|dependency| {
        !(dependency.direct
            && looks_like_version_spec(&dependency.version)
            && exact_direct.contains(&(dependency.ecosystem, dependency.name.clone())))
    });

    merged
}

fn looks_like_version_spec(version: &str) -> bool {
    const PREFIXES: [char; 8] = ['^', '~', '>', '<', '=', '!', '*', '@'];
    version
        .chars()
        .next()
        .is_some_and(|prefix| PREFIXES.contains(&prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_node_dependencies_from_package_json() {
        let input = r#"{
            "dependencies": {"express": "^4.18.2"},
            "devDependencies": {"typescript": "^5.5.0"}
        }"#;

        let dependencies = parse_package_json(input, Path::new("package.json"))
            .expect("package.json should parse");

        assert!(dependencies.contains(&Dependency {
            name: "express".to_string(),
            version: "^4.18.2".to_string(),
            ecosystem: Ecosystem::Node,
            direct: true,
        }));

        assert!(dependencies.contains(&Dependency {
            name: "typescript".to_string(),
            version: "^5.5.0".to_string(),
            ecosystem: Ecosystem::Node,
            direct: true,
        }));
    }

    #[test]
    fn semver_range_matching_with_fixed_boundary() {
        let version = Version::parse("1.3.0").expect("valid semver");
        let events = vec![
            OsvRangeEvent {
                introduced: Some("1.0.0".to_string()),
                fixed: None,
                last_affected: None,
                limit: None,
            },
            OsvRangeEvent {
                introduced: None,
                fixed: Some("2.0.0".to_string()),
                last_affected: None,
                limit: None,
            },
        ];

        assert!(version_matches_range_events(&version, &events));

        let fixed_version = Version::parse("2.0.0").expect("valid semver");
        assert!(!version_matches_range_events(&fixed_version, &events));
    }

    #[test]
    fn semver_range_matching_with_last_affected_boundary() {
        let events = vec![
            OsvRangeEvent {
                introduced: Some("0".to_string()),
                fixed: None,
                last_affected: None,
                limit: None,
            },
            OsvRangeEvent {
                introduced: None,
                fixed: None,
                last_affected: Some("1.4.2".to_string()),
                limit: None,
            },
        ];

        let vulnerable = Version::parse("1.4.2").expect("valid semver");
        let patched = Version::parse("1.4.3").expect("valid semver");

        assert!(version_matches_range_events(&vulnerable, &events));
        assert!(!version_matches_range_events(&patched, &events));
    }

    #[test]
    fn semver_normalization_handles_prefixes() {
        let normalized = parse_semverish("^1.2").expect("version should normalize");
        assert_eq!(normalized, Version::parse("1.2.0").expect("valid semver"));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    Node,
    Python,
    Rust,
}

impl Display for Ecosystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node => write!(f, "node"),
            Self::Python => write!(f, "python"),
            Self::Rust => write!(f, "rust"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub direct: bool,
}

#[derive(Debug)]
pub enum ScanError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },
    Walk {
        path: PathBuf,
        source: walkdir::Error,
    },
}

impl Display for ScanError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read '{}': {}", path.display(), source)
            }
            Self::Json { path, source } => {
                write!(f, "failed to parse JSON '{}': {}", path.display(), source)
            }
            Self::Toml { path, source } => {
                write!(f, "failed to parse TOML '{}': {}", path.display(), source)
            }
            Self::Walk { path, source } => {
                write!(f, "failed while walking '{}': {}", path.display(), source)
            }
        }
    }
}

impl Error for ScanError {}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PackageJson {
    dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies")]
    dev_dependencies: HashMap<String, String>,
    #[serde(rename = "peerDependencies")]
    peer_dependencies: HashMap<String, String>,
    #[serde(rename = "optionalDependencies")]
    optional_dependencies: HashMap<String, String>,
}

pub fn scan_dependencies(path: &Path) -> Result<Vec<Dependency>, ScanError> {
    scan_dependencies_with_options(path, false)
}

pub fn scan_dependencies_with_options(
    path: &Path,
    recursive: bool,
) -> Result<Vec<Dependency>, ScanError> {
    if !path.exists() {
        return Err(ScanError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(ErrorKind::NotFound, "path does not exist"),
        });
    }

    let manifest_files = collect_manifest_files(path, recursive)?;
    let mut dependencies = Vec::new();
    for file in manifest_files {
        dependencies.extend(parse_manifest_file(&file)?);
    }

    Ok(dedupe_and_sort(dependencies))
}

fn collect_manifest_files(path: &Path, recursive: bool) -> Result<Vec<PathBuf>, ScanError> {
    if path.is_file() {
        if is_supported_manifest(path) {
            return Ok(vec![path.to_path_buf()]);
        }
        return Ok(Vec::new());
    }

    let mut manifest_paths = Vec::new();
    if recursive {
        for entry in WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_entry(should_descend)
        {
            let entry = entry.map_err(|source| ScanError::Walk {
                path: path.to_path_buf(),
                source,
            })?;
            let candidate = entry.path();
            if candidate.is_file() && is_supported_manifest(candidate) {
                manifest_paths.push(candidate.to_path_buf());
            }
        }
    } else {
        for file_name in SUPPORTED_MANIFESTS {
            let candidate = path.join(file_name);
            if candidate.is_file() {
                manifest_paths.push(candidate);
            }
        }
    }

    manifest_paths.sort();
    Ok(manifest_paths)
}

fn should_descend(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    let ignored = [
        ".git",
        "node_modules",
        "target",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
    ];
    let name = entry.file_name().to_string_lossy();
    !ignored.iter().any(|candidate| *candidate == name)
}

fn is_supported_manifest(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| SUPPORTED_MANIFESTS.contains(&name))
}

fn parse_manifest_file(path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let contents = read_file(path)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();

    match file_name {
        "package.json" => parse_package_json(&contents, path),
        "package-lock.json" | "npm-shrinkwrap.json" => parse_package_lock(&contents, path),
        "requirements.txt" => Ok(parse_requirements(&contents)),
        "pyproject.toml" => parse_pyproject_toml(&contents, path),
        "poetry.lock" => parse_poetry_lock(&contents, path),
        "Cargo.toml" => parse_cargo_toml(&contents, path),
        "Cargo.lock" => parse_cargo_lock(&contents, path),
        _ => Ok(Vec::new()),
    }
}

fn read_file(path: &Path) -> Result<String, ScanError> {
    fs::read_to_string(path).map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_package_json(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let parsed: PackageJson = serde_json::from_str(contents).map_err(|source| ScanError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    let mut dependencies = Vec::new();

    dependencies.extend(node_deps_from_map(parsed.dependencies));
    dependencies.extend(node_deps_from_map(parsed.dev_dependencies));
    dependencies.extend(node_deps_from_map(parsed.peer_dependencies));
    dependencies.extend(node_deps_from_map(parsed.optional_dependencies));

    Ok(dependencies)
}

fn node_deps_from_map(map: HashMap<String, String>) -> Vec<Dependency> {
    map.into_iter()
        .map(|(name, version)| Dependency {
            name,
            version,
            ecosystem: Ecosystem::Node,
            direct: true,
        })
        .collect()
}

fn parse_package_lock(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let value: JsonValue = serde_json::from_str(contents).map_err(|source| ScanError::Json {
        path: path.to_path_buf(),
        source,
    })?;

    let mut dependencies = Vec::new();

    if let Some(packages) = value.get("packages").and_then(JsonValue::as_object) {
        for (package_path, metadata) in packages {
            if package_path.is_empty() {
                continue;
            }

            let Some(version) = metadata.get("version").and_then(JsonValue::as_str) else {
                continue;
            };

            let name = metadata
                .get("name")
                .and_then(JsonValue::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| infer_name_from_package_path(package_path));

            if name.is_empty() {
                continue;
            }

            dependencies.push(Dependency {
                name,
                version: version.to_string(),
                ecosystem: Ecosystem::Node,
                direct: is_direct_lockfile_entry(package_path),
            });
        }
    }

    if dependencies.is_empty()
        && let Some(v1_deps) = value.get("dependencies").and_then(JsonValue::as_object)
    {
        collect_v1_lockfile_dependencies(v1_deps, true, &mut dependencies);
    }

    Ok(dependencies)
}

fn infer_name_from_package_path(package_path: &str) -> String {
    if let Some((_, tail)) = package_path.rsplit_once("node_modules/") {
        return tail.to_string();
    }
    package_path.to_string()
}

fn is_direct_lockfile_entry(package_path: &str) -> bool {
    package_path.matches("node_modules/").count() == 1 && package_path.starts_with("node_modules/")
}

fn collect_v1_lockfile_dependencies(
    deps: &Map<String, JsonValue>,
    direct: bool,
    out: &mut Vec<Dependency>,
) {
    for (name, metadata) in deps {
        let version = metadata
            .get("version")
            .and_then(JsonValue::as_str)
            .unwrap_or("*")
            .to_string();

        out.push(Dependency {
            name: name.to_string(),
            version,
            ecosystem: Ecosystem::Node,
            direct,
        });

        if let Some(children) = metadata.get("dependencies").and_then(JsonValue::as_object) {
            collect_v1_lockfile_dependencies(children, false, out);
        }
    }
}

fn parse_requirements(contents: &str) -> Vec<Dependency> {
    contents
        .lines()
        .filter_map(parse_requirement_line)
        .collect::<Vec<_>>()
}

fn parse_requirement_line(line: &str) -> Option<Dependency> {
    let mut trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    if let Some((before_comment, _)) = trimmed.split_once('#') {
        trimmed = before_comment.trim();
    }

    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('-') {
        return None;
    }

    parse_python_requirement(trimmed)
}

fn parse_pyproject_toml(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let value: TomlValue = toml::from_str(contents).map_err(|source| ScanError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    let mut dependencies = Vec::new();

    if let Some(project) = value.get("project").and_then(TomlValue::as_table) {
        if let Some(list) = project.get("dependencies").and_then(TomlValue::as_array) {
            dependencies.extend(parse_python_dependency_list(list));
        }
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(TomlValue::as_table)
        {
            for group in optional.values() {
                if let Some(list) = group.as_array() {
                    dependencies.extend(parse_python_dependency_list(list));
                }
            }
        }
    }

    if let Some(poetry) = value
        .get("tool")
        .and_then(TomlValue::as_table)
        .and_then(|tool| tool.get("poetry"))
        .and_then(TomlValue::as_table)
    {
        if let Some(deps) = poetry.get("dependencies").and_then(TomlValue::as_table) {
            dependencies.extend(parse_poetry_dependency_table(deps));
        }
        if let Some(dev_deps) = poetry.get("dev-dependencies").and_then(TomlValue::as_table) {
            dependencies.extend(parse_poetry_dependency_table(dev_deps));
        }
        if let Some(groups) = poetry.get("group").and_then(TomlValue::as_table) {
            for group in groups.values() {
                if let Some(group_deps) = group
                    .as_table()
                    .and_then(|table| table.get("dependencies"))
                    .and_then(TomlValue::as_table)
                {
                    dependencies.extend(parse_poetry_dependency_table(group_deps));
                }
            }
        }
    }

    Ok(dependencies)
}

fn parse_poetry_lock(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let value: TomlValue = toml::from_str(contents).map_err(|source| ScanError::Toml {
        path: path.to_path_buf(),
        source,
    })?;

    let direct_names = path
        .parent()
        .map(collect_python_direct_names)
        .transpose()?
        .unwrap_or_default();

    let mut dependencies = Vec::new();
    if let Some(packages) = value.get("package").and_then(TomlValue::as_array) {
        for package in packages {
            let Some(table) = package.as_table() else {
                continue;
            };
            let Some(name) = table.get("name").and_then(TomlValue::as_str) else {
                continue;
            };
            let version = table
                .get("version")
                .and_then(TomlValue::as_str)
                .unwrap_or("*")
                .to_string();
            dependencies.push(Dependency {
                name: name.to_string(),
                version,
                ecosystem: Ecosystem::Python,
                direct: direct_names.contains(name),
            });
        }
    }
    Ok(dependencies)
}

fn collect_python_direct_names(project_root: &Path) -> Result<HashSet<String>, ScanError> {
    let pyproject_path = project_root.join("pyproject.toml");
    if !pyproject_path.is_file() {
        return Ok(HashSet::new());
    }
    let contents = read_file(&pyproject_path)?;
    let deps = parse_pyproject_toml(&contents, &pyproject_path)?;
    Ok(deps.into_iter().map(|dep| dep.name).collect())
}

fn parse_python_dependency_list(list: &[TomlValue]) -> Vec<Dependency> {
    list.iter()
        .filter_map(TomlValue::as_str)
        .filter_map(parse_python_requirement)
        .collect()
}

fn parse_poetry_dependency_table(table: &toml::map::Map<String, TomlValue>) -> Vec<Dependency> {
    let mut dependencies = Vec::new();
    for (name, value) in table {
        if name == "python" {
            continue;
        }
        let version = match value {
            TomlValue::String(raw) => raw.to_string(),
            TomlValue::Table(details) => details
                .get("version")
                .and_then(TomlValue::as_str)
                .unwrap_or("*")
                .to_string(),
            _ => "*".to_string(),
        };
        dependencies.push(Dependency {
            name: name.to_string(),
            version,
            ecosystem: Ecosystem::Python,
            direct: true,
        });
    }
    dependencies
}

fn parse_python_requirement(requirement: &str) -> Option<Dependency> {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return None;
    }

    let requirement = if let Some((lhs, _rhs)) = requirement.split_once(';') {
        lhs.trim()
    } else {
        requirement
    };

    if let Some((name, version)) = parse_name_and_version_spec(requirement) {
        if name.is_empty() {
            return None;
        }
        return Some(Dependency {
            name,
            version,
            ecosystem: Ecosystem::Python,
            direct: true,
        });
    }

    let name = if let Some((lhs, _rhs)) = requirement.split_once(" @ ") {
        lhs.trim().to_string()
    } else {
        requirement.to_string()
    };

    if name.is_empty() {
        return None;
    }

    Some(Dependency {
        name,
        version: "*".to_string(),
        ecosystem: Ecosystem::Python,
        direct: true,
    })
}

fn parse_cargo_toml(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let value: TomlValue = toml::from_str(contents).map_err(|source| ScanError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    let mut dependencies = Vec::new();
    let Some(root) = value.as_table() else {
        return Ok(dependencies);
    };

    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = root.get(key).and_then(TomlValue::as_table) {
            dependencies.extend(parse_cargo_dependency_table(table));
        }
    }

    if let Some(targets) = root.get("target").and_then(TomlValue::as_table) {
        for target in targets.values() {
            if let Some(target_table) = target.as_table() {
                for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    if let Some(table) = target_table.get(key).and_then(TomlValue::as_table) {
                        dependencies.extend(parse_cargo_dependency_table(table));
                    }
                }
            }
        }
    }

    Ok(dependencies)
}

fn parse_cargo_dependency_table(table: &toml::map::Map<String, TomlValue>) -> Vec<Dependency> {
    let mut dependencies = Vec::new();
    for (key, value) in table {
        let (name, version) = match value {
            TomlValue::String(version) => (key.to_string(), version.to_string()),
            TomlValue::Table(details) => {
                let name = details
                    .get("package")
                    .and_then(TomlValue::as_str)
                    .unwrap_or(key)
                    .to_string();
                let version = details
                    .get("version")
                    .and_then(TomlValue::as_str)
                    .unwrap_or("*")
                    .to_string();
                (name, version)
            }
            _ => (key.to_string(), "*".to_string()),
        };
        dependencies.push(Dependency {
            name,
            version,
            ecosystem: Ecosystem::Rust,
            direct: true,
        });
    }
    dependencies
}

fn parse_cargo_lock(contents: &str, path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let value: TomlValue = toml::from_str(contents).map_err(|source| ScanError::Toml {
        path: path.to_path_buf(),
        source,
    })?;

    let direct_names = path
        .parent()
        .map(collect_rust_direct_names)
        .transpose()?
        .unwrap_or_default();

    let mut dependencies = Vec::new();
    if let Some(packages) = value.get("package").and_then(TomlValue::as_array) {
        for package in packages {
            let Some(table) = package.as_table() else {
                continue;
            };
            let Some(name) = table.get("name").and_then(TomlValue::as_str) else {
                continue;
            };
            let version = table
                .get("version")
                .and_then(TomlValue::as_str)
                .unwrap_or("*")
                .to_string();
            dependencies.push(Dependency {
                name: name.to_string(),
                version,
                ecosystem: Ecosystem::Rust,
                direct: direct_names.contains(name),
            });
        }
    }
    Ok(dependencies)
}

fn collect_rust_direct_names(project_root: &Path) -> Result<HashSet<String>, ScanError> {
    let manifest_path = project_root.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Ok(HashSet::new());
    }
    let contents = read_file(&manifest_path)?;
    let deps = parse_cargo_toml(&contents, &manifest_path)?;
    Ok(deps.into_iter().map(|dep| dep.name).collect())
}

fn parse_name_and_version_spec(requirement: &str) -> Option<(String, String)> {
    const OPS: [&str; 7] = ["==", ">=", "<=", "~=", "!=", ">", "<"];
    let mut earliest: Option<(usize, &str)> = None;

    for op in OPS {
        if let Some(index) = requirement.find(op) {
            match earliest {
                Some((current, _)) if index >= current => {}
                _ => earliest = Some((index, op)),
            }
        }
    }

    let (index, op) = earliest?;
    let name = requirement[..index].trim().to_string();
    let version_tail = requirement[index + op.len()..].trim();
    let version = format!("{op}{version_tail}");

    Some((name, version))
}

fn dedupe_and_sort(dependencies: Vec<Dependency>) -> Vec<Dependency> {
    let mut map: BTreeMap<(Ecosystem, String, String), bool> = BTreeMap::new();
    for dep in dependencies {
        let key = (dep.ecosystem, dep.name, dep.version);
        map.entry(key)
            .and_modify(|current_direct| *current_direct = *current_direct || dep.direct)
            .or_insert(dep.direct);
    }

    let mut merged = map
        .into_iter()
        .map(|((ecosystem, name, version), direct)| Dependency {
            name,
            version,
            ecosystem,
            direct,
        })
        .collect::<Vec<_>>();

    let exact_direct_names = merged
        .iter()
        .filter(|dep| dep.direct && !looks_like_version_spec(&dep.version))
        .map(|dep| (dep.ecosystem, dep.name.clone()))
        .collect::<BTreeSet<_>>();

    merged.retain(|dep| {
        !(dep.direct
            && looks_like_version_spec(&dep.version)
            && exact_direct_names.contains(&(dep.ecosystem, dep.name.clone())))
    });

    merged
}

fn looks_like_version_spec(version: &str) -> bool {
    const PREFIXES: [char; 8] = ['^', '~', '>', '<', '=', '!', '*', '@'];
    version
        .chars()
        .next()
        .is_some_and(|first| PREFIXES.contains(&first))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_json_dependencies() {
        let input = r#"{
            "dependencies": { "express": "^4.18.2" },
            "devDependencies": { "typescript": "^5.5.0" }
        }"#;

        let deps = parse_package_json(input, Path::new("package.json"))
            .expect("package.json should parse");
        assert!(deps.contains(&Dependency {
            name: "express".to_string(),
            version: "^4.18.2".to_string(),
            ecosystem: Ecosystem::Node,
            direct: true,
        }));
        assert!(deps.contains(&Dependency {
            name: "typescript".to_string(),
            version: "^5.5.0".to_string(),
            ecosystem: Ecosystem::Node,
            direct: true,
        }));
    }

    #[test]
    fn parses_package_lock_v2_with_direct_and_transitive() {
        let input = r#"{
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "demo", "version": "1.0.0" },
                "node_modules/left-pad": { "version": "1.3.0" },
                "node_modules/left-pad/node_modules/repeat-string": { "version": "1.6.1" }
            }
        }"#;

        let deps = parse_package_lock(input, Path::new("package-lock.json"))
            .expect("package-lock should parse");
        assert!(deps.contains(&Dependency {
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            ecosystem: Ecosystem::Node,
            direct: true,
        }));
        assert!(deps.contains(&Dependency {
            name: "repeat-string".to_string(),
            version: "1.6.1".to_string(),
            ecosystem: Ecosystem::Node,
            direct: false,
        }));
    }

    #[test]
    fn parses_requirements_lines() {
        let input = r#"
            requests==2.31.0
            fastapi>=0.115.0
            # comment
            uvicorn
        "#;

        let deps = parse_requirements(input);
        assert_eq!(deps.len(), 3);
        assert!(deps.contains(&Dependency {
            name: "requests".to_string(),
            version: "==2.31.0".to_string(),
            ecosystem: Ecosystem::Python,
            direct: true,
        }));
        assert!(deps.contains(&Dependency {
            name: "uvicorn".to_string(),
            version: "*".to_string(),
            ecosystem: Ecosystem::Python,
            direct: true,
        }));
    }

    #[test]
    fn parses_cargo_toml_dependencies() {
        let input = r#"
            [dependencies]
            serde = "1"

            [dev-dependencies]
            tokio = { version = "1.40", features = ["macros"] }
        "#;

        let deps =
            parse_cargo_toml(input, Path::new("Cargo.toml")).expect("Cargo.toml should parse");
        assert!(deps.contains(&Dependency {
            name: "serde".to_string(),
            version: "1".to_string(),
            ecosystem: Ecosystem::Rust,
            direct: true,
        }));
        assert!(deps.contains(&Dependency {
            name: "tokio".to_string(),
            version: "1.40".to_string(),
            ecosystem: Ecosystem::Rust,
            direct: true,
        }));
    }

    #[test]
    fn parses_pyproject_dependencies() {
        let input = r#"
            [project]
            dependencies = ["fastapi>=0.115.0", "uvicorn"]

            [tool.poetry.dependencies]
            python = "^3.12"
            requests = "^2.31.0"
        "#;

        let deps = parse_pyproject_toml(input, Path::new("pyproject.toml"))
            .expect("pyproject.toml should parse");
        assert!(deps.contains(&Dependency {
            name: "fastapi".to_string(),
            version: ">=0.115.0".to_string(),
            ecosystem: Ecosystem::Python,
            direct: true,
        }));
        assert!(deps.contains(&Dependency {
            name: "requests".to_string(),
            version: "^2.31.0".to_string(),
            ecosystem: Ecosystem::Python,
            direct: true,
        }));
    }
}
