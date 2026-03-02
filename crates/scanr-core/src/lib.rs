use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, hash_map::DefaultHasher};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::hash::{Hash, Hasher};
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
    pub upgrade_recommendations: Vec<UpgradeRecommendation>,
    pub queried_dependencies: usize,
    pub failed_queries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel {
    Low,
    Moderate,
    High,
}

impl Display for RiskLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Moderate => write!(f, "MODERATE"),
            Self::High => write!(f, "HIGH"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RiskSummary {
    pub total: usize,
    pub counts: SeverityCounts,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub max_critical: usize,
    pub max_high: usize,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            max_critical: 0,
            max_high: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyEvaluation {
    pub passed: bool,
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpgradeRecommendation {
    pub package_name: String,
    pub ecosystem: Ecosystem,
    pub current_version: String,
    pub suggested_version: String,
    pub major_bump: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct SeveritySummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub unknown: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanResult {
    pub target: String,
    pub path: String,
    pub total_dependencies: u32,
    pub dependencies: Vec<Dependency>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub upgrade_recommendations: Vec<UpgradeRecommendation>,
    pub risk_score: u32,
    pub severity_summary: SeveritySummary,
    pub risk_level: RiskLevel,
    pub queried_dependencies: u32,
    pub failed_queries: u32,
    pub lookup_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifReport {
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifRule {
    pub id: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifText {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifText,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
    #[serde(rename = "logicalLocations")]
    pub logical_locations: Vec<SarifLogicalLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifLogicalLocation {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomDocument {
    pub target: String,
    pub path: String,
    pub component_count: usize,
    pub json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SbomVersionChange {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub old_versions: Vec<String>,
    pub new_versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SbomDiffReport {
    pub old_components: usize,
    pub new_components: usize,
    pub added_dependencies: Vec<Dependency>,
    pub removed_dependencies: Vec<Dependency>,
    pub version_changes: Vec<SbomVersionChange>,
    pub introduced_dependencies: Vec<Dependency>,
}

#[derive(Debug, Serialize)]
struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    #[serde(rename = "serialNumber")]
    serial_number: String,
    version: u32,
    metadata: CycloneDxMetadata,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    components: Vec<CycloneDxComponent>,
    dependencies: Vec<CycloneDxDependencyEntry>,
}

#[derive(Debug, Serialize)]
struct CycloneDxMetadata {
    component: CycloneDxComponent,
}

#[derive(Debug, Serialize, Clone)]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: String,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
}

#[derive(Debug, Serialize)]
struct CycloneDxDependencyEntry {
    #[serde(rename = "ref")]
    ref_id: String,
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct CycloneDxBomInput {
    components: Vec<CycloneDxComponentInput>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct CycloneDxComponentInput {
    #[serde(rename = "type")]
    _component_type: String,
    name: String,
    version: Option<String>,
    scope: Option<String>,
    purl: Option<String>,
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

pub fn generate_cyclonedx_sbom(path: &Path) -> Result<SbomDocument, ScanError> {
    let dependencies = scan_dependencies(path)?;
    let resolved_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let target = resolved_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| resolved_path.display().to_string());
    let display_path = normalize_windows_verbatim_path(resolved_path.display().to_string());
    let root_ref = format!("urn:scanr:application:{}", sanitize_ref(&target));

    let mut component_refs = Vec::with_capacity(dependencies.len());
    let components = dependencies
        .iter()
        .map(|dependency| {
            let purl = package_url(dependency);
            component_refs.push((purl.clone(), dependency.direct));
            CycloneDxComponent {
                component_type: "library".to_string(),
                bom_ref: purl.clone(),
                name: dependency.name.clone(),
                version: Some(dependency.version.clone()),
                scope: Some(if dependency.direct {
                    "required".to_string()
                } else {
                    "optional".to_string()
                }),
                purl: Some(purl),
            }
        })
        .collect::<Vec<_>>();

    let metadata = CycloneDxMetadata {
        component: CycloneDxComponent {
            component_type: "application".to_string(),
            bom_ref: root_ref.clone(),
            name: target.clone(),
            version: None,
            scope: None,
            purl: None,
        },
    };

    let direct_dependencies = component_refs
        .iter()
        .filter_map(|(ref_id, direct)| if *direct { Some(ref_id.clone()) } else { None })
        .collect::<Vec<_>>();
    let mut dependency_graph = Vec::with_capacity(component_refs.len() + 1);
    dependency_graph.push(CycloneDxDependencyEntry {
        ref_id: root_ref,
        depends_on: direct_dependencies,
    });
    dependency_graph.extend(component_refs.into_iter().map(|(ref_id, _)| {
        CycloneDxDependencyEntry {
            ref_id,
            depends_on: Vec::new(),
        }
    }));

    let bom = CycloneDxBom {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        serial_number: format!(
            "urn:uuid:{}",
            deterministic_uuid(&target, &display_path, dependencies.len())
        ),
        version: 1,
        metadata,
        components,
        dependencies: dependency_graph,
    };

    let json = serde_json::to_string_pretty(&bom).map_err(|source| ScanError::Io {
        path: PathBuf::from("sbom.cdx.json"),
        source: std::io::Error::other(format!("failed to serialize CycloneDX BOM: {source}")),
    })?;

    Ok(SbomDocument {
        target,
        path: display_path,
        component_count: dependencies.len(),
        json,
    })
}

pub async fn scan_path(path: &Path) -> Result<ScanResult, ScanError> {
    let dependencies = scan_dependencies(path)?;
    let resolved_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let target = resolved_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| resolved_path.display().to_string());
    let display_path = normalize_windows_verbatim_path(resolved_path.display().to_string());

    let (vulnerability_report, lookup_error) =
        match investigate_vulnerabilities(&dependencies).await {
            Ok(report) => (report, None),
            Err(error) => (
                VulnerabilityReport {
                    vulnerabilities: Vec::new(),
                    upgrade_recommendations: Vec::new(),
                    queried_dependencies: 0,
                    failed_queries: 0,
                },
                Some(error.to_string()),
            ),
        };
    let risk_summary = summarize_risk(&vulnerability_report.vulnerabilities);
    let severity_summary = SeveritySummary {
        critical: to_u32(risk_summary.counts.critical),
        high: to_u32(risk_summary.counts.high),
        medium: to_u32(risk_summary.counts.medium),
        low: to_u32(risk_summary.counts.low),
        unknown: to_u32(risk_summary.counts.unknown),
    };
    let risk_score = calculate_risk_score(&severity_summary);

    Ok(ScanResult {
        target,
        path: display_path,
        total_dependencies: to_u32(dependencies.len()),
        dependencies,
        vulnerabilities: vulnerability_report.vulnerabilities,
        upgrade_recommendations: vulnerability_report.upgrade_recommendations,
        risk_score,
        severity_summary,
        risk_level: risk_summary.risk_level,
        queried_dependencies: to_u32(vulnerability_report.queried_dependencies),
        failed_queries: to_u32(vulnerability_report.failed_queries),
        lookup_error,
    })
}

pub fn scan_result_to_sarif(scan_result: &ScanResult) -> SarifReport {
    let mut rules_by_id = BTreeMap::<String, String>::new();
    for vulnerability in &scan_result.vulnerabilities {
        rules_by_id
            .entry(vulnerability.cve_id.clone())
            .or_insert_with(|| short_message_from_description(&vulnerability.description));
    }

    let rules = rules_by_id
        .into_iter()
        .map(|(id, description)| SarifRule {
            id,
            short_description: SarifText { text: description },
        })
        .collect::<Vec<_>>();

    let artifact_uri = sarif_artifact_uri(&scan_result.path);
    let results = scan_result
        .vulnerabilities
        .iter()
        .map(|vulnerability| {
            let package_name = package_name_from_description(&vulnerability.description);
            SarifResult {
                rule_id: vulnerability.cve_id.clone(),
                level: sarif_level(vulnerability.severity).to_string(),
                message: SarifText {
                    text: vulnerability.description.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: artifact_uri.clone(),
                        },
                    },
                    logical_locations: vec![SarifLogicalLocation {
                        name: if package_name.is_empty() {
                            "dependency".to_string()
                        } else {
                            package_name
                        },
                        kind: "package".to_string(),
                    }],
                }],
            }
        })
        .collect::<Vec<_>>();

    SarifReport {
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Scanr".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/Scanr/Scanr".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

pub fn diff_cyclonedx_sbom_files(
    old_path: &Path,
    new_path: &Path,
) -> Result<SbomDiffReport, ScanError> {
    let old_dependencies = load_sbom_dependencies(old_path)?;
    let new_dependencies = load_sbom_dependencies(new_path)?;

    type FullKey = (Ecosystem, String, String);
    type PackageKey = (Ecosystem, String);

    let mut old_direct_map: HashMap<FullKey, bool> = HashMap::new();
    let mut new_direct_map: HashMap<FullKey, bool> = HashMap::new();
    for dependency in &old_dependencies {
        let key = (
            dependency.ecosystem,
            dependency.name.clone(),
            dependency.version.clone(),
        );
        old_direct_map
            .entry(key)
            .and_modify(|direct| *direct = *direct || dependency.direct)
            .or_insert(dependency.direct);
    }
    for dependency in &new_dependencies {
        let key = (
            dependency.ecosystem,
            dependency.name.clone(),
            dependency.version.clone(),
        );
        new_direct_map
            .entry(key)
            .and_modify(|direct| *direct = *direct || dependency.direct)
            .or_insert(dependency.direct);
    }

    let mut old_versions: HashMap<PackageKey, BTreeSet<String>> = HashMap::new();
    let mut new_versions: HashMap<PackageKey, BTreeSet<String>> = HashMap::new();
    for dependency in &old_dependencies {
        old_versions
            .entry((dependency.ecosystem, dependency.name.clone()))
            .or_default()
            .insert(dependency.version.clone());
    }
    for dependency in &new_dependencies {
        new_versions
            .entry((dependency.ecosystem, dependency.name.clone()))
            .or_default()
            .insert(dependency.version.clone());
    }

    let old_packages = old_versions.keys().cloned().collect::<HashSet<_>>();
    let new_packages = new_versions.keys().cloned().collect::<HashSet<_>>();
    let added_packages = new_packages
        .difference(&old_packages)
        .cloned()
        .collect::<HashSet<_>>();
    let removed_packages = old_packages
        .difference(&new_packages)
        .cloned()
        .collect::<HashSet<_>>();

    let mut added = new_direct_map
        .iter()
        .filter_map(|((ecosystem, name, version), direct)| {
            if !added_packages.contains(&(*ecosystem, name.clone())) {
                return None;
            }
            Some(Dependency {
                ecosystem: *ecosystem,
                name: name.clone(),
                version: version.clone(),
                direct: *direct,
            })
        })
        .collect::<Vec<_>>();
    let mut removed = old_direct_map
        .iter()
        .filter_map(|((ecosystem, name, version), direct)| {
            if !removed_packages.contains(&(*ecosystem, name.clone())) {
                return None;
            }
            Some(Dependency {
                ecosystem: *ecosystem,
                name: name.clone(),
                version: version.clone(),
                direct: *direct,
            })
        })
        .collect::<Vec<_>>();
    added.sort_by(|a, b| {
        (a.ecosystem, a.name.as_str(), a.version.as_str()).cmp(&(
            b.ecosystem,
            b.name.as_str(),
            b.version.as_str(),
        ))
    });
    removed.sort_by(|a, b| {
        (a.ecosystem, a.name.as_str(), a.version.as_str()).cmp(&(
            b.ecosystem,
            b.name.as_str(),
            b.version.as_str(),
        ))
    });

    let mut version_changes = Vec::new();
    for (package_key, old_set_versions) in &old_versions {
        let Some(new_set_versions) = new_versions.get(package_key) else {
            continue;
        };
        if old_set_versions != new_set_versions {
            version_changes.push(SbomVersionChange {
                ecosystem: package_key.0,
                name: package_key.1.clone(),
                old_versions: old_set_versions.iter().cloned().collect(),
                new_versions: new_set_versions.iter().cloned().collect(),
            });
        }
    }
    version_changes
        .sort_by(|a, b| (a.ecosystem, a.name.as_str()).cmp(&(b.ecosystem, b.name.as_str())));

    let mut introduced_map: HashMap<FullKey, bool> = HashMap::new();
    for dependency in &added {
        let key = (
            dependency.ecosystem,
            dependency.name.clone(),
            dependency.version.clone(),
        );
        introduced_map
            .entry(key)
            .and_modify(|direct| *direct = *direct || dependency.direct)
            .or_insert(dependency.direct);
    }
    for change in &version_changes {
        let old_set_versions = old_versions
            .get(&(change.ecosystem, change.name.clone()))
            .cloned()
            .unwrap_or_default();
        for new_version in &change.new_versions {
            if old_set_versions.contains(new_version) {
                continue;
            }
            let direct = new_direct_map
                .get(&(change.ecosystem, change.name.clone(), new_version.clone()))
                .copied()
                .unwrap_or(false);
            introduced_map
                .entry((change.ecosystem, change.name.clone(), new_version.clone()))
                .and_modify(|flag| *flag = *flag || direct)
                .or_insert(direct);
        }
    }
    let mut introduced_dependencies = introduced_map
        .into_iter()
        .map(|((ecosystem, name, version), direct)| Dependency {
            ecosystem,
            name,
            version,
            direct,
        })
        .collect::<Vec<_>>();
    introduced_dependencies.sort_by(|a, b| {
        (a.ecosystem, a.name.as_str(), a.version.as_str()).cmp(&(
            b.ecosystem,
            b.name.as_str(),
            b.version.as_str(),
        ))
    });

    Ok(SbomDiffReport {
        old_components: old_direct_map.len(),
        new_components: new_direct_map.len(),
        added_dependencies: added,
        removed_dependencies: removed,
        version_changes,
        introduced_dependencies,
    })
}

fn load_sbom_dependencies(path: &Path) -> Result<Vec<Dependency>, ScanError> {
    let contents = fs::read_to_string(path).map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed: CycloneDxBomInput =
        serde_json::from_str(&contents).map_err(|source| ScanError::Json {
            path: path.to_path_buf(),
            source,
        })?;

    let mut dependencies = Vec::new();
    for component in parsed.components {
        let Some(mut dependency) = dependency_from_component(&component) else {
            continue;
        };
        if dependency.version.trim().is_empty() {
            continue;
        }
        dependency.direct = component
            .scope
            .as_deref()
            .is_some_and(|scope| scope.eq_ignore_ascii_case("required"));
        dependencies.push(dependency);
    }

    Ok(dedupe_and_sort(dependencies))
}

fn dependency_from_component(component: &CycloneDxComponentInput) -> Option<Dependency> {
    if let Some(purl) = component.purl.as_deref()
        && let Some((ecosystem, name, version)) = parse_purl_dependency(purl)
    {
        return Some(Dependency {
            name,
            version: version.unwrap_or_else(|| component.version.clone().unwrap_or_default()),
            ecosystem,
            direct: false,
        });
    }

    None
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

pub async fn investigate_vulnerabilities(
    dependencies: &[Dependency],
) -> Result<VulnerabilityReport, ScanError> {
    if dependencies.is_empty() {
        return Ok(VulnerabilityReport {
            vulnerabilities: Vec::new(),
            upgrade_recommendations: Vec::new(),
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
    let mut recommendations = Vec::new();

    let mut tasks = stream::iter(targets.into_iter().map(|target| {
        let client = client.clone();
        async move { fetch_vulnerabilities_for_dependency(&client, target).await }
    }))
    .buffer_unordered(OSV_CONCURRENCY_LIMIT);

    while let Some(result) = tasks.next().await {
        match result {
            Ok(package_result) => {
                vulnerabilities.extend(package_result.vulnerabilities);
                if let Some(recommendation) = package_result.recommendation {
                    recommendations.push(recommendation);
                }
            }
            Err(_) => failed_queries += 1,
        }
    }

    vulnerabilities.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
    vulnerabilities.dedup_by(|a, b| {
        a.cve_id == b.cve_id
            && a.affected_version == b.affected_version
            && a.description == b.description
    });
    recommendations.sort_by(|a, b| {
        (a.ecosystem, a.package_name.as_str()).cmp(&(b.ecosystem, b.package_name.as_str()))
    });
    recommendations.dedup_by(|a, b| {
        a.ecosystem == b.ecosystem
            && a.package_name == b.package_name
            && a.current_version == b.current_version
            && a.suggested_version == b.suggested_version
    });

    Ok(VulnerabilityReport {
        vulnerabilities,
        upgrade_recommendations: recommendations,
        queried_dependencies,
        failed_queries,
    })
}

pub fn summarize_risk(vulnerabilities: &[Vulnerability]) -> RiskSummary {
    let mut counts = SeverityCounts::default();
    for vulnerability in vulnerabilities {
        match vulnerability.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Unknown => counts.unknown += 1,
        }
    }

    let risk_level = if counts.critical > 0 || counts.high > 0 {
        RiskLevel::High
    } else if counts.medium > 0 || counts.unknown > 0 {
        RiskLevel::Moderate
    } else {
        RiskLevel::Low
    };

    RiskSummary {
        total: vulnerabilities.len(),
        counts,
        risk_level,
    }
}

pub fn evaluate_policy(summary: &RiskSummary, policy: &PolicyConfig) -> PolicyEvaluation {
    let mut violations = Vec::new();

    if summary.counts.critical > policy.max_critical {
        violations.push(format!(
            "critical vulnerabilities {} exceed max_critical {}",
            summary.counts.critical, policy.max_critical
        ));
    }
    if summary.counts.high > policy.max_high {
        violations.push(format!(
            "high vulnerabilities {} exceed max_high {}",
            summary.counts.high, policy.max_high
        ));
    }

    PolicyEvaluation {
        passed: violations.is_empty(),
        violations,
    }
}

pub fn load_policy_for_target(
    target_path: &Path,
) -> Result<(PolicyConfig, Option<PathBuf>), ScanError> {
    let policy_path = resolve_policy_path(target_path);
    match fs::read_to_string(&policy_path) {
        Ok(contents) => {
            let policy =
                toml::from_str::<PolicyConfig>(&contents).map_err(|source| ScanError::Toml {
                    path: policy_path.clone(),
                    source,
                })?;
            Ok((policy, Some(policy_path)))
        }
        Err(source) if source.kind() == ErrorKind::NotFound => Ok((PolicyConfig::default(), None)),
        Err(source) => Err(ScanError::Io {
            path: policy_path,
            source,
        }),
    }
}

fn resolve_policy_path(target_path: &Path) -> PathBuf {
    if target_path.is_file() {
        return target_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("scanr.toml");
    }
    target_path.join("scanr.toml")
}

#[derive(Debug, Clone)]
struct VulnerabilityTarget {
    dependency: Dependency,
    version: Version,
}

#[derive(Debug)]
struct PackageInvestigationResult {
    vulnerabilities: Vec<Vulnerability>,
    recommendation: Option<UpgradeRecommendation>,
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
) -> Result<PackageInvestigationResult, ScanError> {
    let ecosystem = osv_ecosystem(target.dependency.ecosystem);
    let request = OsvQueryRequest {
        package: OsvPackageQuery {
            name: target.dependency.name.clone(),
            ecosystem: ecosystem.to_string(),
        },
    };

    let payload = query_osv_with_retry(client, &request).await?;

    let mut vulnerabilities = Vec::new();
    for vuln in &payload.vulns {
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

    let recommendation = recommend_safe_upgrade(client, &target, &payload.vulns, &vulnerabilities)
        .await
        .unwrap_or(None);

    Ok(PackageInvestigationResult {
        vulnerabilities,
        recommendation,
    })
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

async fn recommend_safe_upgrade(
    client: &reqwest::Client,
    target: &VulnerabilityTarget,
    package_vulns: &[OsvVulnerability],
    current_vulnerabilities: &[Vulnerability],
) -> Result<Option<UpgradeRecommendation>, ScanError> {
    if current_vulnerabilities.is_empty() {
        return Ok(None);
    }

    let registry_versions =
        fetch_registry_versions(client, target.dependency.ecosystem, &target.dependency.name)
            .await?;

    let mut candidates = registry_versions
        .into_iter()
        .filter_map(|raw| parse_semverish(&raw).map(|parsed| (raw, parsed)))
        .collect::<Vec<_>>();
    candidates.sort_by(|(_, left), (_, right)| left.cmp(right));

    let suggested = candidates.into_iter().find(|(_raw, parsed)| {
        parsed >= &target.version
            && !version_is_vulnerable_for_dependency(
                package_vulns,
                &target.dependency,
                parsed,
                &target.dependency.version,
            )
    });

    let fallback = current_vulnerabilities
        .iter()
        .flat_map(|vulnerability| {
            extract_fixed_versions_from_remediation(vulnerability.remediation.as_deref())
        })
        .filter_map(|raw| parse_semverish(&raw).map(|parsed| (raw, parsed)))
        .min_by(|(_, left), (_, right)| left.cmp(right));

    let (suggested_raw, suggested_parsed) = if let Some(found) = suggested {
        found
    } else if let Some(found) = fallback {
        found
    } else {
        return Ok(None);
    };

    Ok(Some(UpgradeRecommendation {
        package_name: target.dependency.name.clone(),
        ecosystem: target.dependency.ecosystem,
        current_version: target.dependency.version.clone(),
        suggested_version: suggested_raw,
        major_bump: suggested_parsed.major > target.version.major,
    }))
}

async fn fetch_registry_versions(
    client: &reqwest::Client,
    ecosystem: Ecosystem,
    package_name: &str,
) -> Result<Vec<String>, ScanError> {
    match ecosystem {
        Ecosystem::Node => {
            let encoded = package_name.replace('/', "%2F");
            let url = format!("https://registry.npmjs.org/{encoded}");
            let payload = query_registry_json_with_retry(client, &url).await?;
            let versions = payload
                .get("versions")
                .and_then(JsonValue::as_object)
                .map(|entries| entries.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            Ok(versions)
        }
        Ecosystem::Python => {
            let url = format!("https://pypi.org/pypi/{package_name}/json");
            let payload = query_registry_json_with_retry(client, &url).await?;
            let versions = payload
                .get("releases")
                .and_then(JsonValue::as_object)
                .map(|entries| entries.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            Ok(versions)
        }
        Ecosystem::Rust => Ok(Vec::new()),
    }
}

async fn query_registry_json_with_retry(
    client: &reqwest::Client,
    url: &str,
) -> Result<JsonValue, ScanError> {
    for attempt in 0..=OSV_MAX_RETRIES {
        let result = client.get(url).send().await;
        match result {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return response.json().await.map_err(ScanError::from);
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
        path: PathBuf::from("registry query"),
        source: std::io::Error::other("registry query retry loop exhausted"),
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

fn version_is_vulnerable_for_dependency(
    vulnerabilities: &[OsvVulnerability],
    dependency: &Dependency,
    candidate_version: &Version,
    candidate_raw: &str,
) -> bool {
    vulnerabilities.iter().any(|vulnerability| {
        vulnerability.affected.iter().any(|affected| {
            if let Some(package) = &affected.package {
                if !package.name.is_empty() && !package.name.eq_ignore_ascii_case(&dependency.name)
                {
                    return false;
                }
                if !package.ecosystem.is_empty()
                    && !package
                        .ecosystem
                        .eq_ignore_ascii_case(osv_ecosystem(dependency.ecosystem))
                {
                    return false;
                }
            }
            affected_versions_match(affected, candidate_version, candidate_raw)
        })
    })
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

fn extract_fixed_versions_from_remediation(remediation: Option<&str>) -> Vec<String> {
    let Some(remediation) = remediation else {
        return Vec::new();
    };
    let Some((_, tail)) = remediation.split_once("one of:") else {
        return Vec::new();
    };

    tail.trim()
        .trim_end_matches(')')
        .trim_end_matches('.')
        .split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn package_url(dependency: &Dependency) -> String {
    let ecosystem = match dependency.ecosystem {
        Ecosystem::Node => "npm",
        Ecosystem::Python => "pypi",
        Ecosystem::Rust => "cargo",
    };
    let name = encode_purl_name(&dependency.name);
    let version = encode_purl_segment(&dependency.version);
    format!("pkg:{ecosystem}/{name}@{version}")
}

fn encode_purl_name(raw: &str) -> String {
    raw.replace('@', "%40").replace(' ', "%20")
}

fn encode_purl_segment(raw: &str) -> String {
    raw.replace(' ', "%20")
}

fn parse_purl_dependency(purl: &str) -> Option<(Ecosystem, String, Option<String>)> {
    let raw = purl.strip_prefix("pkg:")?;
    let (package_type, remainder) = raw.split_once('/')?;
    let ecosystem = match package_type.to_ascii_lowercase().as_str() {
        "npm" => Ecosystem::Node,
        "pypi" => Ecosystem::Python,
        "cargo" | "crates.io" => Ecosystem::Rust,
        _ => return None,
    };

    let remainder = remainder
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(remainder);
    let remainder = remainder
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(remainder);
    let (name_part, version_part) = remainder
        .split_once('@')
        .map_or((remainder, None), |(name, version)| (name, Some(version)));

    let decoded_name = decode_purl_segment(name_part);
    if decoded_name.trim().is_empty() {
        return None;
    }

    let decoded_version = version_part
        .map(decode_purl_segment)
        .filter(|version| !version.trim().is_empty());
    Some((ecosystem, decoded_name, decoded_version))
}

fn decode_purl_segment(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Some(value) = decode_hex_pair(bytes[index + 1], bytes[index + 2])
        {
            output.push(value);
            index += 3;
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }

    String::from_utf8(output).unwrap_or_else(|_| raw.to_string())
}

fn decode_hex_pair(high: u8, low: u8) -> Option<u8> {
    fn decode_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let high = decode_nibble(high)?;
    let low = decode_nibble(low)?;
    Some((high << 4) | low)
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn calculate_risk_score(summary: &SeveritySummary) -> u32 {
    summary
        .critical
        .saturating_mul(100)
        .saturating_add(summary.high.saturating_mul(40))
        .saturating_add(summary.medium.saturating_mul(10))
        .saturating_add(summary.low)
        .saturating_add(summary.unknown.saturating_mul(5))
}

fn short_message_from_description(description: &str) -> String {
    description
        .split_once(':')
        .map(|(_, message)| message.trim().to_string())
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| description.to_string())
}

fn package_name_from_description(description: &str) -> String {
    description
        .split_once(':')
        .map(|(name, _)| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_default()
}

fn sarif_artifact_uri(path: &str) -> String {
    path.replace('\\', "/")
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Unknown => "note",
    }
}

fn sanitize_ref(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn deterministic_uuid(target: &str, path: &str, dependency_count: usize) -> String {
    let mut first_hasher = DefaultHasher::new();
    target.hash(&mut first_hasher);
    path.hash(&mut first_hasher);
    dependency_count.hash(&mut first_hasher);
    let first = first_hasher.finish();

    let mut second_hasher = DefaultHasher::new();
    "scanr-cyclonedx".hash(&mut second_hasher);
    target.hash(&mut second_hasher);
    dependency_count.hash(&mut second_hasher);
    let second = second_hasher.finish();

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&first.to_be_bytes());
    bytes[8..].copy_from_slice(&second.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
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

    #[test]
    fn summarizes_risk_levels() {
        let vulnerabilities = vec![
            Vulnerability {
                cve_id: "CVE-1".to_string(),
                severity: Severity::Low,
                score: None,
                affected_version: "1.0.0".to_string(),
                description: "a".to_string(),
                references: vec![],
                remediation: None,
            },
            Vulnerability {
                cve_id: "CVE-2".to_string(),
                severity: Severity::High,
                score: None,
                affected_version: "1.0.0".to_string(),
                description: "b".to_string(),
                references: vec![],
                remediation: None,
            },
        ];

        let summary = summarize_risk(&vulnerabilities);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.counts.high, 1);
        assert_eq!(summary.counts.low, 1);
        assert_eq!(summary.risk_level, RiskLevel::High);
    }

    #[test]
    fn policy_evaluation_flags_violations() {
        let summary = RiskSummary {
            total: 3,
            counts: SeverityCounts {
                critical: 1,
                high: 2,
                medium: 0,
                low: 0,
                unknown: 0,
            },
            risk_level: RiskLevel::High,
        };
        let policy = PolicyConfig {
            max_critical: 0,
            max_high: 1,
        };

        let evaluation = evaluate_policy(&summary, &policy);
        assert!(!evaluation.passed);
        assert_eq!(evaluation.violations.len(), 2);
    }

    #[test]
    fn generates_cyclonedx_sbom_json() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("valid time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("scanr-sbom-{unique}"));
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"lodash":"4.17.21"}}"#,
        )
        .expect("write package.json");

        let sbom = generate_cyclonedx_sbom(&root).expect("SBOM should generate");
        let json: serde_json::Value = serde_json::from_str(&sbom.json).expect("valid JSON");

        assert_eq!(
            json.get("bomFormat").and_then(serde_json::Value::as_str),
            Some("CycloneDX")
        );
        assert_eq!(
            json.get("specVersion").and_then(serde_json::Value::as_str),
            Some("1.5")
        );
        assert!(
            json.get("components")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|components| !components.is_empty())
        );
        assert!(
            json.get("dependencies")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|dependencies| !dependencies.is_empty())
        );
    }

    #[test]
    fn sbom_diff_detects_added_removed_and_version_changes() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("valid time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("scanr-sbom-diff-{unique}"));
        std::fs::create_dir_all(&root).expect("create temp root");

        let old_sbom = root.join("old.cdx.json");
        let new_sbom = root.join("new.cdx.json");

        std::fs::write(
            &old_sbom,
            r#"{
  "bomFormat":"CycloneDX",
  "specVersion":"1.5",
  "version":1,
  "components":[
    {"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20","scope":"required"},
    {"type":"library","name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0","scope":"required"}
  ]
}"#,
        )
        .expect("write old sbom");

        std::fs::write(
            &new_sbom,
            r#"{
  "bomFormat":"CycloneDX",
  "specVersion":"1.5",
  "version":1,
  "components":[
    {"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21","scope":"required"},
    {"type":"library","name":"axios","version":"1.2.0","purl":"pkg:npm/axios@1.2.0","scope":"required"}
  ]
}"#,
        )
        .expect("write new sbom");

        let diff = diff_cyclonedx_sbom_files(&old_sbom, &new_sbom).expect("diff should parse");

        assert!(
            diff.added_dependencies
                .iter()
                .any(|dependency| dependency.name == "axios" && dependency.version == "1.2.0")
        );
        assert!(
            diff.removed_dependencies
                .iter()
                .any(|dependency| dependency.name == "requests" && dependency.version == "2.31.0")
        );
        assert!(diff.version_changes.iter().any(|change| {
            change.name == "lodash"
                && change.old_versions == vec!["4.17.20".to_string()]
                && change.new_versions == vec!["4.17.21".to_string()]
        }));
        assert!(
            diff.introduced_dependencies
                .iter()
                .any(|dependency| dependency.name == "lodash" && dependency.version == "4.17.21")
        );
        assert!(
            diff.introduced_dependencies
                .iter()
                .any(|dependency| dependency.name == "axios" && dependency.version == "1.2.0")
        );
    }

    #[test]
    fn sarif_output_maps_severity_levels() {
        let scan_result = ScanResult {
            target: "demo".to_string(),
            path: "F:\\demo".to_string(),
            total_dependencies: 2,
            dependencies: vec![],
            vulnerabilities: vec![
                Vulnerability {
                    cve_id: "CVE-2026-0001".to_string(),
                    severity: Severity::High,
                    score: None,
                    affected_version: "1.0.0".to_string(),
                    description: "lodash: high issue".to_string(),
                    references: vec![],
                    remediation: None,
                },
                Vulnerability {
                    cve_id: "CVE-2026-0002".to_string(),
                    severity: Severity::Low,
                    score: None,
                    affected_version: "2.0.0".to_string(),
                    description: "axios: low issue".to_string(),
                    references: vec![],
                    remediation: None,
                },
            ],
            upgrade_recommendations: vec![],
            risk_score: 41,
            severity_summary: SeveritySummary {
                critical: 0,
                high: 1,
                medium: 0,
                low: 1,
                unknown: 0,
            },
            risk_level: RiskLevel::High,
            queried_dependencies: 2,
            failed_queries: 0,
            lookup_error: None,
        };

        let sarif = scan_result_to_sarif(&scan_result);
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.name, "Scanr");
        assert_eq!(sarif.runs[0].results.len(), 2);
        assert_eq!(sarif.runs[0].results[0].level, "error");
        assert_eq!(sarif.runs[0].results[1].level, "note");
    }
}
