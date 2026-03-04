use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineType {
    SCA,
    Container,
    IaC,
    SAST,
    Secrets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub engine: EngineType,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: Option<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanInput {
    Path(PathBuf),
    Image(String),
    Tar(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub engine: EngineType,
    pub engine_name: String,
    pub target: String,
    pub total_dependencies: usize,
    pub total_vulnerabilities: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub metadata: ScanMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSummary {
    pub total: usize,
    pub counts: SeverityCounts,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnerabilityPolicy {
    pub max_critical: usize,
    pub max_high: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub passed: bool,
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
    pub message: String,
}

impl EngineError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for EngineError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for EngineError {}

pub type EngineResult<T> = std::result::Result<T, EngineError>;

pub trait ScanEngine {
    fn name(&self) -> &'static str;

    fn scan(&self, input: ScanInput) -> EngineResult<ScanResult>;
}

pub fn summarize_findings(findings: &[Finding]) -> FindingSummary {
    let mut counts = SeverityCounts::default();
    for finding in findings {
        match finding.severity {
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

    FindingSummary {
        total: findings.len(),
        counts,
        risk_level,
    }
}

pub fn evaluate_vulnerability_policy(
    findings: &[Finding],
    policy: &VulnerabilityPolicy,
) -> PolicyEvaluation {
    let summary = summarize_findings(findings);
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

pub fn resolve_exit_code(vulnerability_failed: bool, license_failed: bool) -> i32 {
    match (vulnerability_failed, license_failed) {
        (false, false) => 0,
        (true, false) => 2,
        (false, true) => 3,
        (true, true) => 4,
    }
}
