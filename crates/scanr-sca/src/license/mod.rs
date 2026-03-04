use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Dependency;

mod evaluator;
mod extractor;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LicensePolicy {
    pub enabled: bool,
    pub block: Vec<String>,
    pub allow_only: Vec<String>,
    pub fail_on_unknown: bool,
    pub enforce_in_ci: bool,
}

impl Default for LicensePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            block: Vec::new(),
            allow_only: Vec::new(),
            fail_on_unknown: false,
            enforce_in_ci: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LicenseInfo {
    pub package: String,
    pub version: String,
    pub license: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LicenseViolation {
    pub package: String,
    pub version: String,
    pub license: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LicenseEvaluationResult {
    pub violations: Vec<LicenseViolation>,
    pub summary: BTreeMap<String, usize>,
}

pub use evaluator::evaluate_licenses;
pub use extractor::extract_licenses_for_dependencies;

pub fn extract_licenses(target_path: &Path, dependencies: &[Dependency]) -> Vec<LicenseInfo> {
    extract_licenses_for_dependencies(target_path, dependencies)
}
