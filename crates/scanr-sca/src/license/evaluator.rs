use std::collections::{BTreeMap, HashSet};

use super::{LicenseEvaluationResult, LicenseInfo, LicensePolicy, LicenseViolation};

pub fn evaluate_licenses(deps: &[LicenseInfo], policy: &LicensePolicy) -> LicenseEvaluationResult {
    let mut violations = Vec::new();
    let mut summary = BTreeMap::new();

    let blocked = normalized_set(&policy.block);
    let allow_only = normalized_set(&policy.allow_only);

    for dep in deps {
        *summary.entry(dep.license.clone()).or_insert(0) += 1;

        if !policy.enabled {
            continue;
        }

        let normalized_license = normalize_license(&dep.license);
        let tokens = license_tokens(&dep.license);

        if policy.fail_on_unknown && normalized_license == "UNKNOWN" {
            violations.push(LicenseViolation {
                package: dep.package.clone(),
                version: dep.version.clone(),
                license: dep.license.clone(),
                reason: "Unknown license".to_string(),
            });
        }

        if has_intersection(&tokens, &blocked) {
            violations.push(LicenseViolation {
                package: dep.package.clone(),
                version: dep.version.clone(),
                license: dep.license.clone(),
                reason: "License is blocked".to_string(),
            });
        }

        if !allow_only.is_empty() && !is_allow_only_match(&tokens, &allow_only) {
            violations.push(LicenseViolation {
                package: dep.package.clone(),
                version: dep.version.clone(),
                license: dep.license.clone(),
                reason: "Not in allow_only list".to_string(),
            });
        }
    }

    LicenseEvaluationResult {
        violations,
        summary,
    }
}

fn normalized_set(values: &[String]) -> HashSet<String> {
    values
        .iter()
        .map(|value| normalize_license(value))
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalize_license(raw: &str) -> String {
    let normalized = raw.trim();
    if normalized.is_empty() {
        "UNKNOWN".to_string()
    } else {
        normalized.to_ascii_uppercase()
    }
}

fn license_tokens(raw: &str) -> HashSet<String> {
    let normalized = normalize_license(raw);
    if normalized == "UNKNOWN" {
        return HashSet::from(["UNKNOWN".to_string()]);
    }

    let mut cleaned = normalized
        .replace(['(', ')', '[', ']'], " ")
        .replace(['|', '/', ',', ';'], " ");
    cleaned = cleaned.replace(" OR ", " ");
    cleaned = cleaned.replace(" AND ", " ");
    cleaned = cleaned.replace(" WITH ", " ");

    let tokens = cleaned
        .split_whitespace()
        .map(|token| token.trim_matches('+').to_string())
        .filter(|token| !token.is_empty())
        .collect::<HashSet<_>>();

    if tokens.is_empty() {
        HashSet::from([normalized])
    } else {
        tokens
    }
}

fn has_intersection(lhs: &HashSet<String>, rhs: &HashSet<String>) -> bool {
    lhs.iter().any(|item| rhs.contains(item))
}

fn is_allow_only_match(tokens: &HashSet<String>, allow_only: &HashSet<String>) -> bool {
    tokens.iter().all(|item| allow_only.contains(item))
}
