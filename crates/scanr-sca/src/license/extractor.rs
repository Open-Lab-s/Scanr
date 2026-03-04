use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value as JsonValue};

use super::LicenseInfo;
use crate::{Dependency, Ecosystem};

pub fn extract_licenses_for_dependencies(
    target_path: &Path,
    dependencies: &[Dependency],
) -> Vec<LicenseInfo> {
    if dependencies.is_empty() {
        return Vec::new();
    }

    let scan_root = resolve_scan_root(target_path);
    let node_license_map = load_node_lock_licenses(&scan_root);
    let mut node_modules_cache: HashMap<String, Option<String>> = HashMap::new();

    dependencies
        .iter()
        .map(|dependency| {
            let license = match dependency.ecosystem {
                Ecosystem::Node => node_license_map
                    .get(&(dependency.name.clone(), dependency.version.clone()))
                    .cloned()
                    .or_else(|| {
                        if let Some(cached) = node_modules_cache.get(&dependency.name) {
                            return cached.clone();
                        }
                        let resolved =
                            read_license_from_installed_node_module(&scan_root, &dependency.name);
                        node_modules_cache.insert(dependency.name.clone(), resolved.clone());
                        resolved
                    })
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
                Ecosystem::Python
                | Ecosystem::Rust
                | Ecosystem::Alpine
                | Ecosystem::Debian
                | Ecosystem::Ubuntu
                | Ecosystem::Rhel => "UNKNOWN".to_string(),
            };

            LicenseInfo {
                package: dependency.name.clone(),
                version: dependency.version.clone(),
                license,
            }
        })
        .collect()
}

fn resolve_scan_root(target_path: &Path) -> PathBuf {
    if target_path.is_file() {
        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
        return fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    }
    fs::canonicalize(target_path).unwrap_or_else(|_| target_path.to_path_buf())
}

fn load_node_lock_licenses(scan_root: &Path) -> HashMap<(String, String), String> {
    let lock_path = scan_root.join("package-lock.json");
    let Ok(contents) = fs::read_to_string(lock_path) else {
        return HashMap::new();
    };
    let Ok(json) = serde_json::from_str::<JsonValue>(&contents) else {
        return HashMap::new();
    };

    let mut map = HashMap::new();

    if let Some(packages) = json.get("packages").and_then(JsonValue::as_object) {
        for (package_path, metadata) in packages {
            if package_path.is_empty() {
                continue;
            }
            let Some(version) = metadata.get("version").and_then(JsonValue::as_str) else {
                continue;
            };
            let Some(license) = extract_license_value(metadata) else {
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
            map.entry((name, version.to_string())).or_insert(license);
        }
    }

    if let Some(v1_dependencies) = json.get("dependencies").and_then(JsonValue::as_object) {
        collect_v1_dependency_licenses(v1_dependencies, &mut map);
    }

    map
}

fn collect_v1_dependency_licenses(
    dependencies: &Map<String, JsonValue>,
    out: &mut HashMap<(String, String), String>,
) {
    for (name, metadata) in dependencies {
        let Some(version) = metadata.get("version").and_then(JsonValue::as_str) else {
            continue;
        };

        if let Some(license) = extract_license_value(metadata) {
            out.entry((name.clone(), version.to_string()))
                .or_insert(license);
        }

        if let Some(children) = metadata.get("dependencies").and_then(JsonValue::as_object) {
            collect_v1_dependency_licenses(children, out);
        }
    }
}

fn infer_name_from_package_path(package_path: &str) -> String {
    if let Some((_, tail)) = package_path.rsplit_once("node_modules/") {
        return tail.to_string();
    }
    package_path.to_string()
}

fn read_license_from_installed_node_module(scan_root: &Path, package_name: &str) -> Option<String> {
    let mut package_path = scan_root.join("node_modules");
    for segment in package_name.split('/') {
        package_path.push(segment);
    }
    package_path.push("package.json");

    let contents = fs::read_to_string(package_path).ok()?;
    let json = serde_json::from_str::<JsonValue>(&contents).ok()?;
    extract_license_value(&json)
}

fn extract_license_value(metadata: &JsonValue) -> Option<String> {
    metadata
        .get("license")
        .and_then(parse_license_value)
        .or_else(|| metadata.get("licenses").and_then(parse_license_value))
}

fn parse_license_value(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(raw) => normalize_license(raw),
        JsonValue::Object(object) => object
            .get("type")
            .and_then(JsonValue::as_str)
            .and_then(normalize_license),
        JsonValue::Array(items) => {
            let values = items
                .iter()
                .filter_map(parse_license_value)
                .collect::<Vec<_>>();
            if values.is_empty() {
                None
            } else {
                Some(values.join(" OR "))
            }
        }
        _ => None,
    }
}

fn normalize_license(raw: &str) -> Option<String> {
    let normalized = raw.trim();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}
