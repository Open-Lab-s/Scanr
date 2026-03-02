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

pub fn placeholder_status() -> &'static str {
    "scanr-core placeholder"
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
