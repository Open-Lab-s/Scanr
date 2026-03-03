use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value as JsonValue};

use crate::ScanError;

#[derive(Debug, Clone)]
pub struct NodeGraph {
    pub edges: HashMap<String, Vec<String>>,
    pub root_dependencies: Vec<String>,
}

impl NodeGraph {
    pub fn all_nodes(&self) -> Vec<String> {
        let mut nodes = BTreeSet::new();
        nodes.extend(self.edges.keys().cloned());
        for children in self.edges.values() {
            nodes.extend(children.iter().cloned());
        }
        nodes.into_iter().collect()
    }
}

pub fn build_node_graph(project_path: &Path) -> Result<NodeGraph, ScanError> {
    let lockfile_path = resolve_lockfile_path(project_path);
    let contents = std::fs::read_to_string(&lockfile_path).map_err(|source| ScanError::Io {
        path: lockfile_path.clone(),
        source,
    })?;
    let json: JsonValue = serde_json::from_str(&contents).map_err(|source| ScanError::Json {
        path: lockfile_path.clone(),
        source,
    })?;

    if let Some(packages) = json.get("packages").and_then(JsonValue::as_object) {
        return Ok(build_from_packages_map(packages));
    }

    if let Some(legacy_dependencies) = json.get("dependencies").and_then(JsonValue::as_object) {
        return Ok(build_from_legacy_dependencies(legacy_dependencies));
    }

    Ok(NodeGraph {
        edges: HashMap::new(),
        root_dependencies: Vec::new(),
    })
}

fn resolve_lockfile_path(target_path: &Path) -> PathBuf {
    if target_path.is_file() {
        return target_path.to_path_buf();
    }
    target_path.join("package-lock.json")
}

fn build_from_packages_map(packages: &Map<String, JsonValue>) -> NodeGraph {
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    let mut path_to_node: HashMap<String, String> = HashMap::new();

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

        let node_key = node_key(&name, version);
        path_to_node.insert(package_path.clone(), node_key.clone());
        edges.entry(node_key).or_default();
    }

    for (package_path, metadata) in packages {
        if package_path.is_empty() {
            continue;
        }
        let Some(parent_key) = path_to_node.get(package_path) else {
            continue;
        };
        let Some(children) = metadata.get("dependencies").and_then(JsonValue::as_object) else {
            continue;
        };

        let mut child_keys = Vec::new();
        for child_name in children.keys() {
            if let Some(child_key) = resolve_child_key(package_path, child_name, &path_to_node) {
                child_keys.push(child_key);
            }
        }
        child_keys.sort();
        child_keys.dedup();
        edges.insert(parent_key.clone(), child_keys);
    }

    let mut root_dependencies = Vec::new();
    if let Some(root_dependencies_map) = packages
        .get("")
        .and_then(|root| root.get("dependencies"))
        .and_then(JsonValue::as_object)
    {
        for dependency_name in root_dependencies_map.keys() {
            if let Some(child_key) = resolve_child_key("", dependency_name, &path_to_node) {
                root_dependencies.push(child_key);
            }
        }
    }
    root_dependencies.sort();
    root_dependencies.dedup();

    NodeGraph {
        edges,
        root_dependencies,
    }
}

fn build_from_legacy_dependencies(dependencies: &Map<String, JsonValue>) -> NodeGraph {
    let mut graph = NodeGraph {
        edges: HashMap::new(),
        root_dependencies: Vec::new(),
    };

    for (name, metadata) in dependencies {
        walk_legacy(name, metadata, None, &mut graph);
    }

    for children in graph.edges.values_mut() {
        children.sort();
        children.dedup();
    }
    graph.root_dependencies.sort();
    graph.root_dependencies.dedup();
    graph
}

fn walk_legacy(name: &str, metadata: &JsonValue, parent: Option<&str>, graph: &mut NodeGraph) {
    let Some(version) = metadata.get("version").and_then(JsonValue::as_str) else {
        return;
    };
    let key = node_key(name, version);
    graph.edges.entry(key.clone()).or_default();

    match parent {
        Some(parent_key) => {
            graph
                .edges
                .entry(parent_key.to_string())
                .or_default()
                .push(key.clone());
        }
        None => graph.root_dependencies.push(key.clone()),
    }

    if let Some(children) = metadata.get("dependencies").and_then(JsonValue::as_object) {
        for (child_name, child_metadata) in children {
            walk_legacy(child_name, child_metadata, Some(&key), graph);
        }
    }
}

fn resolve_child_key(
    parent_path: &str,
    dependency_name: &str,
    path_to_node: &HashMap<String, String>,
) -> Option<String> {
    for candidate in candidate_dependency_paths(parent_path, dependency_name) {
        if let Some(key) = path_to_node.get(&candidate) {
            return Some(key.clone());
        }
    }

    let mut fallback = path_to_node
        .iter()
        .filter_map(|(path, key)| {
            if infer_name_from_package_path(path) == dependency_name {
                Some(key.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    fallback.sort();
    fallback.dedup();
    if fallback.len() == 1 {
        return fallback.into_iter().next();
    }
    None
}

fn candidate_dependency_paths(parent_path: &str, dependency_name: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut current = parent_path.to_string();

    loop {
        let candidate = if current.is_empty() {
            format!("node_modules/{dependency_name}")
        } else {
            format!("{current}/node_modules/{dependency_name}")
        };
        candidates.push(candidate);

        if current.is_empty() {
            break;
        }

        if let Some(index) = current.rfind("/node_modules/") {
            current.truncate(index);
        } else {
            current.clear();
        }
    }

    candidates
}

fn infer_name_from_package_path(package_path: &str) -> String {
    if let Some((_, tail)) = package_path.rsplit_once("node_modules/") {
        return tail.to_string();
    }
    package_path.to_string()
}

fn node_key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

pub fn split_node_key(node_key: &str) -> Option<(&str, &str)> {
    let (name, version) = node_key.rsplit_once('@')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}
