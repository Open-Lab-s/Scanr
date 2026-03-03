mod node_graph;
mod tracer;

use std::path::Path;

use node_graph::{build_node_graph, split_node_key};
use tracer::{TRACE_MAX_DEPTH, TRACE_MAX_PATHS, find_paths_to_target};

use crate::{Dependency, Ecosystem, ScanError};

#[derive(Debug, Clone)]
pub struct TraceMatch {
    pub package: String,
    pub version: String,
    pub dependency: Dependency,
    pub paths: Vec<Vec<String>>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct TraceReport {
    pub target_package: String,
    pub matches: Vec<TraceMatch>,
}

pub fn trace_dependency_paths(target_path: &Path, package_name: &str) -> Result<TraceReport, ScanError> {
    let graph = build_node_graph(target_path)?;
    let mut matching_nodes = graph
        .all_nodes()
        .into_iter()
        .filter(|node_key| {
            split_node_key(node_key)
                .map(|(name, _)| name.eq_ignore_ascii_case(package_name))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    matching_nodes.sort();
    matching_nodes.dedup();

    let mut matches = Vec::new();
    for node_key in matching_nodes {
        let Some((name, version)) = split_node_key(&node_key) else {
            continue;
        };
        let (paths, truncated) =
            find_paths_to_target(&graph, &node_key, TRACE_MAX_DEPTH, TRACE_MAX_PATHS);
        let dependency = Dependency {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: Ecosystem::Node,
            direct: graph.root_dependencies.contains(&node_key),
        };

        matches.push(TraceMatch {
            package: name.to_string(),
            version: version.to_string(),
            dependency,
            paths,
            truncated,
        });
    }

    Ok(TraceReport {
        target_package: package_name.to_string(),
        matches,
    })
}
