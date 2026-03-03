use std::collections::HashSet;

use super::node_graph::NodeGraph;

pub const TRACE_MAX_DEPTH: usize = 50;
pub const TRACE_MAX_PATHS: usize = 20;

pub fn find_paths_to_target(
    graph: &NodeGraph,
    target_node: &str,
    max_depth: usize,
    max_paths: usize,
) -> (Vec<Vec<String>>, bool) {
    let mut results = Vec::new();
    let mut truncated = false;

    for root in &graph.root_dependencies {
        let mut path = Vec::new();
        let mut visited = HashSet::new();
        dfs(
            graph,
            root,
            target_node,
            max_depth,
            max_paths,
            &mut path,
            &mut visited,
            &mut results,
            &mut truncated,
        );
        if results.len() >= max_paths {
            truncated = true;
            break;
        }
    }

    (results, truncated)
}

#[allow(clippy::too_many_arguments)]
fn dfs(
    graph: &NodeGraph,
    current: &str,
    target: &str,
    max_depth: usize,
    max_paths: usize,
    path: &mut Vec<String>,
    visited: &mut HashSet<String>,
    results: &mut Vec<Vec<String>>,
    truncated: &mut bool,
) {
    if path.len() >= max_depth {
        *truncated = true;
        return;
    }
    if results.len() >= max_paths {
        *truncated = true;
        return;
    }
    if !visited.insert(current.to_string()) {
        return;
    }

    path.push(current.to_string());
    if current == target {
        results.push(path.clone());
        path.pop();
        visited.remove(current);
        return;
    }

    if let Some(children) = graph.edges.get(current) {
        for child in children {
            dfs(
                graph, child, target, max_depth, max_paths, path, visited, results, truncated,
            );
            if results.len() >= max_paths {
                *truncated = true;
                break;
            }
        }
    }

    path.pop();
    visited.remove(current);
}
