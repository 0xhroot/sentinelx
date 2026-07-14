use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EdgeType {
    Spawned,
    Opened,
    Connected,
    Loaded,
    Modified,
    Created,
    Deleted,
    Executes,
    Owns,
    Inherits,
}

impl EdgeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Spawned => "spawned",
            Self::Opened => "opened",
            Self::Connected => "connected",
            Self::Loaded => "loaded",
            Self::Modified => "modified",
            Self::Created => "created",
            Self::Deleted => "deleted",
            Self::Executes => "executes",
            Self::Owns => "owns",
            Self::Inherits => "inherits",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub properties: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub edge_type: EdgeType,
    pub properties: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPath {
    pub nodes: Vec<String>,
    pub edges: Vec<(String, EdgeType, String)>,
}

pub struct InMemoryGraph {
    nodes: HashMap<String, GraphNode>,
    edges: Vec<GraphEdge>,
    adjacency: HashMap<String, Vec<usize>>,
    reverse_adjacency: HashMap<String, Vec<usize>>,
}

impl InMemoryGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            adjacency: HashMap::new(),
            reverse_adjacency: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) {
        let id = node.id.clone();
        self.nodes.insert(id, node);
    }

    pub fn add_edge(&mut self, edge: GraphEdge) {
        let idx = self.edges.len();
        self.adjacency
            .entry(edge.source.clone())
            .or_default()
            .push(idx);
        self.reverse_adjacency
            .entry(edge.target.clone())
            .or_default()
            .push(idx);
        self.edges.push(edge);
    }

    pub fn connect(&mut self, source_id: &str, target_id: &str, edge_type: EdgeType) {
        self.add_edge(GraphEdge {
            source: source_id.to_string(),
            target: target_id.to_string(),
            edge_type,
            properties: HashMap::new(),
        });
    }

    pub fn get_node(&self, id: &str) -> Option<&GraphNode> {
        self.nodes.get(id)
    }

    pub fn get_edges_from(&self, id: &str) -> Vec<&GraphEdge> {
        self.adjacency
            .get(id)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    pub fn get_edges_to(&self, id: &str) -> Vec<&GraphEdge> {
        self.reverse_adjacency
            .get(id)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    pub fn get_neighbors(&self, id: &str) -> Vec<&GraphNode> {
        let mut neighbors = Vec::new();
        if let Some(indices) = self.adjacency.get(id) {
            for &i in indices {
                if let Some(node) = self.nodes.get(&self.edges[i].target) {
                    neighbors.push(node);
                }
            }
        }
        neighbors
    }

    pub fn find_paths(&self, start: &str, end: &str, max_depth: usize) -> Vec<GraphPath> {
        type StackEntry = (String, Vec<String>, Vec<(String, EdgeType, String)>);
        let mut paths = Vec::new();
        let mut stack: Vec<StackEntry> = Vec::new();
        stack.push((start.to_string(), vec![], vec![]));

        while let Some((current, path_nodes, path_edges)) = stack.pop() {
            if current == end {
                let mut nodes = path_nodes;
                nodes.push(current.clone());
                paths.push(GraphPath {
                    nodes,
                    edges: path_edges,
                });
                continue;
            }

            if path_nodes.len() >= max_depth {
                continue;
            }

            if path_nodes.contains(&current) {
                continue;
            }

            let mut nodes = path_nodes;
            nodes.push(current.clone());

            if let Some(indices) = self.adjacency.get(&current) {
                for &i in indices {
                    let target = &self.edges[i].target;
                    if !nodes.contains(target) {
                        let mut edges = path_edges.clone();
                        edges.push((
                            current.clone(),
                            self.edges[i].edge_type.clone(),
                            target.clone(),
                        ));
                        stack.push((target.clone(), nodes.clone(), edges));
                    }
                }
            }
        }

        paths
    }

    pub fn find_cycles(&self, max_length: usize) -> Vec<GraphPath> {
        let mut cycles = Vec::new();
        for node_id in self.nodes.keys() {
            let paths = self.find_paths(node_id, node_id, max_length);
            for mut path in paths {
                if path.nodes.len() > 2 {
                    path.nodes.dedup();
                    cycles.push(path);
                }
            }
        }
        cycles
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn nodes(&self) -> &HashMap<String, GraphNode> {
        &self.nodes
    }

    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }

    pub fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
        self.adjacency.clear();
        self.reverse_adjacency.clear();
    }
}

impl Default for InMemoryGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, label: &str, node_type: &str) -> GraphNode {
        GraphNode {
            id: id.to_string(),
            label: label.to_string(),
            node_type: node_type.to_string(),
            properties: HashMap::new(),
        }
    }

    #[test]
    fn test_add_node_and_edge() {
        let mut graph = InMemoryGraph::new();
        graph.add_node(make_node("p1", "Process 1", "process"));
        graph.add_node(make_node("f1", "File 1", "file"));
        graph.connect("p1", "f1", EdgeType::Modified);
        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_get_neighbors() {
        let mut graph = InMemoryGraph::new();
        graph.add_node(make_node("p1", "Process", "process"));
        graph.add_node(make_node("f1", "File", "file"));
        graph.add_node(make_node("m1", "Module", "module"));
        graph.connect("p1", "f1", EdgeType::Modified);
        graph.connect("p1", "m1", EdgeType::Loaded);
        let neighbors = graph.get_neighbors("p1");
        assert_eq!(neighbors.len(), 2);
    }

    #[test]
    fn test_find_paths() {
        let mut graph = InMemoryGraph::new();
        graph.add_node(make_node("p1", "Process", "process"));
        graph.add_node(make_node("f1", "File", "file"));
        graph.add_node(make_node("m1", "Module", "module"));
        graph.connect("p1", "f1", EdgeType::Modified);
        graph.connect("f1", "m1", EdgeType::Loaded);
        let paths = graph.find_paths("p1", "m1", 5);
        assert!(!paths.is_empty());
        assert_eq!(paths[0].nodes.len(), 3);
    }

    #[test]
    fn test_find_paths_max_depth() {
        let mut graph = InMemoryGraph::new();
        graph.add_node(make_node("p1", "A", "process"));
        graph.add_node(make_node("p2", "B", "process"));
        graph.add_node(make_node("p3", "C", "process"));
        graph.connect("p1", "p2", EdgeType::Spawned);
        graph.connect("p2", "p3", EdgeType::Spawned);
        let paths = graph.find_paths("p1", "p3", 1);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_get_edges_from_and_to() {
        let mut graph = InMemoryGraph::new();
        graph.add_node(make_node("p1", "Process", "process"));
        graph.add_node(make_node("f1", "File", "file"));
        graph.connect("p1", "f1", EdgeType::Modified);
        let from = graph.get_edges_from("p1");
        assert_eq!(from.len(), 1);
        let to = graph.get_edges_to("f1");
        assert_eq!(to.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut graph = InMemoryGraph::new();
        graph.add_node(make_node("p1", "Process", "process"));
        graph.connect("p1", "p1", EdgeType::Modified);
        graph.clear();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }
}
