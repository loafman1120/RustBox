//! Cross-subsystem dependency validation for runtime services.

use crate::ComposeError;
use rustbox_config::{CompiledConfig, ConfigError};
use rustbox_types::OutboundId;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Node {
    Outbound(OutboundId),
    Dns(String),
}

pub(super) fn validate_runtime_dependencies(config: &CompiledConfig) -> Result<(), ComposeError> {
    let mut graph: HashMap<Node, Vec<Node>> = HashMap::new();
    for outbound in &config.outbounds {
        let node = Node::Outbound(outbound.id);
        graph.entry(node.clone()).or_default();
        if let Some(detour) = outbound.dial.detour {
            graph
                .entry(node.clone())
                .or_default()
                .push(Node::Outbound(detour));
        }
        if let Some(server) = &outbound.dial.domain_resolver {
            graph
                .entry(node)
                .or_default()
                .push(Node::Dns(server.clone()));
        }
    }
    if let Some(dns) = &config.dns {
        for server in &dns.servers {
            let node = Node::Dns(server.id.clone());
            graph.entry(node.clone()).or_default();
            if let Some(outbound) = server.outbound {
                graph
                    .entry(node)
                    .or_default()
                    .push(Node::Outbound(outbound));
            }
        }
    }
    validate_graph(&graph)
}

fn validate_graph(graph: &HashMap<Node, Vec<Node>>) -> Result<(), ComposeError> {
    let mut visited = HashSet::new();
    let mut active = Vec::new();
    for node in graph.keys() {
        visit(node, graph, &mut visited, &mut active)?;
    }
    Ok(())
}

fn visit(
    node: &Node,
    graph: &HashMap<Node, Vec<Node>>,
    visited: &mut HashSet<Node>,
    active: &mut Vec<Node>,
) -> Result<(), ComposeError> {
    if let Some(index) = active.iter().position(|item| item == node) {
        let mut cycle = active[index..].iter().map(label).collect::<Vec<_>>();
        cycle.push(label(node));
        return Err(ComposeError::Config(ConfigError::new(format!(
            "circular DNS/outbound dependency: {}",
            cycle.join(" -> ")
        ))));
    }
    if !visited.insert(node.clone()) {
        return Ok(());
    }
    active.push(node.clone());
    for dependency in graph.get(node).into_iter().flatten() {
        visit(dependency, graph, visited, active)?;
    }
    active.pop();
    Ok(())
}

fn label(node: &Node) -> String {
    match node {
        Node::Outbound(id) => format!("outbound[{id}]"),
        Node::Dns(id) => format!("dns[{id}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    #[test]
    fn rejects_cross_dns_outbound_cycle() {
        let outbound = Node::Outbound(OutboundId::new(NonZeroU64::new(7).expect("id")));
        let dns = Node::Dns("bootstrap".into());
        let graph = HashMap::from([(outbound.clone(), vec![dns.clone()]), (dns, vec![outbound])]);
        let error = validate_graph(&graph).expect_err("cycle");
        assert!(
            matches!(error, ComposeError::Config(error) if error.message.contains("circular DNS/outbound dependency"))
        );
    }
}
