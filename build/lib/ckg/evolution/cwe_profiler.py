"""Aggregate learned CWE context in profile nodes, never on canonical CWE nodes."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository


@dataclass(frozen=True)
class ProfileRebuildReport:
    profile_count: int
    association_count: int


def _identity(aliases: dict[str, str], vulnerability_id: str) -> str:
    seen: set[str] = set()
    current = vulnerability_id
    while current in aliases and current not in seen:
        seen.add(current)
        current = aliases[current]
    return current


def _known_at(props: dict) -> datetime | None:
    for key in ("known_at", "retrieved_at", "published_at", "updated_at"):
        value = props.get(key)
        if not value:
            continue
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def rebuild_cwe_profiles(repository: GraphRepository) -> ProfileRebuildReport:
    all_nodes = {node.node_id: node for node in repository.nodes()}
    all_edges = repository.edges()
    edges_by_type: dict[str, list[GraphEdge]] = defaultdict(list)
    for edge in all_edges:
        edges_by_type[edge.edge_type].append(edge)
    aliases = {
        edge.subject_id: edge.object_id for edge in edges_by_type["ALIAS_OF"]
    }
    active_ids = {identifier for identifier, node in all_nodes.items() if node.props.get("stale") is not True}

    def active_mapped(vulnerability_id: str, assertion_relation: str) -> set[str]:
        assertions = {
            edge.object_id for edge in edges_by_type[assertion_relation]
            if edge.subject_id == vulnerability_id and edge.object_id in active_ids
        }
        return {
            edge.object_id for edge in edges_by_type["MAPS_TO"]
            if edge.subject_id in assertions and edge.object_id in active_ids
        }

    cwe_to_vulnerabilities: dict[str, set[str]] = defaultdict(set)
    vulnerability_techniques: dict[str, set[str]] = {}
    vulnerability_contexts: dict[str, set[str]] = {}
    vulnerability_times: dict[str, set[datetime]] = defaultdict(set)
    vulnerability_evidence: dict[str, set[str]] = defaultdict(set)
    vulnerabilities = [
        node.node_id
        for node in all_nodes.values()
        if node.label in {"CVE", "GHSA"} and node.node_id in active_ids
    ]
    for vulnerability_id in vulnerabilities:
        canonical = _identity(aliases, vulnerability_id)
        source_node = all_nodes[vulnerability_id]
        timestamp = _known_at(source_node.props)
        if timestamp:
            vulnerability_times[canonical].add(timestamp)
        vulnerability_evidence[canonical].update(
            edge.object_id for edge in edges_by_type["SUPPORTED_BY"]
            if edge.subject_id == vulnerability_id and edge.object_id in active_ids
        )
        for cwe_id in active_mapped(vulnerability_id, "HAS_WEAKNESS_ASSERTION"):
            cwe_to_vulnerabilities[cwe_id].add(canonical)
        vulnerability_techniques.setdefault(canonical, set()).update(active_mapped(vulnerability_id, "HAS_TECHNIQUE_ASSERTION"))
        vulnerability_contexts.setdefault(canonical, set()).update(active_mapped(vulnerability_id, "HAS_CONTEXT_ASSERTION"))
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    associations = 0
    current_association_ids: set[str] = set()
    for cwe_id, identities in sorted(cwe_to_vulnerabilities.items()):
        profile_id = f"CWE-PROFILE-{cwe_id}"
        nodes.append(GraphNode(label="CWEContextProfile", node_id=profile_id, props={"cwe_id": cwe_id, "independent_vulnerability_count": len(identities), "status": "OBSERVED"}))
        edges.append(GraphEdge(edge_id=f"EDGE-HAS-ENRICHED-PROFILE-{cwe_id}", edge_type="HAS_ENRICHED_PROFILE", subject_id=cwe_id, object_id=profile_id))
        grouped = {
            "Technique": defaultdict(set),
            "Context": defaultdict(set),
        }
        for identity in identities:
            for technique_id in vulnerability_techniques.get(identity, set()):
                grouped["Technique"][technique_id].add(identity)
            for context_id in vulnerability_contexts.get(identity, set()):
                grouped["Context"][context_id].add(identity)
        for kind, values in grouped.items():
            for target_id, support in sorted(values.items()):
                association_id = f"PROFILE-ASSOC-{profile_id}-{target_id}"
                current_association_ids.add(association_id)
                timestamps = sorted(timestamp for identity in support for timestamp in vulnerability_times.get(identity, set()))
                distribution: dict[str, int] = defaultdict(int)
                for identity in support:
                    for context_id in vulnerability_contexts.get(identity, set()):
                        distribution[context_id] += 1
                evidence_ids = {evidence_id for identity in support for evidence_id in vulnerability_evidence.get(identity, set())}
                nodes.append(GraphNode(label="ProfileAssociation", node_id=association_id, props={"profile_id": profile_id, "target_id": target_id, "kind": kind, "support": len(support), "confidence": len(support) / len(identities), "technology_distribution": dict(sorted(distribution.items())), "evidence_count": len(evidence_ids), "validation_count": 0, "first_seen": timestamps[0].isoformat() if timestamps else None, "last_seen": timestamps[-1].isoformat() if timestamps else None, "status": "OBSERVED"}))
                edges.append(GraphEdge(edge_id=f"EDGE-PROFILE-ASSOCIATION-{association_id}", edge_type="HAS_ASSOCIATION", subject_id=profile_id, object_id=association_id))
                edges.append(GraphEdge(edge_id=f"EDGE-ASSOCIATION-TARGET-{association_id}-{target_id}", edge_type="ASSOCIATES", subject_id=association_id, object_id=target_id))
                associations += 1
    # Historical association nodes are retained for audit, but are not part of
    # the current projection after their supporting active facts disappear.
    for previous in all_nodes.values():
        if previous.label != "ProfileAssociation":
            continue
        if previous.node_id not in current_association_ids and previous.props.get("stale") is not True:
            nodes.append(GraphNode(
                label="ProfileAssociation",
                node_id=previous.node_id,
                props={**previous.props, "stale": True, "status": "STALE"},
            ))
    if nodes or edges:
        repository.atomic_write(nodes=nodes, edges=edges)
    return ProfileRebuildReport(len(cwe_to_vulnerabilities), associations)
