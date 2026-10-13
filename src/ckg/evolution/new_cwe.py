"""Create candidate profile relations for newly introduced canonical CWE entries."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository


@dataclass(frozen=True)
class NewCWEEnrichmentReport:
    cwe_ids: tuple[str, ...]
    candidate_relation_count: int


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", value.lower()))


def enrich_new_cwes(repository: GraphRepository, cwe_ids: tuple[str, ...], *, top_k: int = 5) -> NewCWEEnrichmentReport:
    cwes = {node.node_id: node for node in repository.nodes("CWE")}
    nodes_by_id = {node.node_id: node for node in repository.nodes()}
    assertion_to_vulnerabilities: dict[str, set[str]] = {}
    for edge in repository.edges("HAS_WEAKNESS_ASSERTION"):
        assertion_to_vulnerabilities.setdefault(edge.object_id, set()).add(edge.subject_id)
    mapped_assertions: dict[str, set[str]] = {}
    for edge in repository.edges("MAPS_TO"):
        mapped_assertions.setdefault(edge.object_id, set()).add(edge.subject_id)
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    candidates = 0
    for cwe_id in sorted(set(cwe_ids)):
        current = cwes.get(cwe_id)
        if current is None:
            continue
        current_tokens = _tokens(f"{current.props.get('name', '')} {current.props.get('description', '')}")
        scored = []
        for other_id, other in cwes.items():
            if other_id == cwe_id:
                continue
            other_tokens = _tokens(f"{other.props.get('name', '')} {other.props.get('description', '')}")
            score = len(current_tokens & other_tokens) / len(current_tokens | other_tokens) if current_tokens | other_tokens else 0.0
            if score:
                scored.append((other_id, score))
        profile_id = f"CWE-PROFILE-{cwe_id}"
        nodes.append(GraphNode(label="CWEContextProfile", node_id=profile_id, props={"cwe_id": cwe_id, "status": "INFERRED", "independent_vulnerability_count": 0, "candidate": True}))
        edges.append(GraphEdge(edge_id=f"EDGE-HAS-ENRICHED-PROFILE-{cwe_id}", edge_type="HAS_ENRICHED_PROFILE", subject_id=cwe_id, object_id=profile_id))
        semantic_neighbors = sorted(scored, key=lambda item: (-item[1], item[0]))[:top_k]
        for other_id, score in semantic_neighbors:
            relation_id = "INFERRED-CWE-NEIGHBOR-" + hashlib.sha256(f"{cwe_id}|{other_id}".encode()).hexdigest()[:24]
            nodes.append(GraphNode(label="CandidateRelation", node_id=relation_id, props={"subject_id": cwe_id, "object_id": other_id, "predicate": "SEMANTIC_NEIGHBOR", "status": "INFERRED", "relevance": score, "evidence_coverage": 0.0, "basis": "canonical_definition_lexical_overlap"}))
            edges.append(GraphEdge(edge_id=f"EDGE-PROFILE-CANDIDATE-{profile_id}-{relation_id}", edge_type="HAS_CANDIDATE_RELATION", subject_id=profile_id, object_id=relation_id))
            candidates += 1
        # A newly named CWE may have no historical instances of its own.  The
        # historical candidates here are therefore explicitly inferred via a
        # semantic CWE neighbour, never backfilled as a reported CWE mapping.
        for other_id, score in semantic_neighbors:
            historical_ids = {
                vulnerability_id
                for assertion_id in mapped_assertions.get(other_id, set())
                for vulnerability_id in assertion_to_vulnerabilities.get(assertion_id, set())
                if nodes_by_id.get(vulnerability_id) and nodes_by_id[vulnerability_id].label in {"CVE", "GHSA"}
            }
            for vulnerability_id in sorted(historical_ids)[:top_k]:
                relation_id = "INFERRED-HISTORICAL-CLUSTER-" + hashlib.sha256(f"{cwe_id}|{other_id}|{vulnerability_id}".encode()).hexdigest()[:24]
                nodes.append(GraphNode(label="CandidateRelation", node_id=relation_id, props={"subject_id": cwe_id, "object_id": vulnerability_id, "predicate": "HISTORICAL_CLUSTER_AVAILABLE", "status": "INFERRED", "relevance": score, "evidence_coverage": 1.0, "basis": "semantic_cwe_neighbor_with_historical_instance", "neighbor_cwe_id": other_id}))
                edges.append(GraphEdge(edge_id=f"EDGE-PROFILE-CANDIDATE-{profile_id}-{relation_id}", edge_type="HAS_CANDIDATE_RELATION", subject_id=profile_id, object_id=relation_id))
                candidates += 1
        # CAPEC and WSTG mappings remain their own canonical/source planes.  A
        # profile only records that such knowledge is available for the newly
        # imported CWE; it never rewrites a CAPEC relation as a learned fact.
        source_edges = [
            edge for edge in repository.edges()
            if edge.object_id == cwe_id and edge.edge_type in {"RELATED_WEAKNESS", "TARGETS_WEAKNESS"}
        ]
        for edge in sorted(source_edges, key=lambda item: (item.edge_type, item.subject_id, item.edge_id)):
            predicate = "CAPEC_NEIGHBOR_AVAILABLE" if edge.edge_type == "RELATED_WEAKNESS" else "TEST_STRATEGY_AVAILABLE"
            relation_id = "INFERRED-PLANE-NEIGHBOR-" + hashlib.sha256(f"{cwe_id}|{predicate}|{edge.subject_id}".encode()).hexdigest()[:24]
            nodes.append(GraphNode(label="CandidateRelation", node_id=relation_id, props={"subject_id": cwe_id, "object_id": edge.subject_id, "predicate": predicate, "status": "INFERRED", "relevance": 1.0, "evidence_coverage": 1.0, "basis": "existing_source_plane_mapping", "source_edge_id": edge.edge_id}))
            edges.append(GraphEdge(edge_id=f"EDGE-PROFILE-CANDIDATE-{profile_id}-{relation_id}", edge_type="HAS_CANDIDATE_RELATION", subject_id=profile_id, object_id=relation_id))
            candidates += 1
    if nodes:
        repository.atomic_write(nodes=nodes, edges=edges)
    return NewCWEEnrichmentReport(tuple(sorted(set(cwe_ids))), candidates)
