"""Facet-union candidates for historical vulnerabilities; no description-only search."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ckg.graph.ports import GraphRepository
from ckg.graph.canonical import canonical_content_by_id, canonical_edge_visible
from ckg.graph.models import GraphEdge
from ckg.reasoning.subgraph.builder import _edge_visible, _visible
from ckg.reasoning.subgraph.pruning import assertion_evidence_ids


def _targets(repository: GraphRepository, source_id: str, relation: str, visible_ids: set[str] | None = None, edges: tuple[GraphEdge, ...] | None = None) -> set[str]:
    source_edges = edges if edges is not None else tuple(repository.edges(relation))
    return {edge.object_id for edge in source_edges if edge.edge_type == relation and edge.subject_id == source_id and (visible_ids is None or edge.object_id in visible_ids)}


def _mapped_values(repository: GraphRepository, vulnerability_id: str, assertion_relation: str, visible_ids: set[str] | None = None, edges: tuple[GraphEdge, ...] | None = None) -> set[str]:
    assertions = _targets(repository, vulnerability_id, assertion_relation, visible_ids, edges)
    source_edges = edges if edges is not None else tuple(repository.edges("MAPS_TO"))
    return {edge.object_id for edge in source_edges if edge.edge_type == "MAPS_TO" and edge.subject_id in assertions and (visible_ids is None or edge.object_id in visible_ids)}


def _cwe_neighbors(repository: GraphRepository, cwe_ids: set[str], edges: tuple[GraphEdge, ...] | None = None) -> set[str]:
    allowed = {"CHILD_OF", "PARENT_OF", "PEER_OF", "CAN_ALSO_BE"}
    neighbors = set(cwe_ids)
    for edge in edges if edges is not None else repository.edges():
        if edge.edge_type not in allowed:
            continue
        if edge.subject_id in cwe_ids:
            neighbors.add(edge.object_id)
        if edge.object_id in cwe_ids:
            neighbors.add(edge.subject_id)
    return neighbors


def _capec_ids(repository: GraphRepository, cwe_ids: set[str], edges: tuple[GraphEdge, ...] | None = None) -> set[str]:
    source_edges = edges if edges is not None else tuple(repository.edges("RELATED_WEAKNESS"))
    return {edge.subject_id for edge in source_edges if edge.edge_type == "RELATED_WEAKNESS" and edge.object_id in cwe_ids}


def _patch_patterns(repository: GraphRepository, vulnerability_id: str, visible_ids: set[str] | None = None, edges: tuple[GraphEdge, ...] | None = None) -> set[str]:
    return _targets(repository, vulnerability_id, "HAS_PATCH_PATTERN", visible_ids, edges)


def historical_candidate_sources(repository: GraphRepository, vulnerability_id: str, *, as_of: datetime | None = None) -> dict[str, frozenset[str]]:
    """Return candidate CVEs plus the independent retrieval planes that found them using inverted index."""
    result: dict[str, set[str]] = defaultdict(set)
    visible_nodes = {node.node_id: node for node in repository.nodes() if _visible(node, as_of)}
    visible_ids = set(visible_nodes)
    invalid_assertions = {
        node.node_id
        for node in visible_nodes.values()
        if node.label.endswith("Assertion")
        and (
            node.props.get("all_source_snapshots_available") is False
            or (
                (node.props.get("evidence_spans") or node.props.get("evidence_spansJson"))
                and not assertion_evidence_ids(node, visible_nodes)
            )
        )
    }
    cwe_content = canonical_content_by_id(repository, "CWE", as_of=as_of)
    capec_content = canonical_content_by_id(repository, "CAPEC", as_of=as_of)
    all_edges = tuple(repository.edges())
    custom_only_vulnerabilities: set[str] = set()
    source_urls: dict[str, list[str]] = defaultdict(list)
    for edge in all_edges:
        source = visible_nodes.get(edge.subject_id)
        if edge.edge_type == "DESCRIBES" and source is not None and source.label == "VulnerabilitySourceRecord":
            source_urls[edge.object_id].append(str(source.props.get("source_url") or ""))
    custom_only_vulnerabilities = {
        identifier for identifier, urls in source_urls.items()
        if urls and all(url.startswith("custom://") for url in urls)
    }
    visible_edges = tuple(
        edge for edge in all_edges
        if _edge_visible(edge, as_of)
        and edge.subject_id not in invalid_assertions
        and edge.object_id not in invalid_assertions
        and canonical_edge_visible(
            repository,
            edge,
            as_of=as_of,
            cwe_content=cwe_content,
            capec_content=capec_content,
        )
    )
    if vulnerability_id not in visible_ids:
        return {}

    weaknesses = _mapped_values(repository, vulnerability_id, "HAS_WEAKNESS_ASSERTION", visible_ids, visible_edges)
    techniques = _mapped_values(repository, vulnerability_id, "HAS_TECHNIQUE_ASSERTION", visible_ids, visible_edges)
    contexts = _mapped_values(repository, vulnerability_id, "HAS_CONTEXT_ASSERTION", visible_ids, visible_edges)
    capec_ids = _capec_ids(repository, weaknesses, visible_edges)
    patches = _patch_patterns(repository, vulnerability_id, visible_ids, visible_edges)
    expanded_weaknesses = _cwe_neighbors(repository, weaknesses, visible_edges)

    # Inverted lookup for weaknesses
    all_target_weaknesses = weaknesses | expanded_weaknesses
    if all_target_weaknesses:
        w_map = {e.subject_id: e.object_id for e in visible_edges if e.edge_type == "MAPS_TO" and e.object_id in all_target_weaknesses and e.subject_id in visible_ids}
        for e in visible_edges:
            if e.edge_type != "HAS_WEAKNESS_ASSERTION":
                continue
            if e.object_id in w_map and e.subject_id != vulnerability_id and e.subject_id in visible_ids:
                mapped_cwe = w_map[e.object_id]
                if mapped_cwe in weaknesses:
                    result[e.subject_id].add("same_weakness")
                elif mapped_cwe in expanded_weaknesses:
                    result[e.subject_id].add("adjacent_weakness")
        # Ensure that if a candidate has same_weakness, adjacent_weakness is not needed
        for other in result:
            if "same_weakness" in result[other] and "adjacent_weakness" in result[other]:
                result[other].remove("adjacent_weakness")

    # Inverted lookup for techniques
    if techniques:
        t_map = {e.subject_id: e.object_id for e in visible_edges if e.edge_type == "MAPS_TO" and e.object_id in techniques and e.subject_id in visible_ids}
        for e in visible_edges:
            if e.edge_type != "HAS_TECHNIQUE_ASSERTION":
                continue
            if e.object_id in t_map and e.subject_id != vulnerability_id and e.subject_id in visible_ids:
                result[e.subject_id].add("same_technique")

    # Inverted lookup for contexts
    if contexts:
        c_map = {e.subject_id: e.object_id for e in visible_edges if e.edge_type == "MAPS_TO" and e.object_id in contexts and e.subject_id in visible_ids}
        for e in visible_edges:
            if e.edge_type != "HAS_CONTEXT_ASSERTION":
                continue
            if e.object_id in c_map and e.subject_id != vulnerability_id and e.subject_id in visible_ids:
                result[e.subject_id].add("same_context")

    # Inverted lookup for CAPEC neighborhood
    if capec_ids:
        capec_cwes = {e.object_id for e in visible_edges if e.edge_type == "RELATED_WEAKNESS" and e.subject_id in capec_ids}
        if capec_cwes:
            capec_w_map = {e.subject_id: e.object_id for e in visible_edges if e.edge_type == "MAPS_TO" and e.object_id in capec_cwes and e.subject_id in visible_ids}
            for e in visible_edges:
                if e.edge_type != "HAS_WEAKNESS_ASSERTION":
                    continue
                if e.object_id in capec_w_map and e.subject_id != vulnerability_id and e.subject_id in visible_ids:
                    result[e.subject_id].add("same_capec_neighborhood")

    # Inverted lookup for patch patterns
    if patches:
        for e in visible_edges:
            if e.edge_type != "HAS_PATCH_PATTERN":
                continue
            if e.object_id in patches and e.subject_id != vulnerability_id and e.subject_id in visible_ids:
                result[e.subject_id].add("same_patch_pattern")

    for edge in visible_edges:
        if edge.edge_type != "SIMILAR_TO":
            continue
        if edge.subject_id == vulnerability_id and edge.object_id in visible_ids:
            result[edge.object_id].add("graph_similarity")
        elif edge.object_id == vulnerability_id and edge.subject_id in visible_ids:
            result[edge.subject_id].add("graph_similarity")

    for edge in visible_edges:
        if edge.edge_type != "SHARES_PATTERN":
            continue
        if edge.subject_id == vulnerability_id and edge.object_id in visible_ids:
            result[edge.object_id].add("shared_patch_pattern")
        elif edge.object_id == vulnerability_id and edge.subject_id in visible_ids:
            result[edge.subject_id].add("shared_patch_pattern")

    return {
        identifier: frozenset(sources)
        for identifier, sources in result.items()
        if identifier not in custom_only_vulnerabilities
    }
