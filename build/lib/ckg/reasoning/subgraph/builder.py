"""Bounded local graph construction with typed traversal and temporal visibility."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
import json

from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.reasoning.subgraph.budgets import SubgraphBudget
from ckg.reasoning.subgraph.pruning import evidence_closure


TRAVERSAL_WHITELIST = frozenset({
    "HAS_WEAKNESS_ASSERTION", "HAS_TECHNIQUE_ASSERTION", "HAS_CONTEXT_ASSERTION",
    "MAPS_TO", "SUPPORTED_BY", "DESCRIBES", "USES_TECHNIQUE", "USES_CHANNEL",
    "USES_ORACLE", "APPLIES_TO", "TARGETS_WEAKNESS", "RELATED_WEAKNESS",
    "CHILD_OF", "PARENT_OF", "CAN_PRECEDE", "CAN_FOLLOW", "REQUIRES",
    "REQUIRED_BY", "PEER_OF", "CAN_ALSO_BE", "SIMILAR_TO", "SHARES_PATTERN",
    "HAS_OCCURRENCE", "ENABLES", "PRECEDES", "REQUIRED_TOGETHER",
    "HAS_CONSTRAINT", "REQUIRES_CONSTRAINT", "BLOCKED_BY", "DERIVED_FROM",
    "TARGETS", "HAS_PATCH_PATTERN",
})

# Only ontology nodes which are installed as canonical catalog content may be
# visible without a timestamp.  WSTG/PATT are source snapshots, not timeless
# ontology: allowing an undated document here leaks future methodology into a
# temporal evaluation split.
_TIMELESS_CANONICAL = frozenset({
    "CWE", "CWECategory", "CWEView", "CAPEC", "AttackStep",
    "AttackPrerequisite", "Technique", "CallbackChannel", "Oracle",
    "InputSurface", "TestStrategy", "ProbeFamily", "BypassTechnique", "PatchPattern",
    "ApplicabilityConstraint",
})


@dataclass(frozen=True)
class LocalSubgraph:
    root_id: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    truncated: bool
    dropped_node_ids: tuple[str, ...]
    temporal_excluded_node_ids: tuple[str, ...]


def _timestamp(node: GraphNode) -> datetime | None:
    for key in ("first_seen_at", "known_at", "retrieved_at", "published_at", "updated_at", "observed_at"):
        value = node.props.get(key)
        if not value:
            continue
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    provenance = node.props.get("provenance")
    if provenance is None and isinstance(node.props.get("provenanceJson"), str):
        try:
            provenance = json.loads(node.props["provenanceJson"])
        except json.JSONDecodeError:
            provenance = None
    if isinstance(provenance, dict) and provenance.get("retrieved_at"):
        try:
            return datetime.fromisoformat(str(provenance["retrieved_at"]).replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _visible(node: GraphNode, as_of: datetime | None, canonical_revisions: dict[str, set[str]] | None = None) -> bool:
    if node.props.get("stale") is True:
        return False
    if as_of is None:
        return True
    timestamp = _timestamp(node)
    if timestamp is None:
        return node.label in _TIMELESS_CANONICAL
    if timestamp.tzinfo is None and as_of.tzinfo is not None:
        timestamp = timestamp.replace(tzinfo=as_of.tzinfo)
    if timestamp <= as_of:
        return True
    if canonical_revisions and node.label in canonical_revisions:
        return node.node_id in canonical_revisions[node.label]
    return False


def _edge_visible(edge: GraphEdge, as_of: datetime | None) -> bool:
    if as_of is None:
        return True
    value = edge.props.get("retrieved_at") or edge.props.get("known_at")
    if not value:
        return True
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    if timestamp.tzinfo is None and as_of.tzinfo is not None:
        timestamp = timestamp.replace(tzinfo=as_of.tzinfo)
    return timestamp <= as_of


def _plane(label: str, root_id: str, node_id: str) -> str | None:
    if label == "CWE":
        return "cwe"
    if label in {"CAPEC", "AttackStep", "AttackPrerequisite"}:
        return "capec"
    if label in {"CVE", "GHSA"} and node_id != root_id:
        return "historical_cves"
    if label in {"Technique", "TechniqueAssertion", "CallbackChannel", "Oracle", "TestStrategy"}:
        return "techniques"
    if label in {"ContextAssertion", "Language", "Runtime", "Framework", "Library", "Package", "DBMS", "Protocol", "DataFormat", "Component", "InputSurface", "ApplicabilityConstraint"}:
        return "contexts"
    if label == "Evidence":
        return "evidence"
    if label == "Scenario":
        return "scenarios"
    if label in {"WeaknessOccurrence", "CompositionGroup"}:
        return "cwe"
    return None


def _semantic_anchor_nodes(repository: GraphRepository, root_id: str) -> tuple[GraphNode, ...]:
    """Find exact-property anchors not necessarily represented by an edge.

    Early v2 projections materialised scenarios and occurrence groups with a
    ``target_vulnerability_id``/``vulnerability_id`` property before the
    corresponding graph edges existed.  Treat those explicit identifiers as a
    compatibility index, rather than making reasoners scan global state.  New
    writes still use normal whitelisted edges.
    """

    scenarios = repository.find_nodes(
        "Scenario", {"target_vulnerability_id": root_id}
    )
    occurrences = repository.find_nodes(
        "WeaknessOccurrence", {"vulnerability_id": root_id}
    )
    composition_groups = repository.find_nodes(
        "CompositionGroup", {"vulnerability_id": root_id}
    )
    constraint_ids = {
        str(constraint_id)
        for node in scenarios
        for constraint_id in (node.props.get("constraint_ids") or ())
    }
    constraints = repository.nodes_by_ids(frozenset(constraint_ids))
    return tuple(
        sorted(
            {node.node_id: node for node in (*scenarios, *occurrences, *composition_groups, *constraints)}.values(),
            key=lambda node: node.node_id,
        )
    )


def _test_strategy_anchor_nodes(
    repository: GraphRepository,
    target_cwe_ids: set[str],
    as_of: datetime | None = None,
    canonical_revisions: dict[str, set[str]] | None = None,
) -> tuple[tuple[GraphNode, ...], tuple[GraphEdge, ...]]:
    if not target_cwe_ids:
        return (), ()
    strategy_candidates = [
        node for node in repository.find_nodes("TestStrategy", {})
        if _visible(node, as_of, canonical_revisions)
    ]
    if not strategy_candidates:
        return (), ()
    strat_ids = {n.node_id for n in strategy_candidates}
    target_edges = [
        edge
        for edge in repository.edges_between(
            frozenset(strat_ids | target_cwe_ids),
            edge_types=frozenset({"TARGETS_WEAKNESS"}),
        )
        if edge.subject_id in strat_ids and edge.object_id in target_cwe_ids and _edge_visible(edge, as_of)
    ]
    if not target_edges:
        return (), ()
    relevant_strat_ids = {edge.subject_id for edge in target_edges}
    relevant_strat_nodes = [n for n in strategy_candidates if n.node_id in relevant_strat_ids]

    aux_nodes = [
        node
        for label in ("Technique", "CallbackChannel", "Oracle", "InputSurface")
        for node in repository.find_nodes(label, {})
        if _visible(node, as_of, canonical_revisions)
    ]
    aux_ids = {n.node_id for n in aux_nodes}
    aux_edges = [
        edge
        for edge in repository.edges_between(
            frozenset(relevant_strat_ids | aux_ids),
            edge_types=frozenset({"USES_TECHNIQUE", "USES_CHANNEL", "USES_ORACLE", "APPLIES_TO"}),
        )
        if edge.subject_id in relevant_strat_ids and _edge_visible(edge, as_of)
    ]
    connected_aux_ids = {edge.object_id for edge in aux_edges}
    connected_aux_nodes = [n for n in aux_nodes if n.node_id in connected_aux_ids]

    all_nodes = tuple(
        sorted(
            {node.node_id: node for node in (*relevant_strat_nodes, *connected_aux_nodes)}.values(),
            key=lambda n: n.node_id,
        )
    )
    all_edges = tuple(
        sorted(
            {edge.edge_id: edge for edge in (*target_edges, *aux_edges)}.values(),
            key=lambda e: e.edge_id,
        )
    )
    return all_nodes, all_edges


def build_local_subgraph(repository: GraphRepository, root_id: str, *, budget: SubgraphBudget = SubgraphBudget(), as_of: datetime | None = None) -> LocalSubgraph:
    cwe_revs = {}
    capec_revs = {}
    canonical_revisions = None
    if as_of is not None:
        from ckg.graph.canonical import canonical_content_by_id
        cwe_revs = canonical_content_by_id(repository, "CWE", as_of=as_of)
        capec_revs = canonical_content_by_id(repository, "CAPEC", as_of=as_of)
        canonical_revisions = {"CWE": set(cwe_revs.keys()), "CAPEC": set(capec_revs.keys())}

    pushed_down = repository.bounded_neighborhood(
        root_id,
        edge_types=TRAVERSAL_WHITELIST,
        max_depth=budget.max_depth,
        max_nodes=budget.hard_max_nodes,
        max_paths=budget.max_query_paths,
        timeout_seconds=budget.timeout_seconds,
    )
    initial_nodes = tuple(pushed_down.nodes) if pushed_down else tuple(repository.nodes())
    nodes_by_id = {node.node_id: node for node in initial_nodes}
    if root_id not in nodes_by_id:
        raise ValueError(f"local subgraph root does not exist: {root_id}")
    if not _visible(nodes_by_id[root_id], as_of, canonical_revisions):
        raise ValueError(f"local subgraph root is not temporally visible: {root_id}")
    initial_edges = tuple(pushed_down.edges) if pushed_down else tuple(repository.edges())
    from ckg.graph.canonical import canonical_content_by_id, canonical_edge_visible
    has_release_scoped_edges = any(
        isinstance(edge.props.get("source_release"), str) for edge in initial_edges
    )
    effective_cwe_content = cwe_revs
    effective_capec_content = capec_revs
    if has_release_scoped_edges and not effective_cwe_content:
        effective_cwe_content = canonical_content_by_id(repository, "CWE")
    if has_release_scoped_edges and not effective_capec_content:
        effective_capec_content = canonical_content_by_id(repository, "CAPEC")
    edges = [
        edge for edge in initial_edges
        if edge.edge_type in TRAVERSAL_WHITELIST
        and _edge_visible(edge, as_of)
        and canonical_edge_visible(
            repository,
            edge,
            as_of=as_of,
            cwe_content=effective_cwe_content,
            capec_content=effective_capec_content,
        )
    ]
    adjacency: dict[str, list[tuple[str, GraphEdge]]] = {}
    for edge in edges:
        adjacency.setdefault(edge.subject_id, []).append((edge.object_id, edge))
        adjacency.setdefault(edge.object_id, []).append((edge.subject_id, edge))
    selected = {root_id}
    selected_edges: dict[str, GraphEdge] = {}
    counts = {key: 0 for key in ("cwe", "capec", "historical_cves", "techniques", "contexts", "evidence", "scenarios")}
    queue = deque([(root_id, 0)])
    dropped: set[str] = set()
    temporal_excluded: set[str] = set()
    truncated = bool(pushed_down and pushed_down.truncated)
    while queue:
        current, depth = queue.popleft()
        if depth >= budget.max_depth:
            continue
        for neighbor, edge in sorted(adjacency.get(current, []), key=lambda value: (value[1].edge_type, value[0], value[1].edge_id)):
            node = nodes_by_id.get(neighbor)
            if node is None:
                continue
            if not _visible(node, as_of, canonical_revisions):
                temporal_excluded.add(neighbor)
                continue
            if neighbor not in selected:
                plane = _plane(node.label, root_id, neighbor)
                plane_cap = getattr(budget, plane) if plane else None
                if len(selected) >= budget.hard_max_nodes or (plane and counts[plane] >= plane_cap):
                    dropped.add(neighbor)
                    truncated = True
                    continue
                selected.add(neighbor)
                if plane:
                    counts[plane] += 1
                queue.append((neighbor, depth + 1))
            if edge.subject_id in selected and edge.object_id in selected:
                selected_edges[edge.edge_id] = edge
    # Complete only exact, declared scenario/occurrence anchors. This does not
    # turn into free graph traversal and remains under the same plane caps.
    for node in _semantic_anchor_nodes(repository, root_id):
        node_id = node.node_id
        if node_id in selected:
            continue
        if not _visible(node, as_of, canonical_revisions):
            temporal_excluded.add(node_id)
            continue
        plane = _plane(node.label, root_id, node_id)
        plane_cap = getattr(budget, plane) if plane else None
        if len(selected) >= budget.hard_max_nodes or (plane and counts[plane] >= plane_cap):
            dropped.add(node_id)
            truncated = True
            continue
        selected.add(node_id)
        if plane:
            counts[plane] += 1
        nodes_by_id[node_id] = node

    # Anchors for canonical TestStrategies targeting discovered CWEs
    selected_cwes = {
        node_id
        for node_id in selected
        if nodes_by_id.get(node_id) and nodes_by_id[node_id].label == "CWE"
    }
    strat_nodes, strat_edges = _test_strategy_anchor_nodes(
        repository, selected_cwes, as_of=as_of, canonical_revisions=canonical_revisions
    )
    for node in strat_nodes:
        node_id = node.node_id
        if node_id in selected:
            continue
        if not _visible(node, as_of, canonical_revisions):
            temporal_excluded.add(node_id)
            continue
        plane = _plane(node.label, root_id, node_id)
        plane_cap = getattr(budget, plane) if plane else None
        if len(selected) >= budget.hard_max_nodes or (plane and counts[plane] >= plane_cap):
            dropped.add(node_id)
            truncated = True
            continue
        selected.add(node_id)
        if plane:
            counts[plane] += 1
        nodes_by_id[node_id] = node
    for edge in strat_edges:
        if edge.subject_id in selected and edge.object_id in selected:
            selected_edges[edge.edge_id] = edge

    # Anchors for ApplicabilityConstraint nodes
    for constraint_node in repository.find_nodes("ApplicabilityConstraint", {}):
        node_id = constraint_node.node_id
        if node_id in selected:
            continue
        if not _visible(constraint_node, as_of, canonical_revisions):
            temporal_excluded.add(node_id)
            continue
        plane = _plane(constraint_node.label, root_id, node_id)
        plane_cap = getattr(budget, plane) if plane else None
        if len(selected) >= budget.hard_max_nodes or (plane and counts[plane] >= plane_cap):
            dropped.add(node_id)
            truncated = True
            continue
        selected.add(node_id)
        if plane:
            counts[plane] += 1
        nodes_by_id[node_id] = constraint_node

    # Exact anchors may be linked by an existing whitelisted relation which
    # was outside the storage traversal envelope; retain it only when both
    # endpoints are already local.
    for edge in repository.edges_between(
        frozenset(selected), edge_types=TRAVERSAL_WHITELIST
    ):
        if (
            edge.edge_type in TRAVERSAL_WHITELIST
            and _edge_visible(edge, as_of)
            and edge.subject_id in selected
            and edge.object_id in selected
        ):
            selected_edges[edge.edge_id] = edge
    selected_nodes = [nodes_by_id[node_id] for node_id in sorted(selected)]
    if as_of is not None:
        projected = []
        for n in selected_nodes:
            if n.label == "CWE" and n.node_id in cwe_revs:
                projected.append(GraphNode(label=n.label, node_id=n.node_id, props=cwe_revs[n.node_id].props))
            elif n.label == "CAPEC" and n.node_id in capec_revs:
                projected.append(GraphNode(label=n.label, node_id=n.node_id, props=capec_revs[n.node_id].props))
            else:
                projected.append(n)
        selected_nodes = projected
    retained_edges = [selected_edges[edge_id] for edge_id in sorted(selected_edges)]
    selected_nodes, retained_edges = evidence_closure(selected_nodes, retained_edges)
    return LocalSubgraph(root_id, tuple(selected_nodes), tuple(retained_edges), truncated, tuple(sorted(dropped)), tuple(sorted(temporal_excluded)))
