"""Statistical co-occurrence is explicitly non-causal."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from itertools import combinations

from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository


@dataclass(frozen=True)
class CooccurrenceReport:
    relation_count: int


def mine_cooccurrence(repository: GraphRepository, *, min_support: int = 2, min_lift: float = 1.0) -> CooccurrenceReport:
    all_nodes = repository.nodes()
    all_edges = repository.edges()
    assertions_by_vulnerability: dict[str, set[str]] = {}
    mapped_targets: dict[str, set[str]] = {}
    for edge in all_edges:
        if edge.edge_type == "HAS_WEAKNESS_ASSERTION":
            assertions_by_vulnerability.setdefault(edge.subject_id, set()).add(edge.object_id)
        elif edge.edge_type == "MAPS_TO":
            mapped_targets.setdefault(edge.subject_id, set()).add(edge.object_id)
    per_vulnerability = [
        {
            target
            for assertion_id in assertions_by_vulnerability.get(node.node_id, set())
            for target in mapped_targets.get(assertion_id, set())
        }
        for node in all_nodes
        if node.label in {"CVE", "GHSA"}
    ]
    total = len(per_vulnerability)
    individual = Counter(item for values in per_vulnerability for item in values)
    pairs = Counter(pair for values in per_vulnerability for pair in combinations(sorted(values), 2))
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    for (left, right), support in sorted(pairs.items()):
        if total == 0 or support < min_support:
            continue
        lift = (support / total) / ((individual[left] / total) * (individual[right] / total))
        if lift < min_lift:
            continue
        relation_id = f"COOCCUR-{left}-{right}"
        nodes.append(GraphNode(label="Cooccurrence", node_id=relation_id, props={"left": left, "right": right, "support": support, "lift": lift, "semantic": "non_causal_observation", "status": "OBSERVED"}))
        edges.extend((
            GraphEdge(edge_id=f"EDGE-COOCCUR-LEFT-{relation_id}", edge_type="CO_OCCURS_WITH", subject_id=left, object_id=relation_id),
            GraphEdge(edge_id=f"EDGE-COOCCUR-RIGHT-{relation_id}", edge_type="CO_OCCURS_WITH", subject_id=relation_id, object_id=right),
        ))
    if nodes:
        repository.atomic_write(nodes=nodes, edges=edges)
    return CooccurrenceReport(len(nodes))
