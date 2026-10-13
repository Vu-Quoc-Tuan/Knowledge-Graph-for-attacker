import json

from ckg.graph.models import GraphEdge, GraphNode


def assertion_evidence_ids(assertion: GraphNode, nodes_by_id: dict[str, GraphNode]) -> set[str]:
    """Return only snapshot-backed evidence referenced by this assertion."""
    if assertion.props.get("all_source_snapshots_available") is False:
        return set()
    spans = assertion.props.get("evidence_spans") or assertion.props.get("evidence_spansJson")
    if isinstance(spans, str):
        try:
            spans = json.loads(spans)
        except json.JSONDecodeError:
            return set()
    supported = set()
    for span in spans or ():
        if not isinstance(span, dict):
            continue
        evidence_id = span.get("evidence_id")
        evidence = nodes_by_id.get(evidence_id) if isinstance(evidence_id, str) else None
        if evidence is None or evidence.label != "Evidence":
            continue
        if evidence.props.get("source_snapshot_available") is False:
            continue
        digest = span.get("content_digest")
        if digest and evidence.props.get("content_digest") != digest:
            continue
        supported.add(evidence_id)
    return supported


def evidence_closure(nodes: list[GraphNode], edges: list[GraphEdge]) -> tuple[list[GraphNode], list[GraphEdge]]:
    """Drop any assertion that lost all evidence paths during budget pruning."""
    nodes_by_id = {node.node_id: node for node in nodes}
    orphaned: set[str] = set()
    for node in nodes:
        if not node.label.endswith("Assertion"):
            continue
        spans = node.props.get("evidence_spans") or node.props.get("evidence_spansJson")
        if isinstance(spans, str):
            # Neo4j serializes nested props. A malformed value is not evidence.
            try:
                spans = json.loads(spans)
            except json.JSONDecodeError:
                spans = []
        if spans:
            if assertion_evidence_ids(node, nodes_by_id):
                continue
            orphaned.add(node.node_id)
            continue
        # Pre-v2 registry migrations can contain a declared assertion with no
        # span at all. It is not evidence-backed and later rankers must keep
        # coverage low, but it was not *orphaned by this pruning pass*. Dropping
        # it here would silently erase the only historical linkage.
    if not orphaned:
        return nodes, edges
    retained_nodes = [node for node in nodes if node.node_id not in orphaned]
    retained_edges = [edge for edge in edges if edge.subject_id not in orphaned and edge.object_id not in orphaned]
    return retained_nodes, retained_edges
