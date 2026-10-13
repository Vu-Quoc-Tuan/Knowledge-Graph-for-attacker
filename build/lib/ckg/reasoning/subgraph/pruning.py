from ckg.graph.models import GraphEdge, GraphNode


def evidence_closure(nodes: list[GraphNode], edges: list[GraphEdge]) -> tuple[list[GraphNode], list[GraphEdge]]:
    """Drop any assertion that lost all evidence paths during budget pruning."""
    node_ids = {node.node_id for node in nodes}
    supported_by = {edge.subject_id for edge in edges if edge.edge_type == "SUPPORTED_BY" and edge.object_id in node_ids}
    orphaned: set[str] = set()
    for node in nodes:
        if not node.label.endswith("Assertion"):
            continue
        spans = node.props.get("evidence_spans") or node.props.get("evidence_spansJson")
        if isinstance(spans, str):
            # Neo4j serializes nested props. A malformed value is not evidence.
            import json
            try:
                spans = json.loads(spans)
            except json.JSONDecodeError:
                spans = []
        span_ids = {
            item.get("evidence_id")
            for item in spans or []
            if isinstance(item, dict) and item.get("evidence_id")
        }
        if span_ids:
            if span_ids & node_ids:
                continue
            if node.node_id in supported_by:
                continue
            orphaned.add(node.node_id)
            continue
        # Pre-v2 registry migrations can contain a declared assertion with no
        # span at all. It is not evidence-backed and later rankers must keep
        # coverage low, but it was not *orphaned by this pruning pass*. Dropping
        # it here would silently erase the only historical linkage.
        if node.node_id in supported_by:
            continue
    if not orphaned:
        return nodes, edges
    retained_nodes = [node for node in nodes if node.node_id not in orphaned]
    retained_edges = [edge for edge in edges if edge.subject_id not in orphaned and edge.object_id not in orphaned]
    return retained_nodes, retained_edges
