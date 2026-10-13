from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository


class InMemoryGraphRepository(GraphRepository):
    """Reference repository used by unit tests and offline importer staging."""

    @property
    def backend_name(self) -> str:
        return "in-memory"

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}

    @staticmethod
    def _validate(nodes: dict[str, GraphNode], edges: dict[str, GraphEdge]) -> None:
        for edge in edges.values():
            absent = [endpoint for endpoint in (edge.subject_id, edge.object_id) if endpoint not in nodes]
            if absent:
                raise ValueError(f"cannot create {edge.edge_id}: missing endpoint {absent[0]}")
            endpoint_labels = {nodes[edge.subject_id].label, nodes[edge.object_id].label}
            if "CWE" in endpoint_labels and endpoint_labels & {"CVE", "GHSA"}:
                raise ValueError(
                    "direct vulnerability-to-CWE relation is forbidden; "
                    "use a reified WeaknessAssertion"
                )

    def atomic_write(self, *, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        next_nodes = dict(self._nodes)
        next_edges = dict(self._edges)
        for node in nodes:
            existing = next_nodes.get(node.node_id)
            if existing is not None and existing.label != node.label:
                raise ValueError(f"node identity collision: {node.node_id}")
            next_nodes[node.node_id] = node
        for edge in edges:
            existing = next_edges.get(edge.edge_id)
            if existing is not None and (
                existing.edge_type != edge.edge_type
                or existing.subject_id != edge.subject_id
                or existing.object_id != edge.object_id
            ):
                raise ValueError(f"edge identity collision: {edge.edge_id}")
            next_edges[edge.edge_id] = edge
        self._validate(next_nodes, next_edges)
        self._nodes = next_nodes
        self._edges = next_edges

    def replace_all(self, *, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        next_nodes = {node.node_id: node for node in nodes}
        if len(next_nodes) != len(nodes):
            raise ValueError("duplicate node identity in replacement batch")
        next_edges = {edge.edge_id: edge for edge in edges}
        if len(next_edges) != len(edges):
            raise ValueError("duplicate edge identity in replacement batch")
        self._validate(next_nodes, next_edges)
        self._nodes = next_nodes
        self._edges = next_edges

    def nodes(self, label: str | None = None) -> list[GraphNode]:
        return sorted(
            (node for node in self._nodes.values() if label is None or node.label == label),
            key=lambda node: node.node_id,
        )

    def edges(self, edge_type: str | None = None) -> list[GraphEdge]:
        return sorted(
            (edge for edge in self._edges.values() if edge_type is None or edge.edge_type == edge_type),
            key=lambda edge: edge.edge_id,
        )
