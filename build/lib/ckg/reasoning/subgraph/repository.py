"""Read-only repository projection for bounded reasoning subgraphs."""

from __future__ import annotations

from ckg.graph.models import BoundedNeighborhood, GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.reasoning.subgraph.builder import LocalSubgraph


class LocalSubgraphRepository(GraphRepository):
    """Expose only a pre-built local graph to reasoners.

    Candidate retrieval may consult the full historical index, but a reasoner
    must not accidentally traverse the complete knowledge graph afterwards.
    This adapter deliberately rejects writes: scenario materialisation occurs
    through the original repository after candidates are produced.
    """

    def __init__(self, subgraph: LocalSubgraph) -> None:
        self._nodes = {node.node_id: node for node in subgraph.nodes}
        self._edges = {edge.edge_id: edge for edge in subgraph.edges}

    def atomic_write(self, *, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        raise RuntimeError("local subgraph repository is read-only")

    def replace_all(self, *, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        raise RuntimeError("local subgraph repository is read-only")

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

    def bounded_neighborhood(
        self,
        root_id: str,
        *,
        edge_types: frozenset[str],
        max_depth: int,
        max_nodes: int,
        max_paths: int,
        timeout_seconds: float,
    ) -> BoundedNeighborhood | None:
        if root_id not in self._nodes:
            return None
        # The supplied subgraph is already bounded by the authoritative
        # builder. Returning it avoids a second unbounded storage traversal.
        return BoundedNeighborhood(tuple(self.nodes()), tuple(self.edges()))
