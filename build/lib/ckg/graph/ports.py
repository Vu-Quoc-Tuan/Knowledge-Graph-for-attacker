from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ckg.graph.models import BoundedNeighborhood, GraphEdge, GraphNode, VulnerabilitySearchMatch

if TYPE_CHECKING:
    from ckg.provenance.compact_details import CompactDetailStore


class GraphRepository(ABC):
    """Storage contract where edge identity is explicit and batches are atomic."""

    @property
    def backend_name(self) -> str:
        """Stable runtime identity used by health/status responses."""

        return "v2-repository"

    @abstractmethod
    def atomic_write(self, *, nodes: list[GraphNode], edges: list[GraphEdge]) -> None: ...

    @abstractmethod
    def replace_all(self, *, nodes: list[GraphNode], edges: list[GraphEdge]) -> None: ...

    @abstractmethod
    def nodes(self, label: str | None = None) -> list[GraphNode]: ...

    @abstractmethod
    def edges(self, edge_type: str | None = None) -> list[GraphEdge]: ...

    def set_compact_detail_store(self, store: CompactDetailStore) -> None:
        """Attach the sidecar holding revisions removed from the active graph."""

        self._compact_detail_store = store

    def canonical_content_revisions(self, catalog: str) -> list[GraphNode]:
        """Combine graph revisions with historical sidecar revisions by identity."""

        if catalog not in {"CWE", "CAPEC"}:
            raise ValueError(f"unsupported canonical catalog: {catalog}")
        store = getattr(self, "_compact_detail_store", None)
        revisions = {
            node.node_id: node for node in self.nodes(f"{catalog}ContentRevision")
        }
        # A replay may write the same revision back into the graph with a
        # later retrieval time. The compacted original owns its first-seen
        # timestamp and must win for historical queries.
        if store is not None:
            revisions.update(
                (node.node_id, node) for node in store.canonical_revisions(catalog)
            )
        return [revisions[node_id] for node_id in sorted(revisions)]

    def find_nodes(self, label: str, properties: dict[str, object]) -> list[GraphNode]:
        """Return nodes matching exact, indexed-compatible scalar properties.

        The default is deliberately a reference implementation for the
        in-memory adapter. Production graph adapters override it so legacy
        property anchors can be added without returning the whole graph to a
        reasoner process.
        """
        return [
            node for node in self.nodes(label)
            if all(node.props.get(key) == value for key, value in properties.items())
        ]

    def nodes_by_ids(self, node_ids: frozenset[str]) -> list[GraphNode]:
        """Fetch an exact node set; production adapters should push this down."""
        return [node for node in self.nodes() if node.node_id in node_ids]

    def edges_between(
        self, node_ids: frozenset[str], *, edge_types: frozenset[str] | None = None
    ) -> list[GraphEdge]:
        """Fetch only relations whose two endpoints are already local."""
        return [
            edge for edge in self.edges()
            if edge.subject_id in node_ids
            and edge.object_id in node_ids
            and (edge_types is None or edge.edge_type in edge_types)
        ]

    def search_vulnerabilities(
        self,
        technology: str,
        *,
        from_year: int,
        to_year: int,
        limit: int = 100,
    ) -> list[VulnerabilitySearchMatch]:
        """Search source-backed CVE/GHSA product relations.

        This reference implementation keeps offline repositories useful. The
        Neo4j adapter overrides it with a bounded Cypher query so production
        searches do not export the entire graph to Python.
        """
        from ckg.graph.search import search_vulnerabilities

        return search_vulnerabilities(
            self.nodes(),
            self.edges(),
            technology=technology,
            from_year=from_year,
            to_year=to_year,
            limit=limit,
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
        """Optional push-down hook.

        In-memory fixtures return ``None`` and use the reference traversal.
        Production adapters must use this hook so query cardinality is bounded
        before graph data reaches the reasoning process.
        """
        return None
