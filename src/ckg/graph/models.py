from dataclasses import dataclass
from typing import Any

from pydantic import ConfigDict, Field

from ckg.domain.value_objects.base import DomainModel


class GraphNode(DomainModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    props: dict[str, Any]


class GraphEdge(DomainModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    edge_id: str = Field(min_length=1)
    edge_type: str = Field(min_length=1)
    subject_id: str = Field(min_length=1)
    object_id: str = Field(min_length=1)
    props: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class VulnerabilitySearchMatch:
    """A vulnerability and the source-backed products returned by a search."""

    vulnerability: GraphNode
    products: tuple[GraphNode, ...] = ()
    versions: tuple[GraphNode, ...] = ()
    sources: tuple[GraphNode, ...] = ()
    relevance: float = 0.0
    match_reason: str = "unranked"


@dataclass(frozen=True)
class BoundedNeighborhood:
    """A storage-bounded traversal result before reasoning-plane pruning."""

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    truncated: bool = False
