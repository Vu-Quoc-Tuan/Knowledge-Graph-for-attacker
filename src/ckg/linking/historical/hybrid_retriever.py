from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ckg.graph.ports import GraphRepository
from ckg.linking.historical.candidate_generator import historical_candidate_sources
from ckg.linking.historical.reranker import fuse_sources
from ckg.reasoning.subgraph.builder import _visible


@dataclass(frozen=True)
class HistoricalNeighbor:
    vulnerability_id: str
    sources: frozenset[str]
    score: float


def retrieve_historical_neighbors(repository: GraphRepository, vulnerability_id: str, *, top_k: int = 30, as_of: datetime | None = None) -> tuple[HistoricalNeighbor, ...]:
    if top_k < 1:
        return ()
    nodes = {node.node_id: node for node in repository.nodes()}
    candidates = historical_candidate_sources(repository, vulnerability_id, as_of=as_of)
    ranked = [
        HistoricalNeighbor(identifier, sources, fuse_sources(sources))
        for identifier, sources in candidates.items()
        if identifier in nodes and _visible(nodes[identifier], as_of)
    ]
    return tuple(sorted(ranked, key=lambda item: (-item.score, item.vulnerability_id))[:top_k])
