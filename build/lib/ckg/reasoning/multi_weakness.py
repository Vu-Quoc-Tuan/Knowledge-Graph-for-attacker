"""Classify multi-CWE evidence without composing independent labels."""

from __future__ import annotations

from enum import StrEnum

from ckg.graph.ports import GraphRepository


class MultiWeaknessKind(StrEnum):
    INDEPENDENT = "INDEPENDENT"
    CHAINED = "CHAINED"
    COMPOSITE = "COMPOSITE"


def classify(repository: GraphRepository, vulnerability_id: str) -> MultiWeaknessKind:
    groups = [node for node in repository.nodes("CompositionGroup") if node.props.get("vulnerability_id") == vulnerability_id and node.props.get("operator") == "ALL_OF"]
    if groups:
        return MultiWeaknessKind.COMPOSITE
    occurrences = {node.node_id for node in repository.nodes("WeaknessOccurrence") if node.props.get("vulnerability_id") == vulnerability_id}
    if any(edge.edge_type in {"ENABLES", "PRECEDES"} and edge.subject_id in occurrences and edge.object_id in occurrences for edge in repository.edges()):
        return MultiWeaknessKind.CHAINED
    return MultiWeaknessKind.INDEPENDENT
