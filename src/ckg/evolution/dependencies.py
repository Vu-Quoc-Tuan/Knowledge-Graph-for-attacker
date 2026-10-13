"""Track and invalidate derived knowledge without deleting provenance history."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository


@dataclass(frozen=True)
class InvalidationReport:
    source_id: str
    invalidated_ids: tuple[str, ...]


def record_dependency(repository: GraphRepository, *, dependent_id: str, source_id: str) -> None:
    repository.atomic_write(nodes=[], edges=[GraphEdge(edge_id=f"EDGE-DEPENDS-ON-{dependent_id}-{source_id}", edge_type="DEPENDS_ON", subject_id=dependent_id, object_id=source_id)])


def invalidate_dependents(repository: GraphRepository, *, source_id: str, reason: str, occurred_at: datetime | None = None) -> InvalidationReport:
    """Mark transitive derived nodes stale; canonical source nodes remain untouched."""
    reverse: dict[str, set[str]] = {}
    for edge in repository.edges("DEPENDS_ON"):
        reverse.setdefault(edge.object_id, set()).add(edge.subject_id)
    queue = [source_id]
    invalidated: set[str] = set()
    while queue:
        current = queue.pop()
        for dependent in reverse.get(current, set()):
            if dependent not in invalidated:
                invalidated.add(dependent)
                queue.append(dependent)
    timestamp = (occurred_at or datetime.now(timezone.utc)).isoformat()
    nodes = []
    edges = []
    for identifier in sorted(invalidated):
        dependent = next((node for node in repository.nodes() if node.node_id == identifier), None)
        event_id = "INVALIDATION-" + hashlib.sha256(f"{source_id}|{identifier}|{timestamp}".encode()).hexdigest()[:24]
        # Preserve immutable evidence/canonical records. Derived nodes are
        # projected as stale so retrieval/reasoning readers can exclude them
        # until their owning application workflow recomputes the projection.
        if dependent is not None and dependent.props.get("status") != "CANONICAL":
            nodes.append(
                GraphNode(
                    label=dependent.label,
                    node_id=dependent.node_id,
                    props={
                        **dependent.props,
                        "stale": True,
                        "invalidated_at": timestamp,
                        "invalidation_reason": reason,
                    },
                )
            )
        nodes.append(GraphNode(label="InvalidationEvent", node_id=event_id, props={"source_id": source_id, "dependent_id": identifier, "reason": reason, "occurred_at": timestamp, "status": "STALE"}))
        edges.append(GraphEdge(edge_id=f"EDGE-INVALIDATES-{event_id}", edge_type="INVALIDATES", subject_id=event_id, object_id=identifier))
    if nodes:
        repository.atomic_write(nodes=nodes, edges=edges)
    return InvalidationReport(source_id, tuple(sorted(invalidated)))
