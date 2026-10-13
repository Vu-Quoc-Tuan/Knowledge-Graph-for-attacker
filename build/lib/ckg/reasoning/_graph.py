from __future__ import annotations

import json

from ckg.graph.ports import GraphRepository


def targets(repository: GraphRepository, source_id: str, relation: str) -> set[str]:
    return {edge.object_id for edge in repository.edges(relation) if edge.subject_id == source_id}


def mapped_values(repository: GraphRepository, vulnerability_id: str, assertion_relation: str) -> set[str]:
    assertions = targets(repository, vulnerability_id, assertion_relation)
    return {edge.object_id for edge in repository.edges("MAPS_TO") if edge.subject_id in assertions}


def constraint_ids(repository: GraphRepository, vulnerability_id: str) -> tuple[str, ...]:
    """Explicit target constraints attach to every discovered target scenario."""
    return tuple(sorted(targets(repository, vulnerability_id, "REQUIRES_CONSTRAINT")))


def list_prop(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return ()
    return tuple(str(item) for item in value) if isinstance(value, (tuple, list)) else ()
