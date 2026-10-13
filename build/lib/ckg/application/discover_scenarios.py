"""Persist discovered semantic scenarios without generating executable bindings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ckg.constraints.evaluator import EnvironmentSnapshot
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.scenario.discoverer import discover_scenarios


@dataclass(frozen=True)
class DiscoverScenariosReport:
    scenario_count: int
    scenario_ids: tuple[str, ...]


def discover_and_materialize_scenarios(repository: GraphRepository, vulnerability_id: str, *, environment: EnvironmentSnapshot | None = None, as_of: datetime | None = None) -> DiscoverScenariosReport:
    candidates = discover_scenarios(repository, vulnerability_id, environment=environment, as_of=as_of)
    existing_ids = {node.node_id for node in repository.nodes()}
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    for candidate in candidates:
        scenario = candidate.scenario
        nodes.append(GraphNode(label="Scenario", node_id=scenario.scenario_id, props={**scenario.model_dump(mode="json"), "premises": list(candidate.premises), "evidence_ids": list(candidate.evidence_ids)}))
        edges.append(GraphEdge(edge_id=f"EDGE-SCENARIO-TARGETS-{scenario.scenario_id}", edge_type="TARGETS", subject_id=scenario.scenario_id, object_id=vulnerability_id))
        for derivation_id in scenario.derivation_ids:
            if derivation_id in existing_ids:
                edges.append(GraphEdge(edge_id=f"EDGE-SCENARIO-DERIVED-{scenario.scenario_id}-{derivation_id}", edge_type="DERIVED_FROM", subject_id=scenario.scenario_id, object_id=derivation_id))
                edges.append(GraphEdge(edge_id=f"EDGE-DEPENDS-ON-{scenario.scenario_id}-{derivation_id}", edge_type="DEPENDS_ON", subject_id=scenario.scenario_id, object_id=derivation_id))
    if nodes or edges:
        repository.atomic_write(nodes=nodes, edges=edges)
    return DiscoverScenariosReport(len(candidates), tuple(candidate.scenario.scenario_id for candidate in candidates))
