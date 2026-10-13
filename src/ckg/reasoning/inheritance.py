from __future__ import annotations

from ckg.domain.enums.scenario_type import ScenarioType
from ckg.graph.ports import GraphRepository
from ckg.reasoning._graph import constraint_ids, list_prop, mapped_values
from ckg.scenario.composer import compose
from ckg.scenario.contract import ScenarioCandidate


def inherited_scenarios(repository: GraphRepository, vulnerability_id: str) -> tuple[ScenarioCandidate, ...]:
    weaknesses = mapped_values(repository, vulnerability_id, "HAS_WEAKNESS_ASSERTION")
    candidates = []
    for node in repository.nodes("Scenario"):
        if node.props.get("target_vulnerability_id") == vulnerability_id:
            continue
        lineage = set(list_prop(node.props.get("derivation_ids")))
        if vulnerability_id in lineage or node.node_id in lineage:
            continue
        source_weaknesses = set(list_prop(node.props.get("weakness_ids")))
        overlap = weaknesses & source_weaknesses
        if not overlap:
            continue
        candidates.append(compose(target_vulnerability_id=vulnerability_id, scenario_type=ScenarioType.INHERITED, weakness_ids=tuple(sorted(overlap)), technique_ids=list_prop(node.props.get("technique_ids")), channel_ids=list_prop(node.props.get("channel_ids")), context_ids=list_prop(node.props.get("context_ids")), oracle_ids=list_prop(node.props.get("oracle_ids")), constraint_ids=tuple(sorted(set(list_prop(node.props.get("constraint_ids"))) | set(constraint_ids(repository, vulnerability_id)))), relevance=0.70, evidence_coverage=0.45, historical_support=0.5, derivation_ids=(node.node_id,), premises=(f"shared weakness {','.join(sorted(overlap))}",), missing_bindings=tuple(sorted(set(list_prop(node.props.get("missing_bindings"))) | {"target_endpoint", "input_binding", "probe_binding"}))))
    return tuple(candidates)
