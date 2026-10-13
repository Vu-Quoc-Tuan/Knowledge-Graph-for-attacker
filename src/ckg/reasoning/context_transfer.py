from __future__ import annotations

from ckg.domain.enums.scenario_type import ScenarioType
from ckg.graph.ports import GraphRepository
from ckg.reasoning._graph import constraint_ids, mapped_values, targets
from ckg.scenario.composer import compose
from ckg.scenario.contract import ScenarioCandidate


def transferable_test_strategies(repository: GraphRepository, vulnerability_id: str) -> tuple[ScenarioCandidate, ...]:
    """Transfer WSTG method semantics only when its explicit target CWE overlaps."""
    weakness_ids = mapped_values(repository, vulnerability_id, "HAS_WEAKNESS_ASSERTION")
    candidates = []
    for strategy in repository.nodes("TestStrategy"):
        targets_cwe = targets(repository, strategy.node_id, "TARGETS_WEAKNESS")
        overlap = weakness_ids & targets_cwe
        if not overlap:
            continue
        techniques = targets(repository, strategy.node_id, "USES_TECHNIQUE")
        channels = targets(repository, strategy.node_id, "USES_CHANNEL")
        oracles = targets(repository, strategy.node_id, "USES_ORACLE")
        candidates.append(compose(target_vulnerability_id=vulnerability_id, scenario_type=ScenarioType.NOVEL, weakness_ids=tuple(sorted(overlap)), technique_ids=tuple(sorted(techniques)), channel_ids=tuple(sorted(channels)), oracle_ids=tuple(sorted(oracles)), constraint_ids=constraint_ids(repository, vulnerability_id), relevance=0.65, evidence_coverage=0.40, derivation_ids=(strategy.node_id,), premises=(f"WSTG strategy explicitly targets {','.join(sorted(overlap))}",), missing_bindings=("target_endpoint", "input_binding", "probe_binding", "environment_snapshot")))
    return tuple(candidates)
