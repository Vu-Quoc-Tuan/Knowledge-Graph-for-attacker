from __future__ import annotations

from ckg.domain.enums.scenario_type import ScenarioType
from ckg.graph.ports import GraphRepository
from ckg.linking.historical.hybrid_retriever import HistoricalNeighbor
from ckg.reasoning._graph import list_prop, mapped_values
from ckg.scenario.composer import compose
from ckg.scenario.contract import ScenarioCandidate


def _has_dimension_conflict(target_contexts: set[str], source_contexts: set[str]) -> bool:
    target_by_dim: dict[str, set[str]] = {}
    for c in target_contexts:
        dim = c.split("-")[0] if "-" in c else "MISC"
        target_by_dim.setdefault(dim, set()).add(c)
    source_by_dim: dict[str, set[str]] = {}
    for c in source_contexts:
        dim = c.split("-")[0] if "-" in c else "MISC"
        source_by_dim.setdefault(dim, set()).add(c)
    for dim in ("LANG", "DBMS", "RUNTIME", "FRAMEWORK", "COMPONENT"):
        if dim in target_by_dim and dim in source_by_dim:
            if not (target_by_dim[dim] & source_by_dim[dim]):
                return True
    return False


def analogous_scenarios(repository: GraphRepository, vulnerability_id: str, neighbors: tuple[HistoricalNeighbor, ...]) -> tuple[ScenarioCandidate, ...]:
    target_weaknesses = mapped_values(repository, vulnerability_id, "HAS_WEAKNESS_ASSERTION")
    target_contexts = mapped_values(repository, vulnerability_id, "HAS_CONTEXT_ASSERTION")
    candidates: list[ScenarioCandidate] = []
    for neighbor in neighbors:
        for source in repository.nodes("Scenario"):
            if source.props.get("target_vulnerability_id") != neighbor.vulnerability_id:
                continue
            source_weaknesses = set(list_prop(source.props.get("weakness_ids")))
            overlap = target_weaknesses & source_weaknesses
            if not overlap:
                continue
            source_contexts = set(list_prop(source.props.get("context_ids")))
            # Context is a compatibility gate when both sides actually know
            # it. Absence remains uncertainty, not evidence of incompatibility.
            if target_contexts and source_contexts and not (target_contexts & source_contexts):
                continue
            if _has_dimension_conflict(target_contexts, source_contexts):
                continue
            candidates.append(compose(target_vulnerability_id=vulnerability_id, scenario_type=ScenarioType.ANALOGOUS, weakness_ids=tuple(sorted(overlap)), technique_ids=list_prop(source.props.get("technique_ids")), channel_ids=list_prop(source.props.get("channel_ids")), context_ids=list_prop(source.props.get("context_ids")), oracle_ids=list_prop(source.props.get("oracle_ids")), constraint_ids=list_prop(source.props.get("constraint_ids")), relevance=min(0.85, 0.45 + neighbor.score), evidence_coverage=0.45, historical_support=neighbor.score, derivation_ids=(source.node_id, neighbor.vulnerability_id), premises=(f"historical neighbor via {','.join(sorted(neighbor.sources))}", f"shared weakness {','.join(sorted(overlap))}"), missing_bindings=("target_endpoint", "input_binding", "probe_binding")))
    return tuple(candidates)
