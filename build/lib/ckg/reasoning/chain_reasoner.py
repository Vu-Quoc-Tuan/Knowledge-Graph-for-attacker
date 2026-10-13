from __future__ import annotations

from ckg.domain.enums.scenario_type import ScenarioType
from ckg.graph.ports import GraphRepository
from ckg.scenario.composer import compose
from ckg.scenario.contract import ScenarioCandidate


def _has_spans(props: dict, repository: GraphRepository | None = None) -> bool:
    spans = props.get("evidence_spans")
    if not isinstance(spans, list) or not spans:
        return False
    for item in spans:
        if not isinstance(item, dict) or not item:
            return False
        evidence_id = item.get("evidence_id")
        locator = item.get("locator")
        if not evidence_id and not locator:
            return False
        if repository is not None and evidence_id:
            evi_nodes = [n for n in repository.nodes("Evidence") if n.node_id == evidence_id]
            if evi_nodes:
                expected_digest = item.get("content_digest")
                if expected_digest and evi_nodes[0].props.get("content_digest") != expected_digest:
                    return False
    return True


def chained_scenarios(repository: GraphRepository, vulnerability_id: str) -> tuple[ScenarioCandidate, ...]:
    occurrences = {node.node_id: node for node in repository.nodes("WeaknessOccurrence") if node.props.get("vulnerability_id") == vulnerability_id}
    canonical = {
        (edge.subject_id, edge.object_id)
        if edge.edge_type == "CAN_PRECEDE"
        else (edge.object_id, edge.subject_id)
        for edge in repository.edges()
        if edge.edge_type in {"CAN_PRECEDE", "CAN_FOLLOW"}
    }
    candidates = []
    for edge in repository.edges():
        if edge.edge_type not in {"ENABLES", "PRECEDES"} or edge.subject_id not in occurrences or edge.object_id not in occurrences:
            continue
        before, after = occurrences[edge.subject_id], occurrences[edge.object_id]
        if not (_has_spans(before.props, repository) and _has_spans(after.props, repository) and _has_spans(edge.props, repository)):
            continue
        pair = (str(before.props.get("cwe_id")), str(after.props.get("cwe_id")))
        # The CWE schema relations encode direction. Treating the reverse pair
        # as equivalent permits an impossible attack sequence.
        if pair not in canonical:
            continue
        candidates.append(compose(target_vulnerability_id=vulnerability_id, scenario_type=ScenarioType.CHAINED, weakness_ids=pair, relevance=0.75, evidence_coverage=0.55, derivation_ids=(before.node_id, after.node_id, edge.edge_id), premises=("instance occurrence sequence", "canonical chain relation"), missing_bindings=("target_endpoint", "input_binding", "probe_binding")))
    return tuple(candidates)
