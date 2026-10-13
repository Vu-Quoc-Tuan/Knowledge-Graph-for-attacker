from __future__ import annotations

from ckg.domain.enums.scenario_type import ScenarioType
from ckg.graph.ports import GraphRepository
from ckg.reasoning._graph import list_prop
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


def composite_scenarios(repository: GraphRepository, vulnerability_id: str) -> tuple[ScenarioCandidate, ...]:
    occurrences = {node.node_id: node for node in repository.nodes("WeaknessOccurrence") if node.props.get("vulnerability_id") == vulnerability_id}
    canonical_requires = {
        (edge.subject_id, edge.object_id)
        if edge.edge_type == "REQUIRES"
        else (edge.object_id, edge.subject_id)
        for edge in repository.edges()
        if edge.edge_type in {"REQUIRES", "REQUIRED_BY"}
    }
    candidates = []
    emitted: set[tuple[str, ...]] = set()
    for group in repository.nodes("CompositionGroup"):
        if group.props.get("vulnerability_id") != vulnerability_id or group.props.get("operator") != "ALL_OF":
            continue
        occurrence_ids = list_prop(group.props.get("occurrence_ids"))
        members = [occurrences[item] for item in occurrence_ids if item in occurrences]
        if len(members) != len(occurrence_ids) or len(members) < 2 or not _has_spans(group.props, repository) or not all(_has_spans(member.props, repository) for member in members):
            continue
        weakness_ids = tuple(sorted({str(member.props.get("cwe_id")) for member in members}))
        if len(weakness_ids) < 2:
            continue
        has_canonical = any(
            (w1, w2) in canonical_requires or (w2, w1) in canonical_requires
            for i, w1 in enumerate(weakness_ids)
            for w2 in weakness_ids[i + 1:]
        )
        if not has_canonical:
            continue
        emitted.add(weakness_ids)
        candidates.append(compose(target_vulnerability_id=vulnerability_id, scenario_type=ScenarioType.COMPOSITE, weakness_ids=weakness_ids, relevance=0.75, evidence_coverage=0.60, derivation_ids=(group.node_id, *occurrence_ids), premises=("explicit ALL_OF occurrence composition",), missing_bindings=("target_endpoint", "input_binding", "probe_binding")))
    for edge in repository.edges("REQUIRED_TOGETHER"):
        if edge.subject_id not in occurrences or edge.object_id not in occurrences:
            continue
        left, right = occurrences[edge.subject_id], occurrences[edge.object_id]
        if not (_has_spans(left.props, repository) and _has_spans(right.props, repository) and _has_spans(edge.props, repository)):
            continue
        ordered_pair = (str(left.props.get("cwe_id")), str(right.props.get("cwe_id")))
        weakness_ids = tuple(sorted(set(ordered_pair)))
        if len(weakness_ids) != 2 or weakness_ids in emitted or ordered_pair not in canonical_requires:
            continue
        emitted.add(weakness_ids)
        candidates.append(compose(
            target_vulnerability_id=vulnerability_id,
            scenario_type=ScenarioType.COMPOSITE,
            weakness_ids=weakness_ids,
            relevance=0.72,
            evidence_coverage=0.55,
            derivation_ids=(left.node_id, right.node_id, edge.edge_id),
            premises=("instance required-together relation", "canonical composite relation"),
            missing_bindings=("target_endpoint", "input_binding", "probe_binding"),
        ))
    return tuple(candidates)
