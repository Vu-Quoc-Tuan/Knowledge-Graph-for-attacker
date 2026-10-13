from collections import deque
from datetime import datetime, timezone
from typing import Any

from utils.payloads import (
    ASSERTED_TRUST_LEVEL,
    LOCAL_REVIEW_PAYLOAD_SOURCE,
    TESTED_VALIDATION_STATUS,
    payload_is_eligible_for_weakness,
)
from db.sink import GraphSink
from schema.models import is_bare_activity


def _plain(node: dict[str, Any] | None) -> dict[str, Any] | None:
    if node is None:
        return None
    stripped = dict(node)
    stripped.pop("_label", None)
    return stripped


def _nodes_by_id(
    sink: GraphSink, label: str, key: str, values: list[Any]
) -> list[dict[str, Any]]:
    found = (_plain(sink.get_node(label, key, value)) for value in values)
    return [node for node in found if node]


def _methodology_descendants(
    sink: GraphSink, root_ids: list[str]
) -> list[dict[str, Any]]:
    """Usable WSTG descendants with their path back to a direct mapping.

    A descendant is document structure proved by OWASP WSTG, not another
    OpenCRE assertion. The traversal therefore returns provenance metadata but
    never writes a TESTED_BY edge. It operates once per direct root so a caller
    can see which mapping exposed a node when multiple roots converge.
    """
    root_refs = {
        ("TestActivity", "wstgId", root_id) for root_id in root_ids
    }
    output: list[dict[str, Any]] = []

    for root_id in sorted(root_ids):
        root_ref = ("TestActivity", "wstgId", root_id)
        expanded = {root_ref}
        pending = deque([(root_ref, 0)])
        best: dict[
            tuple[str, str, str],
            tuple[int, str, str],
        ] = {}

        while pending:
            (parent_label, _parent_key, parent_value), parent_depth = (
                pending.popleft()
            )
            candidates = []
            for relation in ("HAS_CHILD", "HAS_VARIANT"):
                candidates.extend(
                    (
                        relation,
                        rel["to_label"],
                        rel["to_key"],
                        rel["to_value"],
                    )
                    for rel in sink.match_rels(
                        relation,
                        from_label=parent_label,
                        from_value=parent_value,
                    )
                    if rel["to_label"] in {
                        "TestActivity", "MethodologyPage"
                    }
                )

            for relation, label, key, value in sorted(candidates):
                child_ref = (label, key, value)
                depth = parent_depth + 1
                existing = best.get(child_ref)
                preferred = (
                    existing is None
                    or depth < existing[0]
                    or (
                        depth == existing[0]
                        and relation == "HAS_VARIANT"
                        and existing[2] != "HAS_VARIANT"
                    )
                )
                # A root mapped directly to this weakness belongs only in the
                # direct `methodology` field, even if another root reaches it.
                if child_ref not in root_refs and preferred:
                    best[child_ref] = (depth, parent_value, relation)
                if child_ref not in expanded:
                    expanded.add(child_ref)
                    pending.append((child_ref, depth))

        for (label, key, value), (
            depth, parent, relation
        ) in sorted(
            best.items(),
            key=lambda item: (
                item[1][0], str(item[0][2]), item[1][2]
            ),
        ):
            node = _plain(sink.get_node(label, key, value))
            if not node:
                continue
            if label == "TestActivity" and is_bare_activity(node):
                continue
            technologies = sorted(
                rel["to_value"]
                for rel in sink.match_rels(
                    "ON_TECH",
                    from_label=label,
                    from_value=value,
                    to_label="Technology",
                )
            )
            output.append(
                {
                    **node,
                    "mappingMode": "descendant",
                    "via": root_id,
                    "depth": depth,
                    "parent": parent,
                    "relation": relation,
                    "technologies": technologies,
                }
            )

    return sorted(
        output,
        key=lambda item: (
            item["via"],
            item["depth"],
            str(item.get("wstgId") or item.get("sourcePage") or ""),
            item["relation"],
        ),
    )


def children_of(sink: GraphSink, weakness_id: str) -> list[dict[str, Any]]:
    rels = sink.match_rels(
        "CHILD_OF", from_label="Weakness", to_label="Weakness", to_value=weakness_id
    )
    children = _nodes_by_id(
        sink, "Weakness", "weaknessId", [rel["from_value"] for rel in rels]
    )
    return sorted(children, key=lambda item: item["weaknessId"])


def parents_of(sink: GraphSink, weakness_id: str) -> list[dict[str, Any]]:
    rels = sink.match_rels(
        "CHILD_OF", from_label="Weakness", from_value=weakness_id, to_label="Weakness"
    )
    parents = _nodes_by_id(
        sink, "Weakness", "weaknessId", [rel["to_value"] for rel in rels]
    )
    return sorted(parents, key=lambda item: item["weaknessId"])


def scenarios_of(sink: GraphSink, weakness_id: str) -> list[dict[str, Any]]:
    rels = sink.match_rels(
        "TARGETS", from_label="Scenario", to_label="Weakness", to_value=weakness_id
    )
    scenarios = _nodes_by_id(
        sink, "Scenario", "scenarioId", [rel["from_value"] for rel in rels]
    )
    return sorted(scenarios, key=lambda item: item["scenarioId"])


def _exposure_metadata(
    relation: dict[str, Any],
    related_weakness_id: str,
) -> dict[str, Any]:
    props = relation["props"]
    dimensions = list(props.get("dimensions") or [])
    if props.get("dimension") and props["dimension"] not in dimensions:
        dimensions.append(props["dimension"])
    rationales = list(props.get("rationales") or [])
    if props.get("rationale") and props["rationale"] not in rationales:
        rationales.append(props["rationale"])
    proposal_ids = list(props.get("proposalIds") or [])
    if props.get("proposalId") and props["proposalId"] not in proposal_ids:
        proposal_ids.append(props["proposalId"])
    asserted_by = props.get("assertedBy")
    asserted_at = props.get("assertedAt")
    return {
        "predicate": relation["type"],
        "relatedWeaknessId": related_weakness_id,
        "dimensions": dimensions,
        "proposalIds": proposal_ids,
        "rationales": rationales,
        "evidenceSourceRefs": list(
            props.get("evidenceSourceRefs") or []
        ),
        "evidenceExcerpts": list(props.get("evidenceExcerpts") or []),
        "provenance": {
            "source": props.get("source"),
            "trustLevel": props.get("trustLevel"),
            "assertedBy": (
                list(asserted_by)
                if isinstance(asserted_by, list)
                else ([asserted_by] if asserted_by else [])
            ),
            "assertedAt": (
                list(asserted_at)
                if isinstance(asserted_at, list)
                else ([asserted_at] if asserted_at else [])
            ),
        },
    }


def _reference_exposures(
    sink: GraphSink,
    weakness_id: str,
) -> list[tuple[str, dict[str, Any]]]:
    relations = [
        *sink.match_rels(
            "CHILD_OF",
            from_label="Weakness",
            from_value=weakness_id,
            to_label="Weakness",
        ),
        *sink.match_rels(
            "SIMILAR_TO",
            from_label="Weakness",
            from_value=weakness_id,
            to_label="Weakness",
        ),
        *sink.match_rels(
            "SIMILAR_TO",
            from_label="Weakness",
            to_label="Weakness",
            to_value=weakness_id,
        ),
    ]
    exposures: dict[tuple[str, str, str], tuple[str, dict[str, Any]]] = {}
    for relation in relations:
        if relation["props"].get("trustLevel") != "asserted":
            continue
        related_id = (
            relation["to_value"]
            if relation["from_value"] == weakness_id
            else relation["from_value"]
        )
        key = (relation["type"], relation["from_value"], relation["to_value"])
        exposures[key] = (
            related_id,
            _exposure_metadata(relation, related_id),
        )
    return [exposures[key] for key in sorted(exposures)]


def asserted_relations_of(
    sink: GraphSink,
    weakness_id: str,
) -> list[dict[str, Any]]:
    relations = [
        *sink.match_rels(
            "CHILD_OF", from_label="Weakness", from_value=weakness_id,
            to_label="Weakness",
        ),
        *sink.match_rels(
            "CHILD_OF", from_label="Weakness", to_label="Weakness",
            to_value=weakness_id,
        ),
        *sink.match_rels(
            "SIMILAR_TO", from_label="Weakness", from_value=weakness_id,
            to_label="Weakness",
        ),
        *sink.match_rels(
            "SIMILAR_TO", from_label="Weakness", to_label="Weakness",
            to_value=weakness_id,
        ),
    ]
    found: dict[tuple[str, str, str], dict[str, Any]] = {}
    for relation in relations:
        props = relation["props"]
        if props.get("source") == "local-human-review" and (
            props.get("trustLevel") != "asserted"
        ):
            continue
        related_id = (
            relation["to_value"]
            if relation["from_value"] == weakness_id
            else relation["from_value"]
        )
        key = (relation["type"], relation["from_value"], relation["to_value"])
        found[key] = {
            "subjectWeaknessId": relation["from_value"],
            "objectWeaknessId": relation["to_value"],
            **_exposure_metadata(relation, related_id),
        }
    return [found[key] for key in sorted(found)]


def reference_methodologies_of(
    sink: GraphSink,
    weakness_id: str,
) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    for related_id, exposure in _reference_exposures(sink, weakness_id):
        methodology_ids = sorted(
            rel["to_value"]
            for rel in sink.match_rels(
                "TESTED_BY", from_label="Weakness", from_value=related_id,
                to_label="TestActivity",
            )
        )
        for methodology in _nodes_by_id(
            sink, "TestActivity", "wstgId", methodology_ids
        ):
            if is_bare_activity(methodology):
                continue
            references.append(
                {
                    "applicability": "unknown",
                    "relatedWeaknessId": related_id,
                    "mappingMode": "direct",
                    "methodology": methodology,
                    "exposedBy": exposure,
                }
            )
        for methodology in _methodology_descendants(sink, methodology_ids):
            references.append(
                {
                    "applicability": "unknown",
                    "relatedWeaknessId": related_id,
                    "mappingMode": "descendant",
                    "methodology": methodology,
                    "exposedBy": exposure,
                }
            )
    return sorted(
        references,
        key=lambda item: (
            item["relatedWeaknessId"],
            str(
                item["methodology"].get("wstgId")
                or item["methodology"].get("sourcePage")
                or ""
            ),
            item["mappingMode"],
        ),
    )


def reference_scenarios_of(
    sink: GraphSink,
    weakness_id: str,
) -> list[dict[str, Any]]:
    references = []
    for related_id, exposure in _reference_exposures(sink, weakness_id):
        for scenario in scenarios_of(sink, related_id):
            references.append(
                {
                    "applicability": "unknown",
                    "relatedWeaknessId": related_id,
                    "scenario": scenario,
                    "exposedBy": exposure,
                }
            )
    return sorted(
        references,
        key=lambda item: (
            item["relatedWeaknessId"], item["scenario"]["scenarioId"]
        ),
    )


def weakness_card(sink: GraphSink, weakness_id: str) -> dict[str, Any] | None:
    """Everything grounded about one authoritative or local weakness.

    Definition-only weaknesses return explicit empty enrichment lists. They do
    not borrow methodology, payloads, or scenarios from a similarly named CWE.
    """
    weakness = _plain(sink.get_node("Weakness", "weaknessId", weakness_id))
    if not weakness:
        return None

    methodology_ids = [
        rel["to_value"]
        for rel in sink.match_rels(
            "TESTED_BY",
            from_label="Weakness",
            from_value=weakness_id,
            to_label="TestActivity",
        )
    ]
    activities = _nodes_by_id(sink, "TestActivity", "wstgId", methodology_ids)

    return {
        "weaknessId": weakness_id,
        "namespace": weakness.get("namespace"),
        "externalId": weakness.get("externalId"),
        "cweId": weakness.get("cweId"),
        "name": weakness.get("name"),
        "abstraction": weakness.get("abstraction"),
        "summary": weakness.get("summary"),
        "lifecycleStatus": weakness.get("lifecycleStatus"),
        "origin": weakness.get("origin"),
        "webTestable": weakness.get("webTestable"),
        "provenance": {
            "sourceType": weakness.get("sourceType"),
            "sourceUrl": weakness.get("sourceUrl"),
            "sourceTitle": weakness.get("sourceTitle"),
            "sourceHash": weakness.get("sourceHash"),
            "sourceSnapshot": weakness.get("sourceSnapshot"),
            "sourceExcerpt": weakness.get("sourceExcerpt"),
            "declaredBy": weakness.get("declaredBy"),
        },
        "risk": {
            "likelihoodOfExploit": weakness.get("likelihoodOfExploit"),
            "top25Rank": weakness.get("top25Rank"),
            "top25Score": weakness.get("top25Score"),
            "kevCount": weakness.get("kevCount"),
        },
        "detection": {
            "methods": weakness.get("detectionMethods") or [],
            "mitigations": weakness.get("mitigations") or [],
            "applicablePlatforms": weakness.get("applicablePlatforms") or [],
            "demonstrativeExamples": weakness.get("demonstrativeExamples") or [],
        },
        "affectedTechnologies": affected_technologies_of(
            sink, weakness_id
        ),
        "parents": [
            item["weaknessId"] for item in parents_of(sink, weakness_id)
        ],
        "children": [
            item["weaknessId"] for item in children_of(sink, weakness_id)
        ],
        "methodology": [
            node for node in activities if not is_bare_activity(node)
        ],
        "methodologyDescendants": _methodology_descendants(
            sink, methodology_ids
        ),
        # Ids OpenCRE mapped that no WSTG page backs, named rather than dropped:
        # a shortened methodology list on its own reads as "WSTG has no test for
        # this", which is a different claim from "the mapping exists but carries
        # no content". An empty node in `methodology` said neither.
        "unsourcedMethodology": sorted(
            node["wstgId"] for node in activities if is_bare_activity(node)
        ),
        "assertedRelations": asserted_relations_of(sink, weakness_id),
        "referenceMethodologies": reference_methodologies_of(
            sink, weakness_id
        ),
        "referenceScenarios": reference_scenarios_of(sink, weakness_id),
        "scenarios": scenarios_of(sink, weakness_id),
        "reviewedPayloads": reviewed_payloads_of(
            sink,
            weakness_id,
        ),
    }


def technologies_of(sink: GraphSink, weakness_id: str) -> list[str]:
    """The technologies this weakness has scenarios for.

    Lets a caller enumerate the slice instead of naming a technology it hopes is
    there: `build.py` used to print an example for a hardcoded "PostgreSQL",
    which silently became an empty list for any other slice CWE.
    """
    scenario_ids = {item["scenarioId"] for item in scenarios_of(sink, weakness_id)}
    return sorted(
        {
            rel["to_value"]
            for rel in sink.match_rels(
                "ON_TECH", from_label="Scenario", to_label="Technology"
            )
            if rel["from_value"] in scenario_ids
        }
    )


def affected_technologies_of(
    sink: GraphSink, weakness_id: str
) -> list[str]:
    """Technologies asserted directly on a weakness definition."""

    return sorted(
        rel["to_value"]
        for rel in sink.match_rels(
            "AFFECTS_TECHNOLOGY",
            from_label="Weakness",
            from_value=weakness_id,
            to_label="Technology",
        )
    )


def relation_proposals(
    sink: GraphSink,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Current folded proposal nodes, optionally filtered by review status."""

    proposals = [
        node
        for node in (
            _plain(item)
            for item in sink.nodes("RelationProposal")
        )
        if node is not None
    ]
    if status is not None:
        proposals = [
            proposal
            for proposal in proposals
            if proposal.get("status") == status
        ]
    return sorted(
        proposals,
        key=lambda proposal: proposal["proposalId"],
    )


def _event_sort_key(event: dict[str, Any]) -> tuple[datetime, str]:
    occurred_at = str(event["occurredAt"])
    parsed = datetime.fromisoformat(
        occurred_at.replace("Z", "+00:00")
    )
    return (
        parsed.astimezone(timezone.utc),
        str(event["eventId"]),
    )


def review_history(
    sink: GraphSink,
    proposal_id: str,
) -> list[dict[str, Any]]:
    """Immutable proposal events in chronological order."""

    event_ids = [
        relation["from_value"]
        for relation in sink.match_rels(
            "APPLIES_TO",
            from_label="RelationEvent",
            to_label="RelationProposal",
            to_value=proposal_id,
        )
    ]
    events = _nodes_by_id(
        sink,
        "RelationEvent",
        "eventId",
        event_ids,
    )
    return sorted(events, key=_event_sort_key)


def relation_proposal(
    sink: GraphSink,
    proposal_id: str,
) -> dict[str, Any] | None:
    """One proposal with direct endpoint cards and immutable review history."""

    proposal = _plain(
        sink.get_node(
            "RelationProposal",
            "proposalId",
            proposal_id,
        )
    )
    if proposal is None:
        return None
    return {
        **proposal,
        "subject": weakness_card(
            sink, proposal["subjectWeaknessId"]
        ),
        "object": weakness_card(
            sink, proposal["objectWeaknessId"]
        ),
        "reviewHistory": review_history(
            sink, proposal_id
        ),
    }


def payload_proposals(
    sink: GraphSink,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Current extracted-payload proposal states."""

    proposals = [
        node
        for node in (
            _plain(item)
            for item in sink.nodes("PayloadProposal")
        )
        if node is not None
    ]
    if status is not None:
        proposals = [
            proposal
            for proposal in proposals
            if proposal.get("status") == status
        ]
    return sorted(
        proposals,
        key=lambda proposal: proposal["proposalId"],
    )


def payload_review_history(
    sink: GraphSink,
    proposal_id: str,
) -> list[dict[str, Any]]:
    """Immutable payload events in chronological order."""

    event_ids = [
        relation["from_value"]
        for relation in sink.match_rels(
            "APPLIES_TO",
            from_label="PayloadEvent",
            to_label="PayloadProposal",
            to_value=proposal_id,
        )
    ]
    events = _nodes_by_id(
        sink,
        "PayloadEvent",
        "eventId",
        event_ids,
    )
    return sorted(events, key=_event_sort_key)


def payload_proposal(
    sink: GraphSink,
    proposal_id: str,
) -> dict[str, Any] | None:
    """One extracted-payload proposal with evidence history."""

    proposal = _plain(
        sink.get_node(
            "PayloadProposal",
            "proposalId",
            proposal_id,
        )
    )
    if proposal is None:
        return None
    return {
        **proposal,
        "weakness": weakness_card(
            sink,
            proposal["weaknessId"],
        ),
        "reviewHistory": payload_review_history(
            sink,
            proposal_id,
        ),
    }


def reviewed_payloads_of(
    sink: GraphSink,
    weakness_id: str,
    family_key: str | None = None,
    technology: str | None = None,
) -> list[dict[str, Any]]:
    """Accepted, tested payload assertions for one Weakness."""

    if sink.get_node(
        "Weakness",
        "weaknessId",
        weakness_id,
    ) is None:
        return []
    reviewed = []
    for relation in sink.match_rels(
        "TARGETS",
        from_label="Payload",
        to_label="Weakness",
        to_value=weakness_id,
    ):
        props = relation["props"]
        if (
            props.get("source") != LOCAL_REVIEW_PAYLOAD_SOURCE
            or props.get("trustLevel") != ASSERTED_TRUST_LEVEL
            or props.get("validationStatus")
            != TESTED_VALIDATION_STATUS
        ):
            continue
        payload_id = relation["from_value"]
        payload = _plain(
            sink.get_node(
                "Payload",
                "payloadId",
                payload_id,
            )
        )
        if payload is None:
            continue
        family_edges = sink.match_rels(
            "IN_FAMILY",
            from_label="Payload",
            from_value=payload_id,
            to_label="PayloadFamily",
        )
        if not family_edges:
            continue
        payload_family_key = family_edges[0]["to_value"]
        if (
            family_key is not None
            and payload_family_key != family_key
        ):
            continue
        family = _plain(
            sink.get_node(
                "PayloadFamily",
                "key",
                payload_family_key,
            )
        )
        if family is None:
            continue
        technologies = sorted(
            edge["to_value"]
            for edge in sink.match_rels(
                "ON_TECH",
                from_label="Payload",
                from_value=payload_id,
                to_label="Technology",
            )
        )
        if (
            technology is not None
            and technology not in technologies
        ):
            continue
        reviewed.append(
            {
                **payload,
                "family": family,
                "technologies": technologies,
                "assertion": dict(props),
            }
        )
    return sorted(
        reviewed,
        key=lambda payload: payload["payloadId"],
    )


def similar_weaknesses(
    sink: GraphSink,
    weakness_id: str,
    dimension: str | None = None,
) -> list[dict[str, Any]]:
    """Reviewed symmetric similarity, independent of stored edge direction."""

    if sink.get_node(
        "Weakness", "weaknessId", weakness_id
    ) is None:
        return []

    matches: dict[str, dict[str, Any]] = {}
    candidates = [
        *sink.match_rels(
            "SIMILAR_TO",
            from_label="Weakness",
            from_value=weakness_id,
            to_label="Weakness",
        ),
        *sink.match_rels(
            "SIMILAR_TO",
            from_label="Weakness",
            to_label="Weakness",
            to_value=weakness_id,
        ),
    ]
    for relation in candidates:
        props = relation["props"]
        dimensions = list(props.get("dimensions") or [])
        if props.get("trustLevel") != "asserted":
            continue
        if dimension is not None and dimension not in dimensions:
            continue
        other_id = (
            relation["to_value"]
            if relation["from_value"] == weakness_id
            else relation["from_value"]
        )
        weakness = _plain(
            sink.get_node(
                "Weakness",
                "weaknessId",
                other_id,
            )
        )
        if weakness is None:
            continue
        matches[other_id] = {
            **weakness,
            "similarity": {
                "source": props.get("source"),
                "trustLevel": props["trustLevel"],
                "dimensions": dimensions,
                "proposalIds": list(
                    props.get("proposalIds") or []
                ),
            },
        }
    return [
        matches[weakness_id]
        for weakness_id in sorted(matches)
    ]


def scenarios_for_tech(
    sink: GraphSink, weakness_id: str, technology: str
) -> list[dict[str, Any]]:
    on_tech = {
        rel["from_value"]
        for rel in sink.match_rels(
            "ON_TECH",
            from_label="Scenario",
            to_label="Technology",
            to_value=technology,
        )
    }
    return [
        scenario
        for scenario in scenarios_of(sink, weakness_id)
        if scenario["scenarioId"] in on_tech
    ]


def _payload_ids_for(
    sink: GraphSink, rel_type: str, to_label: str, to_values: list[str]
) -> set[str]:
    return {
        rel["from_value"]
        for value in to_values
        for rel in sink.match_rels(
            rel_type, from_label="Payload", to_label=to_label, to_value=value
        )
    }


def scenario_card(sink: GraphSink, scenario_id: str) -> dict[str, Any] | None:
    """Compact GraphRAG card: only the subgraph an LLM needs for one scenario."""
    scenario = _plain(sink.get_node("Scenario", "scenarioId", scenario_id))
    if not scenario:
        return None

    def linked(rel_type: str, to_label: str) -> list[str]:
        return sorted(
            rel["to_value"]
            for rel in sink.match_rels(
                rel_type,
                from_label="Scenario",
                from_value=scenario_id,
                to_label=to_label,
            )
        )

    weaknesses = linked("TARGETS", "Weakness")
    technologies = linked("ON_TECH", "Technology")
    families = linked("USES", "PayloadFamily")
    methodology_ids = linked("DERIVED_FROM", "TestActivity")
    methodology_pages = linked("DERIVED_FROM", "MethodologyPage")
    detection_signals = linked("CONFIRMED_BY", "DetectionSignal")

    # Which payloads belong on the card. For a technology-split scenario, a
    # payload must be in the family *and* on that technology, so a MySQL card
    # does not show PostgreSQL payloads. For a flat scenario (no technology), the
    # family is the only filter -- requiring a technology here would show none.
    in_family = _payload_ids_for(sink, "IN_FAMILY", "PayloadFamily", families)
    if technologies:
        on_tech = _payload_ids_for(sink, "ON_TECH", "Technology", technologies)
        payload_ids = in_family & on_tech
    else:
        payload_ids = in_family
    if weaknesses:
        payload_ids = {
            payload_id
            for payload_id in payload_ids
            if any(
                payload_is_eligible_for_weakness(
                    sink,
                    payload_id,
                    weakness_id,
                )
                for weakness_id in weaknesses
            )
        }
    payload_nodes = sorted(
        _nodes_by_id(sink, "Payload", "payloadId", sorted(payload_ids)),
        key=lambda item: item["payloadId"],
    )
    methodology = (
        _nodes_by_id(sink, "TestActivity", "wstgId", methodology_ids)
        + _nodes_by_id(
            sink, "MethodologyPage", "sourcePage", methodology_pages
        )
    )
    methodology.sort(
        key=lambda node: str(node.get("wstgId") or node.get("sourcePage") or "")
    )
    weakness_nodes = _nodes_by_id(
        sink, "Weakness", "weaknessId", weaknesses
    )

    return {
        "scenarioId": scenario_id,
        "testReady": scenario.get("testReady", False),
        "targets": weaknesses,
        "technology": technologies,
        "methodology": methodology,
        "payloadFamilies": families,
        "payloads": sorted(node["value"] for node in payload_nodes),
        "payloadEvidence": payload_nodes,
        "detectionSignals": detection_signals,
        "methodologyStatus": scenario.get("methodologyStatus", "missing"),
        "detectionSignalStatus": scenario.get(
            "detectionSignalStatus", "missing"
        ),
        "confidence": scenario.get("confidence"),
        "provenance": {
            "weakness": [
                node["sourceUrl"]
                for node in weakness_nodes
                if node.get("sourceUrl")
            ],
            "methodology": [
                node["url"] for node in methodology if node.get("url")
            ],
            "payloads": sorted(
                {
                    node["sourceUrl"]
                    for node in payload_nodes
                    if node.get("sourceUrl")
                }
            ),
        },
    }
