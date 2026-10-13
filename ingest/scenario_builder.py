"""Compose Scenario nodes from what the authoritative loaders already proved.

A scenario is one detection family of a weakness, made concrete: the payloads to
send, an optional signal that confirms a hit, and optional WSTG methodology. It is
composed per slice, once against the `GraphSink` primitives, so the dry run and
Neo4j compose identically.

Methodology comes from whichever is more specific:

* a per-technology WSTG variant, if the slice has one (SQL injection ships
  05.x per DBMS), else
* the weakness's general WSTG test, mapped in through OpenCRE.

Technology is optional. SQL injection and template injection split payloads by
technology, so their scenarios carry one; a flat vuln (XSS, command injection)
has no technology dimension and yields one scenario for the whole family.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from utils.payloads import payload_is_eligible_for_weakness
from db.sink import GraphSink
from ingest.slices import VulnSlice
from schema.models import DetectionSignal, Scenario, is_bare_activity


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")


def _direct_methodology_ids(sink: GraphSink, weakness_id: str) -> list[str]:
    return sorted(
        {
            rel["to_value"]
            for rel in sink.match_rels(
                "TESTED_BY",
                from_label="Weakness",
                from_value=weakness_id,
                to_label="TestActivity",
            )
        }
    )


MethodologyRef = tuple[str, str, str]


def _descendants(sink: GraphSink, roots: list[str]) -> list[MethodologyRef]:
    """All official WSTG descendants reachable from directly mapped roots."""
    root_refs = {("TestActivity", "wstgId", value) for value in roots}
    found: set[MethodologyRef] = set()
    pending = list(root_refs)
    while pending:
        parent_label, _parent_key, parent_value = pending.pop()
        for rel_type in ("HAS_CHILD", "HAS_VARIANT"):
            for rel in sink.match_rels(
                rel_type,
                from_label=parent_label,
                from_value=parent_value,
            ):
                child = (
                    rel["to_label"],
                    rel["to_key"],
                    rel["to_value"],
                )
                if child not in found and child not in root_refs:
                    found.add(child)
                    pending.append(child)
    return sorted(found)


def _general_methodology(sink: GraphSink, weakness_id: str) -> list[str]:
    """The weakness's WSTG tests, minus the content-free pointers.

    A bare id (WSTG-INPV-00, a chapter OpenCRE names but no page backs) is not a
    methodology, so it must not become one just because a scenario needs a
    `DERIVED_FROM` target.
    """
    ids = _direct_methodology_ids(sink, weakness_id)
    kept = []
    for wstg_id in ids:
        node = sink.get_node("TestActivity", "wstgId", wstg_id)
        if node and not is_bare_activity(node):
            kept.append(wstg_id)
    return sorted(kept)


def _methodology_for(
    sink: GraphSink,
    weakness_id: str,
    technology: str | None,
) -> tuple[list[MethodologyRef], str]:
    """Best supported methodology plus whether it is direct or a descendant."""
    direct_ids = _direct_methodology_ids(sink, weakness_id)
    descendant_ids = _descendants(sink, direct_ids)
    usable_descendants: list[MethodologyRef] = []
    for label, key, value in descendant_ids:
        node = sink.get_node(label, key, value)
        if node and (
            label == "MethodologyPage" or not is_bare_activity(node)
        ):
            usable_descendants.append((label, key, value))

    if technology:
        matching = {
            (rel["from_label"], rel["from_key"], rel["from_value"])
            for label in ("TestActivity", "MethodologyPage")
            for rel in sink.match_rels(
                "ON_TECH", from_label=label,
                to_label="Technology", to_value=technology,
            )
        }
        specific = sorted(set(usable_descendants) & matching)
        if specific:
            return specific, "descendant"

    # An OpenCRE mapping to a WSTG category/index is a navigation root rather
    # than a usable testing page. Its official children are the methodology.
    if any(wstg_id.endswith("-00") for wstg_id in direct_ids):
        if usable_descendants:
            return sorted(usable_descendants), "descendant"

    direct = _general_methodology(sink, weakness_id)
    if direct:
        return [
            ("TestActivity", "wstgId", wstg_id) for wstg_id in direct
        ], "direct"
    if usable_descendants:
        return sorted(usable_descendants), "descendant"
    return [], "missing"


def _eligible_payload_families(
    sink: GraphSink,
    family_keys: set[str],
    weakness_id: str,
) -> dict[str, set[str]]:
    """Return family membership only for payloads valid for this weakness."""
    families_of_payload: dict[str, set[str]] = defaultdict(set)
    for rel in sink.match_rels(
        "IN_FAMILY", from_label="Payload", to_label="PayloadFamily"
    ):
        if (
            rel["to_value"] in family_keys
            and payload_is_eligible_for_weakness(
                sink,
                rel["from_value"],
                weakness_id,
            )
        ):
            families_of_payload[rel["from_value"]].add(rel["to_value"])
    return families_of_payload


def _family_technologies(
    sink: GraphSink,
    families_of_payload: dict[str, set[str]],
) -> dict[str, set[str]]:
    """For each of the slice's families, the technologies its payloads carry.

    Empty set for a flat family, whose payloads have no ON_TECH edge.
    """
    techs: dict[str, set[str]] = defaultdict(set)
    for rel in sink.match_rels("ON_TECH", from_label="Payload", to_label="Technology"):
        for family in families_of_payload.get(rel["from_value"], ()):
            techs[family].add(rel["to_value"])
    return techs


def compose_scenarios(sink: GraphSink, slice_: VulnSlice) -> dict[str, Any]:
    """Create one slice's scenarios and report what was left out."""
    weakness_id = slice_.weakness_id
    families = {spec.key: spec for spec in slice_.families}
    # The wordlist family is composed too. For a flat vuln it is already one of
    # `families`; for SQLi it is a separate technology-free generic family, and
    # if it is left out its wordlist payloads reach no scenario.
    if slice_.intruder_family is not None:
        families.setdefault(slice_.intruder_family.key, slice_.intruder_family)

    families_of_payload = _eligible_payload_families(
        sink,
        set(families),
        weakness_id,
    )
    families_with_payloads = {
        family
        for payload_families in families_of_payload.values()
        for family in payload_families
    }
    technologies_of = _family_technologies(
        sink,
        families_of_payload,
    )

    scenario_ids: set[str] = set()
    missing_methodology: set[str] = set()
    missing_detection_signal: set[str] = set()
    for family_key in sorted(families_with_payloads):
        spec = families[family_key]
        # A technology-split family yields one scenario per technology; a flat
        # one yields a single scenario with no technology (the () placeholder).
        technologies = sorted(technologies_of.get(family_key, set())) or [None]
        for technology in technologies:
            methodology, methodology_status = _methodology_for(
                sink, weakness_id, technology
            )
            suffix = f"{_slug(technology)}-" if technology else ""
            scenario_id = f"SCN-{weakness_id}-{suffix}{family_key}"
            signal = spec.detection_signal
            sink.merge_node(
                "Scenario",
                "scenarioId",
                Scenario(
                    scenarioId=scenario_id,
                    testReady=signal is not None,
                    methodologyStatus=methodology_status,
                    detectionSignalStatus=(
                        "strategy_hint" if signal else "missing"
                    ),
                ).to_props(),
            )
            sink.merge_rel(
                "Scenario", "scenarioId", scenario_id,
                "TARGETS", "Weakness", "weaknessId", weakness_id,
            )
            sink.merge_rel(
                "Scenario", "scenarioId", scenario_id,
                "USES", "PayloadFamily", "key", family_key,
            )
            if signal:
                sink.merge_node(
                    "DetectionSignal",
                    "key",
                    DetectionSignal(
                        key=signal,
                        name=signal.replace("_", " "),
                        trustLevel="strategy_hint",
                    ).to_props(),
                )
                sink.merge_rel(
                    "Scenario", "scenarioId", scenario_id,
                    "CONFIRMED_BY", "DetectionSignal", "key", signal,
                )
            else:
                missing_detection_signal.add(scenario_id)
            if technology:
                sink.merge_rel(
                    "Scenario", "scenarioId", scenario_id,
                    "ON_TECH", "Technology", "name", technology,
                )
            for label, key, value in methodology:
                sink.merge_rel(
                    "Scenario", "scenarioId", scenario_id,
                    "DERIVED_FROM", label, key, value,
                    {"mappingMode": methodology_status},
                )
            if not methodology:
                missing_methodology.add(scenario_id)
            scenario_ids.add(scenario_id)

    return {
        "cwe": weakness_id,
        "scenarios": len(scenario_ids),
        "scenarios_missing_methodology": sorted(missing_methodology),
        "scenarios_missing_detection_signal": sorted(
            missing_detection_signal
        ),
    }


def _reviewed_payload_scopes(
    sink: GraphSink,
) -> set[tuple[str, str, str | None]]:
    scopes: set[tuple[str, str, str | None]] = set()
    for target in sink.match_rels(
        "TARGETS", from_label="Payload", to_label="Weakness"
    ):
        weakness_id = target["to_value"]
        weakness = sink.get_node("Weakness", "weaknessId", weakness_id)
        if weakness is None or weakness.get("namespace") == "CWE":
            continue
        props = target["props"]
        if (
            props.get("source") != "local-human-review"
            or props.get("trustLevel") != "asserted"
            or props.get("validationStatus") != "tested"
        ):
            continue
        payload_id = target["from_value"]
        families = {
            relation["to_value"]
            for relation in sink.match_rels(
                "IN_FAMILY",
                from_label="Payload",
                from_value=payload_id,
                to_label="PayloadFamily",
            )
        }
        technologies = {
            relation["to_value"]
            for relation in sink.match_rels(
                "ON_TECH",
                from_label="Payload",
                from_value=payload_id,
                to_label="Technology",
            )
        } or {None}
        scopes.update(
            (weakness_id, family_key, technology)
            for family_key in families
            for technology in technologies
        )
    return scopes


def _accepted_oracles(
    sink: GraphSink,
) -> dict[tuple[str, str, str | None], list[str]]:
    accepted: dict[tuple[str, str, str | None], list[str]] = defaultdict(list)
    for signal in sink.nodes("DetectionSignal"):
        if signal.get("trustLevel") != "accepted":
            continue
        weakness_id = signal.get("weaknessId")
        family_key = signal.get("familyKey")
        if not weakness_id or not family_key:
            continue
        signal_id = signal["key"]
        targets = sink.match_rels(
            "TARGETS",
            from_label="DetectionSignal",
            from_value=signal_id,
            to_label="Weakness",
            to_value=weakness_id,
        )
        families = sink.match_rels(
            "APPLIES_TO_FAMILY",
            from_label="DetectionSignal",
            from_value=signal_id,
            to_label="PayloadFamily",
            to_value=family_key,
        )
        if not targets or not families:
            continue
        accepted[(weakness_id, family_key, signal.get("technology"))].append(
            signal_id
        )
    return accepted


def compose_reviewed_local_scenarios(sink: GraphSink) -> dict[str, Any]:
    """Compose local scenarios only from reviewed, weakness-specific material."""

    payload_scopes = _reviewed_payload_scopes(sink)
    oracles = _accepted_oracles(sink)
    composed: set[str] = set()
    missing_oracle: list[str] = []
    for weakness_id, family_key, technology in sorted(
        payload_scopes,
        key=lambda item: (item[0], item[1], item[2] or ""),
    ):
        signal_ids = sorted(
            set(oracles.get((weakness_id, family_key, technology), []))
            | set(oracles.get((weakness_id, family_key, None), []))
        )
        if not signal_ids:
            missing_oracle.append(
                f"{weakness_id}:{family_key}:{technology or 'generic'}"
            )
            continue
        suffix = f"{_slug(technology)}-" if technology else ""
        scenario_id = f"SCN-{weakness_id}-{suffix}{family_key}"
        sink.merge_node(
            "Scenario",
            "scenarioId",
            Scenario(
                scenarioId=scenario_id,
                testReady=True,
                methodologyStatus="missing",
                detectionSignalStatus="accepted",
            ).to_props(),
        )
        sink.merge_rel(
            "Scenario", "scenarioId", scenario_id,
            "TARGETS", "Weakness", "weaknessId", weakness_id,
            {"source": "reviewed-local-material", "trustLevel": "asserted"},
        )
        sink.merge_rel(
            "Scenario", "scenarioId", scenario_id,
            "USES", "PayloadFamily", "key", family_key,
            {"source": "reviewed-local-material"},
        )
        if technology:
            sink.merge_rel(
                "Scenario", "scenarioId", scenario_id,
                "ON_TECH", "Technology", "name", technology,
                {"source": "reviewed-local-material"},
            )
        for signal_id in signal_ids:
            sink.merge_rel(
                "Scenario", "scenarioId", scenario_id,
                "CONFIRMED_BY", "DetectionSignal", "key", signal_id,
                {"source": "oracle-registry", "trustLevel": "accepted"},
            )
        composed.add(scenario_id)
    return {
        "local_scenarios_composed": len(composed),
        "missing_oracle": missing_oracle,
    }
