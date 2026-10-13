"""Creates semantic scenarios; it intentionally knows no target endpoint or payload."""

from __future__ import annotations

import hashlib
import json

from ckg.domain.entities.scenario import Scenario
from ckg.domain.enums.applicability import Applicability
from ckg.domain.enums.fact_status import FactStatus
from ckg.domain.enums.scenario_type import ScenarioType
from ckg.domain.value_objects.confidence import Confidence
from ckg.scenario.contract import ScenarioCandidate


def scenario_fingerprint(*, target_vulnerability_id: str, scenario_type: ScenarioType, weakness_ids: tuple[str, ...], technique_ids: tuple[str, ...], channel_ids: tuple[str, ...], context_ids: tuple[str, ...], oracle_ids: tuple[str, ...], constraint_ids: tuple[str, ...], derivation_ids: tuple[str, ...] = ()) -> str:
    is_chained = scenario_type == ScenarioType.CHAINED
    payload = {
        "target": target_vulnerability_id,
        "type": scenario_type.value,
        "weaknesses": list(weakness_ids) if is_chained else sorted(weakness_ids),
        "techniques": sorted(technique_ids),
        "channels": sorted(channel_ids),
        "contexts": sorted(context_ids),
        "oracles": sorted(oracle_ids),
        "constraints": sorted(constraint_ids),
        "steps": list(derivation_ids) if is_chained else sorted(derivation_ids),
    }
    return "SCN-" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]


def compose(*, target_vulnerability_id: str, scenario_type: ScenarioType, weakness_ids: tuple[str, ...], relevance: float, evidence_coverage: float, technique_ids: tuple[str, ...] = (), channel_ids: tuple[str, ...] = (), context_ids: tuple[str, ...] = (), oracle_ids: tuple[str, ...] = (), constraint_ids: tuple[str, ...] = (), applicability: Applicability = Applicability.UNKNOWN, historical_support: float | None = None, derivation_ids: tuple[str, ...] = (), premises: tuple[str, ...] = (), evidence_ids: tuple[str, ...] = (), missing_bindings: tuple[str, ...] = ("target_endpoint", "input_binding", "probe_binding"), title: str = "", description: str = "", steps: tuple[str, ...] = (), poc_command: str = "") -> ScenarioCandidate:
    if not derivation_ids or not premises:
        raise ValueError("a scenario must retain derivation identifiers and premises")
    is_chained = scenario_type == ScenarioType.CHAINED
    final_weaknesses = tuple(weakness_ids) if is_chained else tuple(sorted(set(weakness_ids)))
    final_derivations = tuple(derivation_ids) if is_chained else tuple(sorted(set(derivation_ids)))
    confidence = Confidence(relevance=relevance, evidence_coverage=evidence_coverage, historical_support=historical_support, final=min(relevance, evidence_coverage))
    scenario = Scenario(
        scenario_id=scenario_fingerprint(target_vulnerability_id=target_vulnerability_id, scenario_type=scenario_type, weakness_ids=final_weaknesses, technique_ids=technique_ids, channel_ids=channel_ids, context_ids=context_ids, oracle_ids=oracle_ids, constraint_ids=constraint_ids, derivation_ids=final_derivations),
        scenario_type=scenario_type,
        status=FactStatus.INFERRED,
        target_vulnerability_id=target_vulnerability_id,
        weakness_ids=final_weaknesses,
        technique_ids=tuple(sorted(set(technique_ids))),
        channel_ids=tuple(sorted(set(channel_ids))),
        context_ids=tuple(sorted(set(context_ids))),
        oracle_ids=tuple(sorted(set(oracle_ids))),
        constraint_ids=tuple(sorted(set(constraint_ids))),
        applicability=applicability,
        confidence=confidence,
        derivation_ids=final_derivations,
        missing_bindings=tuple(sorted(set(missing_bindings))),
        title=title,
        description=description,
        steps=steps,
        poc_command=poc_command,
    )
    return ScenarioCandidate(scenario=scenario, premises=tuple(sorted(set(premises))), evidence_ids=tuple(sorted(set(evidence_ids))), missing_bindings=scenario.missing_bindings)
