"""Incremental materialization for evolving knowledge graph updates (Write Path)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from db.sink import GraphSink
from ingest.vulnerability_loader import VulnerabilityEntry
from proposals.scenario_models import (
    ScenarioValidationRecord,
    ValidatedScenarioRecord,
)
from schema.models import (
    Component,
    Evidence,
    Product,
    VersionRange,
    Vulnerability,
)


def incremental_materialize_scenario(
    sink: GraphSink,
    validated: ValidatedScenarioRecord,
    record: ScenarioValidationRecord,
) -> dict[str, int]:
    """Write validated scenario and validation record back into graph (closing the loop)."""
    if record.status != "passed" or record.vulnerableTargetResult != "passed" or record.patchedTargetResult != "passed":
        raise ValueError("only a passed differential receipt can be materialized")
    if record.executionMode != "target":
        raise ValueError("synthetic execution receipts cannot validate a target vulnerability")
    if validated.candidateId != record.candidateId:
        raise ValueError("validation receipt candidate does not match scenario candidate")
    if validated.targetVulnId != record.targetVulnId:
        raise ValueError("validation receipt target does not match scenario target")
    if validated.validationId != record.validationId:
        raise ValueError("validation receipt ID does not match validated scenario")
    artifact = Path(record.evidenceRef)
    if not artifact.is_file():
        raise ValueError("validation evidence artifact does not exist")
    artifact_digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    if artifact_digest != record.evidenceHash:
        raise ValueError("validation evidence artifact digest mismatch")

    # 1. ValidationRecord node
    sink.merge_node(
        "ValidationRecord",
        "validationId",
        record.model_dump(mode="json"),
    )

    # 2. Scenario node
    sink.merge_node(
        "Scenario",
        "scenarioId",
        {
            "scenarioId": validated.scenarioId,
            "generated": True,
            "testReady": True,
            "methodologyStatus": "direct",
            "detectionSignalStatus": "accepted",
            "confidence": validated.groundingScore,
        },
    )

    # 3. Connect Scenario to Vulnerability
    sink.merge_rel(
        "Scenario",
        "scenarioId",
        validated.scenarioId,
        "TARGETS",
        "Vulnerability",
        "vulnId",
        validated.targetVulnId,
        {"source": "closed-loop-validation", "trustLevel": "validated"},
    )
    sink.merge_rel(
        "Vulnerability",
        "vulnId",
        validated.targetVulnId,
        "DETECTED_BY",
        "Scenario",
        "scenarioId",
        validated.scenarioId,
        {"source": "closed-loop-validation", "trustLevel": "validated"},
    )

    # 4. Connect Scenario to ValidationRecord
    sink.merge_rel(
        "Scenario",
        "scenarioId",
        validated.scenarioId,
        "VALIDATED_BY",
        "ValidationRecord",
        "validationId",
        record.validationId,
        {"status": "passed", "validatedAt": record.validatedAt},
    )

    return {
        "scenarios": 1,
        "validation_records": 1,
        "edges": 3,
    }


def incremental_materialize_vulnerability(
    sink: GraphSink,
    entry: VulnerabilityEntry,
) -> dict[str, int]:
    """Incrementally add a newly analyzed vulnerability and its facts into the graph."""
    facts = entry.facts
    vuln_node = Vulnerability(
        vulnId=entry.vuln_id,
        title=entry.title,
        description=entry.description,
        publishedAt=entry.published_at,
        observedAt=entry.observed_at or entry.published_at,
        epistemicStatus=entry.epistemic_status,
        cweId=entry.cwe_id,
        inputVector=facts.input_vector if facts else None,
        inputParameter=facts.input_parameter if facts else None,
        mechanism=facts.mechanism if facts else None,
        impact=facts.impact if facts else None,
        precondition=facts.precondition if facts else None,
    )
    sink.merge_node("Vulnerability", "vulnId", vuln_node.to_props())

    edge_count = 0
    if entry.cwe_id:
        if sink.get_node("Weakness", "weaknessId", entry.cwe_id) is None:
            from schema.models import Weakness
            sink.merge_node(
                "Weakness",
                "weaknessId",
                Weakness(
                    weaknessId=entry.cwe_id,
                    namespace="CWE",
                    cweId=entry.cwe_id,
                    origin="MITRE",
                ).to_props(),
            )
        sink.merge_rel(
            "Vulnerability",
            "vulnId",
            entry.vuln_id,
            "INSTANCE_OF",
            "Weakness",
            "weaknessId",
            entry.cwe_id,
            {
                "source": "incremental-ingest",
                "epistemicStatus": entry.epistemic_status,
                "knownAt": entry.published_at,
            },
        )
        edge_count += 1

    if entry.product:
        sink.merge_node(
            "Product",
            "name",
            Product(name=entry.product.name, vendor=entry.product.vendor).to_props(),
        )
        sink.merge_rel(
            "Vulnerability",
            "vulnId",
            entry.vuln_id,
            "AFFECTS",
            "Product",
            "name",
            entry.product.name,
            {"knownAt": entry.published_at},
        )
        edge_count += 1

    if entry.component:
        prefix = entry.product.name if entry.product else "generic"
        component_id = f"{prefix}:{entry.component.name}"
        sink.merge_node(
            "Component",
            "componentId",
            Component(
                componentId=component_id,
                name=entry.component.name,
                path=entry.component.path,
            ).to_props(),
        )
        sink.merge_rel(
            "Vulnerability",
            "vulnId",
            entry.vuln_id,
            "AFFECTS_COMPONENT",
            "Component",
            "componentId",
            component_id,
            {"knownAt": entry.published_at},
        )
        edge_count += 1

    for ev in entry.evidence:
        sink.merge_node(
            "Evidence",
            "evidenceId",
            Evidence(
                evidenceId=ev.evidence_id,
                kind=ev.kind,
                sourceRef=ev.source_ref,
                sourceHash=ev.source_hash,
                excerpt=ev.excerpt,
                observedAt=ev.observed_at or entry.published_at,
            ).to_props(),
        )
        sink.merge_rel(
            "Vulnerability",
            "vulnId",
            entry.vuln_id,
            "HAS_EVIDENCE",
            "Evidence",
            "evidenceId",
            ev.evidence_id,
            {"knownAt": entry.published_at},
        )
        edge_count += 1

    return {
        "vulnerabilities": 1,
        "edges": edge_count,
    }
