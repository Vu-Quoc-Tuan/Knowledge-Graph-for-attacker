from __future__ import annotations

from pathlib import Path

from db.sink import DryRunSink
from proposals.materialize import materialize_relation_log
from proposals.models import Evidence, ProposalSnapshot
from proposals.service import RelationEventService
from retrieval.queries import weakness_card
from schema.models import Scenario, TestActivity as Activity, Weakness


def _base_graph() -> DryRunSink:
    sink = DryRunSink()
    for weakness_id, namespace, origin in (
        ("LOCAL-1", "LOCAL", "local"),
        ("CWE-89", "CWE", "MITRE"),
    ):
        sink.merge_node(
            "Weakness",
            "weaknessId",
            Weakness(
                weaknessId=weakness_id,
                namespace=namespace,
                origin=origin,
                name=weakness_id,
                summary="Grounded summary",
            ).to_props(),
        )
    sink.merge_node(
        "TestActivity",
        "wstgId",
        Activity(
            wstgId="WSTG-INPV-05",
            name="Test SQL Injection",
            url="https://owasp.org/wstg/INPV-05",
            source="OWASP WSTG",
        ).to_props(),
    )
    sink.merge_rel(
        "Weakness",
        "weaknessId",
        "CWE-89",
        "TESTED_BY",
        "TestActivity",
        "wstgId",
        "WSTG-INPV-05",
        {"source": "opencre"},
    )
    sink.merge_node(
        "Scenario",
        "scenarioId",
        Scenario(
            scenarioId="SCN-CWE-89-sqli.generic",
            methodologyStatus="direct",
            detectionSignalStatus="strategy_hint",
        ).to_props(),
    )
    sink.merge_rel(
        "Scenario",
        "scenarioId",
        "SCN-CWE-89-sqli.generic",
        "TARGETS",
        "Weakness",
        "weaknessId",
        "CWE-89",
    )
    return sink


def _service(
    tmp_path: Path,
    relation_policy_path: Path,
) -> tuple[RelationEventService, str]:
    event_path = tmp_path / "events.jsonl"
    event_path.touch()
    service = RelationEventService(relation_policy_path, event_path)
    proposal = service.create(
        ProposalSnapshot(
            subjectWeaknessId="LOCAL-1",
            predicate="SIMILAR_TO",
            objectWeaknessId="CWE-89",
            dimension="mechanism",
            rationale="Both adapt untrusted input across a trust boundary.",
            evidence=[
                Evidence(
                    sourceRef="registry/local-source.md",
                    excerpt="Prompt input crosses the model boundary.",
                ),
                Evidence(
                    sourceRef="https://cwe.mitre.org/data/definitions/89.html",
                    excerpt="SQL input crosses the interpreter boundary.",
                ),
            ],
            producerKind="human",
            producerName="researcher",
        ),
        actor="researcher",
        actor_type="human",
    )
    service.approve(proposal.proposalId, actor="reviewer")
    return service, proposal.proposalId


def test_similarity_exposes_references_not_asserted_scenario(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    sink = _base_graph()
    service, _proposal_id = _service(tmp_path, relation_policy_path)
    materialize_relation_log(sink, service.policy, service._fold_current())

    card = weakness_card(sink, "LOCAL-1")
    assert card is not None
    assert card["scenarios"] == []
    assert card["reviewedPayloads"] == []
    assert card["referenceScenarios"][0]["applicability"] == "unknown"
    assert card["referenceScenarios"][0]["scenario"]["scenarioId"] == (
        "SCN-CWE-89-sqli.generic"
    )
    exposed = card["referenceScenarios"][0]["exposedBy"]
    assert exposed["predicate"] == "SIMILAR_TO"
    assert exposed["dimensions"] == ["mechanism"]
    assert exposed["rationales"] == [
        "Both adapt untrusted input across a trust boundary."
    ]
    assert exposed["evidenceSourceRefs"]
    assert card["referenceMethodologies"][0]["applicability"] == "unknown"
    assert card["referenceMethodologies"][0]["exposedBy"] == exposed
    assert card["assertedRelations"][0]["dimensions"] == ["mechanism"]


def test_retracted_relation_removes_all_references(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    service, proposal_id = _service(tmp_path, relation_policy_path)
    service.retract(
        proposal_id,
        actor="reviewer",
        reason="The analogy is no longer supported.",
    )
    rebuilt = _base_graph()
    materialize_relation_log(
        rebuilt, service.policy, service._fold_current()
    )

    card = weakness_card(rebuilt, "LOCAL-1")
    assert card is not None
    assert card["assertedRelations"] == []
    assert card["referenceMethodologies"] == []
    assert card["referenceScenarios"] == []
