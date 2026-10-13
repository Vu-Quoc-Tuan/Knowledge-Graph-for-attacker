from __future__ import annotations

from pathlib import Path

import pytest

from db.sink import DryRunSink
from proposals.log import RelationLogError, proposal_fingerprint
from proposals.materialize import materialize_relation_log
from proposals.models import Evidence, ProposalSnapshot
from proposals.policy import read_relation_policy
from proposals.service import RelationEventService
from schema.models import Weakness


def _snapshot(subject: str, object_: str) -> ProposalSnapshot:
    return ProposalSnapshot(
        subjectWeaknessId=subject,
        predicate="SIMILAR_TO",
        objectWeaknessId=object_,
        dimension="mechanism",
        rationale="Both cross an interpreter trust boundary.",
        evidence=[
            Evidence(sourceRef="registry/source.md", excerpt="evidence")
        ],
        producerKind="human",
        producerName="reviewer",
    )


def test_symmetric_similarity_fingerprint_is_direction_independent(
    relation_policy_path: Path,
) -> None:
    policy = read_relation_policy(relation_policy_path)
    assert proposal_fingerprint(
        _snapshot("LOCAL-1", "CWE-89"), policy
    ) == proposal_fingerprint(_snapshot("CWE-89", "LOCAL-1"), policy)


def test_human_can_retract_accepted_relation(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    event_path = tmp_path / "events.jsonl"
    event_path.touch()
    service = RelationEventService(relation_policy_path, event_path)
    proposed = service.create(
        _snapshot("LOCAL-1", "CWE-89"),
        actor="author",
        actor_type="human",
    )
    service.approve(proposed.proposalId, actor="reviewer")

    service.retract(
        proposed.proposalId,
        actor="reviewer",
        reason="The source was superseded.",
    )
    state = service.get(proposed.proposalId)
    assert state.status == "retracted"
    assert state.retractedBy == "reviewer"
    assert state.retractionReason == "The source was superseded."

    sink = DryRunSink()
    for weakness_id, namespace in (("LOCAL-1", "LOCAL"), ("CWE-89", "CWE")):
        sink.merge_node(
            "Weakness",
            "weaknessId",
            Weakness(
                weaknessId=weakness_id,
                namespace=namespace,
            ).to_props(),
        )
    stats = materialize_relation_log(
        sink,
        service.policy,
        service._fold_current(),
    )
    assert stats["retracted"] == 1
    assert sink.match_rels("SIMILAR_TO") == []


def test_only_accepted_relation_can_be_retracted(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    event_path = tmp_path / "events.jsonl"
    event_path.touch()
    service = RelationEventService(relation_policy_path, event_path)
    proposed = service.create(
        _snapshot("LOCAL-1", "CWE-89"),
        actor="author",
        actor_type="human",
    )
    with pytest.raises(RelationLogError, match="retract requires accepted"):
        service.retract(
            proposed.proposalId,
            actor="reviewer",
            reason="Not valid.",
        )


def test_retracted_child_claim_can_be_replaced(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    event_path = tmp_path / "events.jsonl"
    event_path.touch()
    service = RelationEventService(relation_policy_path, event_path)
    snapshot = ProposalSnapshot(
        subjectWeaknessId="LOCAL-1",
        predicate="CHILD_OF",
        objectWeaknessId="CWE-89",
        rationale="The reviewed taxonomy places this beneath CWE-89.",
        evidence=[
            Evidence(sourceRef="registry/source.md", excerpt="evidence")
        ],
        producerKind="human",
        producerName="reviewer",
    )
    original = service.create(
        snapshot,
        actor="author",
        actor_type="human",
    )
    service.approve(original.proposalId, actor="reviewer")
    service.retract(
        original.proposalId,
        actor="reviewer",
        reason="Evidence was superseded.",
    )

    replacement = service.create(
        snapshot.model_copy(
            update={
                "rationale": "New evidence confirms the same taxonomy."
            }
        ),
        actor="author",
        actor_type="human",
    )
    assert service.get(replacement.proposalId).status == "pending"
