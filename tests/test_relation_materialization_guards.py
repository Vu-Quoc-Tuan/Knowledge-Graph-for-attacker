from __future__ import annotations

from pathlib import Path

import pytest

from db.sink import DryRunSink
from proposals.log import RelationLogError
from proposals.materialize import (
    RelationMaterializationError,
    materialize_relation_log,
)
from proposals.models import Evidence, ProposalSnapshot
from proposals.service import RelationEventService
from schema.models import Weakness


def _snapshot(
    subject: str,
    predicate: str,
    object_: str,
    dimension: str | None = None,
) -> ProposalSnapshot:
    return ProposalSnapshot(
        subjectWeaknessId=subject,
        predicate=predicate,  # type: ignore[arg-type]
        objectWeaknessId=object_,
        dimension=dimension,
        rationale="Reviewed relationship evidence.",
        evidence=[Evidence(sourceRef="evidence.md", excerpt="evidence")],
        producerKind="human",
        producerName="reviewer",
    )


def _sink(*weakness_ids: str) -> DryRunSink:
    sink = DryRunSink()
    for weakness_id in weakness_ids:
        sink.merge_node(
            "Weakness",
            "weaknessId",
            Weakness(
                weaknessId=weakness_id,
                namespace=weakness_id.split("-", 1)[0],
            ).to_props(),
        )
    return sink


def _accept(
    service: RelationEventService,
    snapshot: ProposalSnapshot,
) -> None:
    proposed = service.create(
        snapshot,
        actor="author",
        actor_type="human",
    )
    service.approve(proposed.proposalId, actor="reviewer")


def test_multiple_similarity_dimensions_merge_to_one_canonical_edge(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    events = tmp_path / "events.jsonl"
    events.touch()
    service = RelationEventService(relation_policy_path, events)
    _accept(
        service,
        _snapshot("LOCAL-1", "SIMILAR_TO", "CWE-89", "mechanism"),
    )
    _accept(
        service,
        _snapshot(
            "CWE-89",
            "SIMILAR_TO",
            "LOCAL-1",
            "detection_strategy",
        ),
    )
    sink = _sink("LOCAL-1", "CWE-89")

    first = materialize_relation_log(
        sink,
        service.policy,
        service._fold_current(),
    )
    second = materialize_relation_log(
        sink,
        service.policy,
        service._fold_current(),
    )

    assert first["materialized_similar_to"] == 1
    assert second["materialized_similar_to"] == 1
    edges = sink.match_rels("SIMILAR_TO")
    assert len(edges) == 1
    assert edges[0]["props"]["dimensions"] == [
        "detection_strategy",
        "mechanism",
    ]


def test_child_cycle_fails_before_any_domain_edge_is_written(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    events = tmp_path / "events.jsonl"
    events.touch()
    service = RelationEventService(relation_policy_path, events)
    _accept(service, _snapshot("LOCAL-1", "CHILD_OF", "LOCAL-2"))
    _accept(service, _snapshot("LOCAL-2", "CHILD_OF", "LOCAL-1"))
    sink = _sink("LOCAL-1", "LOCAL-2")

    with pytest.raises(
        RelationMaterializationError,
        match="CHILD_OF cycle detected",
    ):
        materialize_relation_log(
            sink,
            service.policy,
            service._fold_current(),
        )
    assert sink.match_rels("CHILD_OF") == []


def test_self_relation_is_rejected_before_append(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    events = tmp_path / "events.jsonl"
    events.touch()
    service = RelationEventService(relation_policy_path, events)

    with pytest.raises(RelationLogError, match="self-relation"):
        service.create(
            _snapshot(
                "LOCAL-1", "SIMILAR_TO", "LOCAL-1", "mechanism"
            ),
            actor="author",
            actor_type="human",
        )
    assert events.read_text(encoding="utf-8") == ""
