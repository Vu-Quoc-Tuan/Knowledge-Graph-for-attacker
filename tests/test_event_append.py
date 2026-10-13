from __future__ import annotations

from pathlib import Path
from concurrent.futures import ProcessPoolExecutor

import pytest

import proposals.service as relation_service_module
from proposals.log import read_relation_events
from proposals.models import Evidence, ProposalSnapshot
from proposals.service import RelationEventService, RelationServiceError


def _snapshot() -> ProposalSnapshot:
    return ProposalSnapshot(
        subjectWeaknessId="LOCAL-1",
        predicate="SIMILAR_TO",
        objectWeaknessId="CWE-89",
        dimension="mechanism",
        rationale="Both cross an interpreter trust boundary.",
        evidence=[
            Evidence(sourceRef="registry/source.md", excerpt="evidence")
        ],
        producerKind="human",
        producerName="reviewer",
    )


def _append_relation_worker(
    policy_path: str,
    event_path: str,
    index: int,
) -> str:
    service = RelationEventService(policy_path, event_path)
    event = service.create(
        ProposalSnapshot(
            subjectWeaknessId=f"LOCAL-{index + 1}",
            predicate="SIMILAR_TO",
            objectWeaknessId="CWE-89",
            dimension="mechanism",
            rationale=f"Independent reviewed relation {index}.",
            evidence=[
                Evidence(
                    sourceRef="registry/source.md",
                    excerpt=f"evidence {index}",
                )
            ],
            producerKind="human",
            producerName="reviewer",
        ),
        actor="reviewer",
        actor_type="human",
    )
    return event.eventId


def test_append_adds_boundary_newline(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    event_path = tmp_path / "events.jsonl"
    event_path.touch()
    service = RelationEventService(relation_policy_path, event_path)
    proposed = service.create(
        _snapshot(), actor="reviewer", actor_type="human"
    )

    event_path.write_text(
        event_path.read_text(encoding="utf-8").rstrip("\n"),
        encoding="utf-8",
    )
    service.approve(proposed.proposalId, actor="reviewer")

    lines = event_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [event.eventType for event in read_relation_events(event_path)] == [
        "propose",
        "approve",
    ]


def test_append_fails_closed_without_posix_locking(
    tmp_path: Path,
    relation_policy_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_path = tmp_path / "events.jsonl"
    event_path.touch()
    service = RelationEventService(relation_policy_path, event_path)
    monkeypatch.setattr(relation_service_module, "fcntl", None)

    with pytest.raises(
        RelationServiceError,
        match="refusing unlocked append",
    ):
        service.create(
            _snapshot(), actor="reviewer", actor_type="human"
        )
    assert event_path.read_text(encoding="utf-8") == ""


def test_concurrent_process_appends_preserve_every_event(
    tmp_path: Path,
    relation_policy_path: Path,
) -> None:
    event_path = tmp_path / "events.jsonl"
    event_path.touch()
    with ProcessPoolExecutor(max_workers=4) as executor:
        event_ids = list(
            executor.map(
                _append_relation_worker,
                [str(relation_policy_path)] * 12,
                [str(event_path)] * 12,
                range(12),
            )
        )

    events = read_relation_events(event_path)
    assert len(events) == 12
    assert len(set(event_ids)) == 12
    assert {event.eventId for event in events} == set(event_ids)
