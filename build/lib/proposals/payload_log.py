"""Parse and fold durable extracted-payload review events."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Iterable, Literal

from pydantic import TypeAdapter, ValidationError

from proposals.payload_models import (
    ApprovePayloadEvent,
    PayloadEvent,
    PayloadProposalSnapshot,
    ProposePayloadEvent,
    RecordPayloadValidationEvent,
    RejectPayloadEvent,
    RequestPayloadChangesEvent,
    RevisePayloadEvent,
    ValidationRecord,
)
from proposals.payload_references import (
    PayloadReferenceError,
    validate_snapshot_references,
    validate_validation_references,
)


EVENT_ADAPTER = TypeAdapter(PayloadEvent)
PayloadProposalStatus = Literal[
    "pending",
    "changes_requested",
    "tested",
    "accepted",
    "rejected",
]


class PayloadLogError(ValueError):
    """The payload event log cannot be replayed safely."""


@dataclass(frozen=True)
class PayloadProposalState:
    proposalId: str
    status: PayloadProposalStatus
    revision: int
    snapshot: PayloadProposalSnapshot
    fingerprint: str
    createdAt: datetime
    updatedAt: datetime
    acceptedBy: str | None
    acceptedAt: datetime | None
    testedBy: str | None
    testedAt: datetime | None
    latestValidation: ValidationRecord | None
    events: tuple[PayloadEvent, ...]


@dataclass(frozen=True)
class FoldedPayloadLog:
    proposals: dict[str, PayloadProposalState]
    events: tuple[PayloadEvent, ...]
    reproposalWarnings: tuple[str, ...]
    repoRoot: Path


def _unique_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def parse_payload_event_lines(
    lines: Iterable[str],
    *,
    source: Path,
) -> list[PayloadEvent]:
    events: list[PayloadEvent] = []
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        try:
            raw = json.loads(
                raw_line,
                object_pairs_hook=_unique_json_object,
            )
        except json.JSONDecodeError as exc:
            raise PayloadLogError(
                f"{source}:{line_number}: invalid JSON: {exc}"
            ) from exc
        except ValueError as exc:
            raise PayloadLogError(
                f"{source}:{line_number}: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise PayloadLogError(
                f"{source}:{line_number}: "
                "event must be a JSON object"
            )
        try:
            events.append(EVENT_ADAPTER.validate_python(raw))
        except ValidationError as exc:
            raise PayloadLogError(
                f"{source}:{line_number}: "
                f"invalid payload event: {exc}"
            ) from exc
    return events


def read_payload_events(
    path: str | Path,
) -> list[PayloadEvent]:
    source = Path(path)
    if not source.is_file():
        if not source.exists():
            source.parent.mkdir(parents=True, exist_ok=True)
            source.touch()
            return []
        raise PayloadLogError(
            f"{source}: payload event log does not exist"
        )
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise PayloadLogError(
            f"{source}: cannot read payload event log: {exc}"
        ) from exc
    return parse_payload_event_lines(lines, source=source)


def payload_fingerprint(
    snapshot: PayloadProposalSnapshot,
) -> str:
    data = {
        "weaknessId": snapshot.weaknessId,
        "payloadValue": snapshot.payloadValue,
        "familyKey": snapshot.familyKey,
        "technology": snapshot.technology,
        "producerKind": snapshot.producerKind,
        "producerName": snapshot.producerName,
        "producerVersion": snapshot.producerVersion,
    }
    encoded = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _check_fingerprint(
    *,
    proposal_id: str,
    fingerprint: str,
    states: dict[str, PayloadProposalState],
) -> bool:
    matches = [
        state
        for other_id, state in states.items()
        if other_id != proposal_id
        and state.fingerprint == fingerprint
    ]
    if not matches:
        return False
    accepted = next(
        (
            state
            for state in matches
            if state.status == "accepted"
        ),
        None,
    )
    if accepted is not None:
        raise PayloadLogError(
            f"{proposal_id}: fingerprint is already accepted by "
            f"{accepted.proposalId}"
        )
    active = next(
        (
            state
            for state in matches
            if state.status != "rejected"
        ),
        None,
    )
    if active is not None:
        raise PayloadLogError(
            f"{proposal_id}: duplicate active fingerprint "
            f"from {active.proposalId}"
        )
    return True


def _validated_snapshot(
    proposal_id: str,
    snapshot: PayloadProposalSnapshot,
    repo_root: Path,
) -> str:
    try:
        validate_snapshot_references(snapshot, repo_root)
    except PayloadReferenceError as exc:
        raise PayloadLogError(
            f"{proposal_id}: {exc}"
        ) from exc
    return payload_fingerprint(snapshot)


def _state_for_event(
    event: PayloadEvent,
    states: dict[str, PayloadProposalState],
) -> PayloadProposalState:
    state = states.get(event.proposalId)
    if state is None:
        raise PayloadLogError(
            f"{event.proposalId}: has no initial propose event"
        )
    if event.occurredAt < state.updatedAt:
        raise PayloadLogError(
            f"{event.proposalId}: event {event.eventId} timestamp "
            "precedes the previous proposal event"
        )
    if state.status in {"accepted", "rejected"}:
        raise PayloadLogError(
            f"{event.proposalId}: {state.status} is terminal"
        )
    return state


def fold_payload_events(
    events: Iterable[PayloadEvent],
    repo_root: str | Path,
) -> FoldedPayloadLog:
    ordered_events = tuple(events)
    root = Path(repo_root)
    states: dict[str, PayloadProposalState] = {}
    event_ids: set[str] = set()
    warnings: list[str] = []

    for event in ordered_events:
        if event.eventId in event_ids:
            raise PayloadLogError(
                f"duplicate eventId {event.eventId}"
            )
        event_ids.add(event.eventId)

        if isinstance(event, ProposePayloadEvent):
            if event.proposalId in states:
                raise PayloadLogError(
                    f"{event.proposalId}: duplicate initial proposal"
                )
            fingerprint = _validated_snapshot(
                event.proposalId,
                event.snapshot,
                root,
            )
            if _check_fingerprint(
                proposal_id=event.proposalId,
                fingerprint=fingerprint,
                states=states,
            ):
                warnings.append(event.proposalId)
            states[event.proposalId] = PayloadProposalState(
                proposalId=event.proposalId,
                status="pending",
                revision=1,
                snapshot=event.snapshot,
                fingerprint=fingerprint,
                createdAt=event.occurredAt,
                updatedAt=event.occurredAt,
                acceptedBy=None,
                acceptedAt=None,
                testedBy=None,
                testedAt=None,
                latestValidation=None,
                events=(event,),
            )
            continue

        state = _state_for_event(event, states)
        history = (*state.events, event)

        if isinstance(event, RequestPayloadChangesEvent):
            if state.status not in {"pending", "tested"}:
                raise PayloadLogError(
                    f"{event.proposalId}: request_changes "
                    "requires pending or tested"
                )
            states[event.proposalId] = replace(
                state,
                status="changes_requested",
                updatedAt=event.occurredAt,
                testedBy=None,
                testedAt=None,
                latestValidation=None,
                events=history,
            )
            continue

        if isinstance(event, RevisePayloadEvent):
            if state.status != "changes_requested":
                raise PayloadLogError(
                    f"{event.proposalId}: revise requires "
                    "changes_requested"
                )
            fingerprint = _validated_snapshot(
                event.proposalId,
                event.snapshot,
                root,
            )
            if _check_fingerprint(
                proposal_id=event.proposalId,
                fingerprint=fingerprint,
                states=states,
            ) and event.proposalId not in warnings:
                warnings.append(event.proposalId)
            states[event.proposalId] = replace(
                state,
                status="pending",
                revision=state.revision + 1,
                snapshot=event.snapshot,
                fingerprint=fingerprint,
                updatedAt=event.occurredAt,
                testedBy=None,
                testedAt=None,
                latestValidation=None,
                events=history,
            )
            continue

        if isinstance(event, RecordPayloadValidationEvent):
            if state.status != "pending":
                raise PayloadLogError(
                    f"{event.proposalId}: record_validation "
                    "requires pending"
                )
            validation = event.validation
            if validation.revision != state.revision:
                raise PayloadLogError(
                    f"{event.proposalId}: validation revision "
                    f"{validation.revision} does not match current "
                    f"revision {state.revision}"
                )
            try:
                validate_validation_references(
                    validation,
                    root,
                )
            except PayloadReferenceError as exc:
                raise PayloadLogError(
                    f"{event.proposalId}: {exc}"
                ) from exc
            passed = validation.result == "passed"
            states[event.proposalId] = replace(
                state,
                status="tested" if passed else "pending",
                updatedAt=event.occurredAt,
                testedBy=event.actor if passed else None,
                testedAt=event.occurredAt if passed else None,
                latestValidation=validation,
                events=history,
            )
            continue

        if isinstance(event, ApprovePayloadEvent):
            if state.status != "tested":
                raise PayloadLogError(
                    f"{event.proposalId}: approve requires tested"
                )
            validation = state.latestValidation
            if (
                validation is None
                or validation.result != "passed"
                or validation.revision != state.revision
            ):
                raise PayloadLogError(
                    f"{event.proposalId}: current revision lacks "
                    "passing validation"
                )
            states[event.proposalId] = replace(
                state,
                status="accepted",
                updatedAt=event.occurredAt,
                acceptedBy=event.actor,
                acceptedAt=event.occurredAt,
                events=history,
            )
            continue

        if isinstance(event, RejectPayloadEvent):
            if state.status not in {
                "pending",
                "changes_requested",
                "tested",
            }:
                raise PayloadLogError(
                    f"{event.proposalId}: reject requires pending, "
                    "changes_requested, or tested"
                )
            states[event.proposalId] = replace(
                state,
                status="rejected",
                updatedAt=event.occurredAt,
                events=history,
            )
            continue

        raise PayloadLogError(
            f"{event.proposalId}: unsupported event "
            f"{event.eventType}"
        )

    return FoldedPayloadLog(
        proposals=states,
        events=ordered_events,
        reproposalWarnings=tuple(warnings),
        repoRoot=root.resolve(),
    )


def load_payload_log(
    event_path: str | Path,
    repo_root: str | Path,
) -> FoldedPayloadLog:
    return fold_payload_events(
        read_payload_events(event_path),
        repo_root,
    )
