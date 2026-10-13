"""Parse and fold the append-only relation proposal event log."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Iterable, Literal

from pydantic import TypeAdapter, ValidationError

from proposals.models import (
    ApproveEvent,
    ProposalSnapshot,
    ProposeEvent,
    RejectEvent,
    RelationEvent,
    RetractEvent,
    RequestChangesEvent,
    ReviseEvent,
)
from proposals.policy import RelationPolicy, read_relation_policy


EVENT_ADAPTER = TypeAdapter(RelationEvent)
ProposalStatus = Literal[
    "pending",
    "changes_requested",
    "accepted",
    "rejected",
    "retracted",
]


class RelationLogError(ValueError):
    """The event log cannot be replayed without losing integrity."""


@dataclass(frozen=True)
class ProposalState:
    proposalId: str
    status: ProposalStatus
    revision: int
    snapshot: ProposalSnapshot
    fingerprint: str
    createdAt: datetime
    updatedAt: datetime
    acceptedBy: str | None
    acceptedAt: datetime | None
    retractedBy: str | None
    retractedAt: datetime | None
    retractionReason: str | None
    events: tuple[RelationEvent, ...]


@dataclass(frozen=True)
class FoldedRelationLog:
    proposals: dict[str, ProposalState]
    events: tuple[RelationEvent, ...]
    reproposalWarnings: tuple[str, ...]


def _unique_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def parse_relation_event_lines(
    lines: Iterable[str],
    *,
    source: Path,
) -> list[RelationEvent]:
    """Parse strict JSONL while retaining a precise source line on failure."""

    events: list[RelationEvent] = []
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        try:
            raw = json.loads(
                raw_line,
                object_pairs_hook=_unique_json_object,
            )
        except json.JSONDecodeError as exc:
            raise RelationLogError(
                f"{source}:{line_number}: invalid JSON: {exc}"
            ) from exc
        except ValueError as exc:
            raise RelationLogError(
                f"{source}:{line_number}: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise RelationLogError(
                f"{source}:{line_number}: "
                "event must be a JSON object"
            )
        try:
            events.append(EVENT_ADAPTER.validate_python(raw))
        except ValidationError as exc:
            raise RelationLogError(
                f"{source}:{line_number}: "
                f"invalid relation event: {exc}"
            ) from exc
    return events


def read_relation_events(
    path: str | Path,
) -> list[RelationEvent]:
    source = Path(path)
    if not source.is_file():
        if not source.exists():
            source.parent.mkdir(parents=True, exist_ok=True)
            source.touch()
            return []
        raise RelationLogError(
            f"{source}: relation event log does not exist"
        )
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise RelationLogError(
            f"{source}: cannot read relation event log: {exc}"
        ) from exc
    return parse_relation_event_lines(lines, source=source)


def _validate_snapshot(
    snapshot: ProposalSnapshot,
    policy: RelationPolicy,
) -> None:
    predicate_policy = policy.predicates.get(snapshot.predicate)
    if predicate_policy is None:
        raise RelationLogError(
            f"{snapshot.predicate} is not enabled by relation policy"
        )
    if snapshot.subjectWeaknessId == snapshot.objectWeaknessId:
        raise RelationLogError(
            f"{snapshot.predicate} self-relation is not allowed"
        )
    if predicate_policy.dimension_required:
        if snapshot.dimension is None:
            raise RelationLogError(
                f"{snapshot.predicate} requires a dimension"
            )
        if snapshot.dimension not in (
            predicate_policy.allowed_dimensions
        ):
            raise RelationLogError(
                f"dimension {snapshot.dimension!r} is not allowed "
                f"for {snapshot.predicate}"
            )
    elif snapshot.dimension is not None:
        raise RelationLogError(
            f"{snapshot.predicate} does not allow dimensions"
        )


def canonical_endpoints(
    snapshot: ProposalSnapshot,
    policy: RelationPolicy,
) -> tuple[str, str]:
    _validate_snapshot(snapshot, policy)
    predicate_policy = policy.predicates[snapshot.predicate]
    endpoints = (
        snapshot.subjectWeaknessId,
        snapshot.objectWeaknessId,
    )
    if predicate_policy.symmetric:
        return tuple(sorted(endpoints))
    return endpoints


def proposal_fingerprint(
    snapshot: ProposalSnapshot,
    policy: RelationPolicy,
) -> str:
    subject, object_ = canonical_endpoints(snapshot, policy)
    payload = {
        "predicate": snapshot.predicate,
        "subject": subject,
        "object": object_,
        "dimension": snapshot.dimension,
        "producerKind": snapshot.producerKind,
        "producerName": snapshot.producerName,
        "producerVersion": snapshot.producerVersion,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _check_fingerprint(
    *,
    proposal_id: str,
    fingerprint: str,
    states: dict[str, ProposalState],
) -> bool:
    matches = [
        state
        for other_id, state in states.items()
        if other_id != proposal_id
        and state.fingerprint == fingerprint
    ]
    if not matches:
        return False
    if any(state.status == "accepted" for state in matches):
        accepted = next(
            state
            for state in matches
            if state.status == "accepted"
        )
        raise RelationLogError(
            f"{proposal_id}: fingerprint is already accepted by "
            f"{accepted.proposalId}"
        )
    active = next(
        (
            state
            for state in matches
            if state.status not in {"rejected", "retracted"}
        ),
        None,
    )
    if active is not None:
        raise RelationLogError(
            f"{proposal_id}: duplicate active fingerprint "
            f"from {active.proposalId}"
        )
    return True


def _event_after_proposal(
    event: RelationEvent,
    states: dict[str, ProposalState],
) -> ProposalState:
    state = states.get(event.proposalId)
    if state is None:
        raise RelationLogError(
            f"{event.proposalId}: has no initial propose event"
        )
    if event.occurredAt < state.updatedAt:
        raise RelationLogError(
            f"{event.proposalId}: event {event.eventId} timestamp "
            "precedes the previous proposal event"
        )
    if state.status in {"accepted", "rejected", "retracted"}:
        raise RelationLogError(
            f"{event.proposalId}: {state.status} is terminal"
        )
    return state


def fold_relation_events(
    events: Iterable[RelationEvent],
    policy: RelationPolicy,
) -> FoldedRelationLog:
    ordered_events = tuple(events)
    states: dict[str, ProposalState] = {}
    event_ids: set[str] = set()
    warnings: list[str] = []

    for event in ordered_events:
        if event.eventId in event_ids:
            raise RelationLogError(
                f"duplicate eventId {event.eventId}"
            )
        event_ids.add(event.eventId)

        if isinstance(event, ProposeEvent):
            if event.proposalId in states:
                raise RelationLogError(
                    f"{event.proposalId}: duplicate initial proposal"
                )
            fingerprint = proposal_fingerprint(
                event.snapshot, policy
            )
            if _check_fingerprint(
                proposal_id=event.proposalId,
                fingerprint=fingerprint,
                states=states,
            ):
                warnings.append(event.proposalId)
            states[event.proposalId] = ProposalState(
                proposalId=event.proposalId,
                status="pending",
                revision=1,
                snapshot=event.snapshot,
                fingerprint=fingerprint,
                createdAt=event.occurredAt,
                updatedAt=event.occurredAt,
                acceptedBy=None,
                acceptedAt=None,
                retractedBy=None,
                retractedAt=None,
                retractionReason=None,
                events=(event,),
            )
            continue

        if isinstance(event, RetractEvent):
            state = states.get(event.proposalId)
            if state is None:
                raise RelationLogError(
                    f"{event.proposalId}: has no initial propose event"
                )
            if event.occurredAt < state.updatedAt:
                raise RelationLogError(
                    f"{event.proposalId}: event {event.eventId} timestamp "
                    "precedes the previous proposal event"
                )
            if state.status != "accepted":
                raise RelationLogError(
                    f"{event.proposalId}: retract requires accepted"
                )
            states[event.proposalId] = replace(
                state,
                status="retracted",
                updatedAt=event.occurredAt,
                retractedBy=event.actor,
                retractedAt=event.occurredAt,
                retractionReason=event.reason,
                events=(*state.events, event),
            )
            continue

        state = _event_after_proposal(event, states)
        history = (*state.events, event)

        if isinstance(event, RequestChangesEvent):
            if state.status != "pending":
                raise RelationLogError(
                    f"{event.proposalId}: request_changes "
                    "requires pending"
                )
            states[event.proposalId] = replace(
                state,
                status="changes_requested",
                updatedAt=event.occurredAt,
                events=history,
            )
            continue

        if isinstance(event, ReviseEvent):
            if state.status != "changes_requested":
                raise RelationLogError(
                    f"{event.proposalId}: revise requires "
                    "changes_requested"
                )
            fingerprint = proposal_fingerprint(
                event.snapshot, policy
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
                events=history,
            )
            continue

        if isinstance(event, ApproveEvent):
            if state.status != "pending":
                raise RelationLogError(
                    f"{event.proposalId}: approve requires pending"
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

        if isinstance(event, RejectEvent):
            if state.status not in {
                "pending",
                "changes_requested",
            }:
                raise RelationLogError(
                    f"{event.proposalId}: reject requires pending "
                    "or changes_requested"
                )
            states[event.proposalId] = replace(
                state,
                status="rejected",
                updatedAt=event.occurredAt,
                events=history,
            )
            continue

        raise RelationLogError(
            f"{event.proposalId}: unsupported event "
            f"{event.eventType}"
        )

    return FoldedRelationLog(
        proposals=states,
        events=ordered_events,
        reproposalWarnings=tuple(warnings),
    )


def load_relation_log(
    policy_path: str | Path,
    event_path: str | Path,
) -> tuple[RelationPolicy, FoldedRelationLog]:
    policy = read_relation_policy(policy_path)
    events = read_relation_events(event_path)
    return policy, fold_relation_events(events, policy)
