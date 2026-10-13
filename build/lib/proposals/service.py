"""Durable file-locked operations for relation proposal events."""

from __future__ import annotations

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]
try:
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore[assignment]

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, Sequence, cast
from uuid import uuid4

from proposals.log import (
    FoldedRelationLog,
    ProposalState,
    RelationLogError,
    fold_relation_events,
    parse_relation_event_lines,
    read_relation_events,
)
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
from proposals.file_lock import lock_file, unlock_file
from proposals.cache import EventFoldCheckpoint
from proposals.policy import RelationPolicy, read_relation_policy


ActorType = Literal["human", "ai", "rule"]
ProposalStatus = Literal[
    "pending",
    "changes_requested",
    "accepted",
    "rejected",
    "retracted",
]


class RelationServiceError(ValueError):
    """A requested proposal operation cannot be completed."""


def _lock_file(fd: int) -> None:
    lock_file(
        fd,
        posix_backend=fcntl,
        windows_backend=msvcrt,
        error_type=RelationServiceError,
        resource_name="relation proposal log",
    )


def _unlock_file(fd: int) -> None:
    unlock_file(fd, posix_backend=fcntl, windows_backend=msvcrt)


def _new_event_id() -> str:
    return f"REL-EVT-{uuid4()}"


def _new_proposal_id() -> str:
    return f"REL-PROP-{uuid4()}"


def _event_time(
    occurred_at: datetime | str | None,
) -> datetime | str:
    if occurred_at is None:
        return datetime.now(timezone.utc)
    return occurred_at


def _ensure_unique_active_child_claims(
    folded: FoldedRelationLog,
    snapshots: Sequence[ProposalSnapshot],
    *,
    exclude_proposal_id: str | None = None,
) -> None:
    child_pairs = [
        (
            snapshot.subjectWeaknessId,
            snapshot.objectWeaknessId,
        )
        for snapshot in snapshots
        if snapshot.predicate == "CHILD_OF"
    ]
    if len(set(child_pairs)) != len(child_pairs):
        raise RelationServiceError(
            "proposal batch contains duplicate CHILD_OF claims"
        )
    for state in folded.proposals.values():
        if (
            state.proposalId == exclude_proposal_id
            or state.status in {"rejected", "retracted"}
            or state.snapshot.predicate != "CHILD_OF"
        ):
            continue
        pair = (
            state.snapshot.subjectWeaknessId,
            state.snapshot.objectWeaknessId,
        )
        if pair in child_pairs:
            raise RelationServiceError(
                "CHILD_OF claim is already active or accepted "
                f"as {state.proposalId}"
            )


class RelationEventService:
    """Read-fold-append operations over one durable relation event log."""

    def __init__(
        self,
        policy_path: str | Path,
        event_path: str | Path,
    ) -> None:
        self.policy_path = Path(policy_path)
        self.event_path = Path(event_path)
        self.policy: RelationPolicy = read_relation_policy(
            self.policy_path
        )
        self._checkpoint: EventFoldCheckpoint[FoldedRelationLog] = EventFoldCheckpoint(
            self.event_path
        )

    def _fold_current(self) -> FoldedRelationLog:
        return self._checkpoint.get(
            lambda: fold_relation_events(
                read_relation_events(self.event_path),
                self.policy,
            )
        )

    def _append_many_under_lock(
        self,
        build_events: Callable[
            [FoldedRelationLog], Sequence[RelationEvent]
        ],
    ) -> list[RelationEvent]:
        if not self.event_path.is_file():
            raise RelationLogError(
                f"{self.event_path}: "
                "relation event log does not exist"
            )

        try:
            stream = self.event_path.open(
                "r+",
                encoding="utf-8",
                newline="",
            )
        except (OSError, UnicodeError) as exc:
            raise RelationLogError(
                f"{self.event_path}: "
                f"cannot open relation event log: {exc}"
            ) from exc

        with stream:
            _lock_file(stream.fileno())
            try:
                stream.seek(0)
                try:
                    lines = stream.read().splitlines()
                except (OSError, UnicodeError) as exc:
                    raise RelationLogError(
                        f"{self.event_path}: cannot read "
                        f"relation event log: {exc}"
                    ) from exc
                events = parse_relation_event_lines(
                    lines, source=self.event_path
                )
                folded = fold_relation_events(
                    events, self.policy
                )
                new_events = list(build_events(folded))
                if not new_events:
                    raise RelationServiceError(
                        "event batch must not be empty"
                    )
                fold_relation_events(
                    [*events, *new_events], self.policy
                )
                serialized = "\n".join(
                    json.dumps(
                        event.model_dump(
                            mode="json",
                            exclude_none=True,
                        ),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )
                    for event in new_events
                )

                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                prefix = ""
                if size:
                    stream.seek(size - 1)
                    last_character = stream.read(1)
                    stream.seek(0, os.SEEK_END)
                    if last_character != "\n":
                        prefix = "\n"
                stream.write(f"{prefix}{serialized}\n")
                stream.flush()
                os.fsync(stream.fileno())
                self._checkpoint.invalidate()
                return new_events
            finally:
                _unlock_file(stream.fileno())

    def create(
        self,
        snapshot: ProposalSnapshot,
        *,
        actor: str,
        actor_type: ActorType,
        occurred_at: datetime | str | None = None,
    ) -> ProposeEvent:
        return self.create_many(
            [snapshot],
            actor=actor,
            actor_type=actor_type,
            occurred_at=occurred_at,
        )[0]

    def create_many(
        self,
        snapshots: Sequence[ProposalSnapshot],
        *,
        actor: str,
        actor_type: ActorType,
        occurred_at: datetime | str | None = None,
    ) -> list[ProposeEvent]:
        proposed_snapshots = list(snapshots)
        if not proposed_snapshots:
            raise RelationServiceError(
                "proposal batch must not be empty"
            )
        proposal_ids = [
            _new_proposal_id() for _snapshot in proposed_snapshots
        ]

        def build(folded: FoldedRelationLog) -> list[ProposeEvent]:
            _ensure_unique_active_child_claims(
                folded,
                proposed_snapshots,
            )
            return [
                ProposeEvent(
                    schemaVersion=1,
                    eventId=_new_event_id(),
                    proposalId=proposal_id,
                    eventType="propose",
                    occurredAt=_event_time(occurred_at),
                    actor=actor,
                    actorType=actor_type,
                    snapshot=proposed_snapshot,
                )
                for proposal_id, proposed_snapshot in zip(
                    proposal_ids,
                    proposed_snapshots,
                )
            ]

        events = self._append_many_under_lock(build)
        if not all(isinstance(event, ProposeEvent) for event in events):
            raise AssertionError("create_many built a non-propose event")
        return cast(list[ProposeEvent], events)

    def request_changes(
        self,
        proposal_id: str,
        *,
        actor: str,
        comment: str,
        occurred_at: datetime | str | None = None,
    ) -> RequestChangesEvent:
        def build(
            _folded: FoldedRelationLog,
        ) -> RequestChangesEvent:
            return RequestChangesEvent(
                schemaVersion=1,
                eventId=_new_event_id(),
                proposalId=proposal_id,
                eventType="request_changes",
                occurredAt=_event_time(occurred_at),
                actor=actor,
                actorType="human",
                comment=comment,
            )

        event = self._append_many_under_lock(
            lambda folded: [build(folded)]
        )[0]
        if not isinstance(event, RequestChangesEvent):
            raise TypeError("request_changes built an unexpected event")
        return event

    def revise(
        self,
        proposal_id: str,
        snapshot: ProposalSnapshot,
        *,
        actor: str,
        actor_type: ActorType,
        response: str,
        occurred_at: datetime | str | None = None,
    ) -> ReviseEvent:
        def build(folded: FoldedRelationLog) -> ReviseEvent:
            _ensure_unique_active_child_claims(
                folded,
                [snapshot],
                exclude_proposal_id=proposal_id,
            )
            return ReviseEvent(
                schemaVersion=1,
                eventId=_new_event_id(),
                proposalId=proposal_id,
                eventType="revise",
                occurredAt=_event_time(occurred_at),
                actor=actor,
                actorType=actor_type,
                response=response,
                snapshot=snapshot,
            )

        event = self._append_many_under_lock(
            lambda folded: [build(folded)]
        )[0]
        if not isinstance(event, ReviseEvent):
            raise TypeError("revise built an unexpected event")
        return event

    def approve(
        self,
        proposal_id: str,
        *,
        actor: str,
        comment: str | None = None,
        occurred_at: datetime | str | None = None,
    ) -> ApproveEvent:
        def build(_folded: FoldedRelationLog) -> ApproveEvent:
            return ApproveEvent(
                schemaVersion=1,
                eventId=_new_event_id(),
                proposalId=proposal_id,
                eventType="approve",
                occurredAt=_event_time(occurred_at),
                actor=actor,
                actorType="human",
                comment=comment,
            )

        event = self._append_many_under_lock(
            lambda folded: [build(folded)]
        )[0]
        if not isinstance(event, ApproveEvent):
            raise TypeError("approve built an unexpected event")
        return event

    def reject(
        self,
        proposal_id: str,
        *,
        actor: str,
        comment: str | None = None,
        occurred_at: datetime | str | None = None,
    ) -> RejectEvent:
        def build(_folded: FoldedRelationLog) -> RejectEvent:
            return RejectEvent(
                schemaVersion=1,
                eventId=_new_event_id(),
                proposalId=proposal_id,
                eventType="reject",
                occurredAt=_event_time(occurred_at),
                actor=actor,
                actorType="human",
                comment=comment,
            )

        event = self._append_many_under_lock(
            lambda folded: [build(folded)]
        )[0]
        if not isinstance(event, RejectEvent):
            raise TypeError("reject built an unexpected event")
        return event

    def retract(
        self,
        proposal_id: str,
        *,
        actor: str,
        reason: str,
        occurred_at: datetime | str | None = None,
    ) -> RetractEvent:
        def build(_folded: FoldedRelationLog) -> RetractEvent:
            return RetractEvent(
                schemaVersion=1,
                eventId=_new_event_id(),
                proposalId=proposal_id,
                eventType="retract",
                occurredAt=_event_time(occurred_at),
                actor=actor,
                actorType="human",
                reason=reason,
            )

        event = self._append_many_under_lock(
            lambda folded: [build(folded)]
        )[0]
        if not isinstance(event, RetractEvent):
            raise TypeError("retract built an unexpected event")
        return event

    def get(self, proposal_id: str) -> ProposalState:
        state = self._fold_current().proposals.get(proposal_id)
        if state is None:
            raise RelationServiceError(
                f"proposal {proposal_id} does not exist"
            )
        return state

    def list_proposals(
        self,
        *,
        status: ProposalStatus | None = None,
    ) -> list[ProposalState]:
        states = self._fold_current().proposals.values()
        if status is not None:
            states = (
                state
                for state in states
                if state.status == status
            )
        return sorted(
            states,
            key=lambda state: state.proposalId,
        )
