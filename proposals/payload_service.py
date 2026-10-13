"""Locked durable operations for extracted payload proposals."""

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

from proposals.payload_log import (
    FoldedPayloadLog,
    PayloadLogError,
    PayloadProposalState,
    fold_payload_events,
    parse_payload_event_lines,
    read_payload_events,
)
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
from proposals.file_lock import lock_file, unlock_file
from proposals.cache import EventFoldCheckpoint


ActorType = Literal["human", "ai", "rule"]
PayloadStatus = Literal[
    "pending",
    "changes_requested",
    "tested",
    "accepted",
    "rejected",
]


class PayloadServiceError(ValueError):
    """A requested payload proposal operation cannot complete."""


def _lock_file(fd: int) -> None:
    lock_file(
        fd,
        posix_backend=fcntl,
        windows_backend=msvcrt,
        error_type=PayloadServiceError,
        resource_name="payload proposal log",
    )


def _unlock_file(fd: int) -> None:
    unlock_file(fd, posix_backend=fcntl, windows_backend=msvcrt)


def _event_id() -> str:
    return f"PAY-EVT-{uuid4()}"


def _proposal_id() -> str:
    return f"PAY-PROP-{uuid4()}"


def _event_time(
    occurred_at: datetime | str | None,
) -> datetime | str:
    return (
        datetime.now(timezone.utc)
        if occurred_at is None
        else occurred_at
    )


class PayloadEventService:
    """Read-fold-append operations over one payload event log."""

    def __init__(
        self,
        event_path: str | Path,
        repo_root: str | Path,
    ) -> None:
        self.event_path = Path(event_path)
        self.repo_root = Path(repo_root)
        self._checkpoint: EventFoldCheckpoint[FoldedPayloadLog] = EventFoldCheckpoint(
            self.event_path
        )

    def _fold_current(self) -> FoldedPayloadLog:
        return self._checkpoint.get(
            lambda: fold_payload_events(
                read_payload_events(self.event_path),
                self.repo_root,
            )
        )

    def _append_many_under_lock(
        self,
        build_events: Callable[
            [FoldedPayloadLog], Sequence[PayloadEvent]
        ],
    ) -> list[PayloadEvent]:
        if not self.event_path.is_file():
            raise PayloadLogError(
                f"{self.event_path}: "
                "payload event log does not exist"
            )
        try:
            stream = self.event_path.open(
                "r+",
                encoding="utf-8",
                newline="",
            )
        except (OSError, UnicodeError) as exc:
            raise PayloadLogError(
                f"{self.event_path}: cannot open "
                f"payload event log: {exc}"
            ) from exc

        with stream:
            _lock_file(stream.fileno())
            try:
                stream.seek(0)
                try:
                    lines = stream.read().splitlines()
                except (OSError, UnicodeError) as exc:
                    raise PayloadLogError(
                        f"{self.event_path}: cannot read "
                        f"payload event log: {exc}"
                    ) from exc
                events = parse_payload_event_lines(
                    lines,
                    source=self.event_path,
                )
                folded = fold_payload_events(
                    events,
                    self.repo_root,
                )
                new_events = list(build_events(folded))
                if not new_events:
                    raise PayloadServiceError(
                        "event batch must not be empty"
                    )
                fold_payload_events(
                    [*events, *new_events],
                    self.repo_root,
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
        snapshot: PayloadProposalSnapshot,
        *,
        actor: str,
        actor_type: ActorType,
        occurred_at: datetime | str | None = None,
    ) -> ProposePayloadEvent:
        return self.create_many(
            [snapshot],
            actor=actor,
            actor_type=actor_type,
            occurred_at=occurred_at,
        )[0]

    def create_many(
        self,
        snapshots: Sequence[PayloadProposalSnapshot],
        *,
        actor: str,
        actor_type: ActorType,
        occurred_at: datetime | str | None = None,
    ) -> list[ProposePayloadEvent]:
        proposed_snapshots = list(snapshots)
        if not proposed_snapshots:
            raise PayloadServiceError(
                "proposal batch must not be empty"
            )
        proposal_ids = [
            _proposal_id() for _snapshot in proposed_snapshots
        ]

        def build(_folded: FoldedPayloadLog) -> list[ProposePayloadEvent]:
            return [
                ProposePayloadEvent(
                    schemaVersion=1,
                    eventId=_event_id(),
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
        if not all(
            isinstance(event, ProposePayloadEvent)
            for event in events
        ):
            raise AssertionError(
                "create_many built a non-propose payload event"
            )
        return cast(list[ProposePayloadEvent], events)

    def request_changes(
        self,
        proposal_id: str,
        *,
        actor: str,
        comment: str,
        occurred_at: datetime | str | None = None,
    ) -> RequestPayloadChangesEvent:
        def build(_folded: FoldedPayloadLog):
            return RequestPayloadChangesEvent(
                schemaVersion=1,
                eventId=_event_id(),
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
        if not isinstance(event, RequestPayloadChangesEvent):
            raise TypeError("request_changes built an unexpected event")
        return event

    def revise(
        self,
        proposal_id: str,
        snapshot: PayloadProposalSnapshot,
        *,
        actor: str,
        actor_type: ActorType,
        response: str,
        occurred_at: datetime | str | None = None,
    ) -> RevisePayloadEvent:
        def build(_folded: FoldedPayloadLog):
            return RevisePayloadEvent(
                schemaVersion=1,
                eventId=_event_id(),
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
        if not isinstance(event, RevisePayloadEvent):
            raise TypeError("revise built an unexpected event")
        return event

    def record_validation(
        self,
        proposal_id: str,
        validation: ValidationRecord,
        *,
        actor: str,
        occurred_at: datetime | str | None = None,
    ) -> RecordPayloadValidationEvent:
        def build(_folded: FoldedPayloadLog):
            return RecordPayloadValidationEvent(
                schemaVersion=1,
                eventId=_event_id(),
                proposalId=proposal_id,
                eventType="record_validation",
                occurredAt=_event_time(occurred_at),
                actor=actor,
                actorType="human",
                validation=validation,
            )

        event = self._append_many_under_lock(
            lambda folded: [build(folded)]
        )[0]
        if not isinstance(event, RecordPayloadValidationEvent):
            raise TypeError("record_validation built an unexpected event")
        return event

    def approve(
        self,
        proposal_id: str,
        *,
        actor: str,
        comment: str | None = None,
        occurred_at: datetime | str | None = None,
    ) -> ApprovePayloadEvent:
        def build(_folded: FoldedPayloadLog):
            return ApprovePayloadEvent(
                schemaVersion=1,
                eventId=_event_id(),
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
        if not isinstance(event, ApprovePayloadEvent):
            raise TypeError("approve built an unexpected event")
        return event

    def reject(
        self,
        proposal_id: str,
        *,
        actor: str,
        comment: str | None = None,
        occurred_at: datetime | str | None = None,
    ) -> RejectPayloadEvent:
        def build(_folded: FoldedPayloadLog):
            return RejectPayloadEvent(
                schemaVersion=1,
                eventId=_event_id(),
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
        if not isinstance(event, RejectPayloadEvent):
            raise TypeError("reject built an unexpected event")
        return event

    def get(
        self,
        proposal_id: str,
    ) -> PayloadProposalState:
        state = self._fold_current().proposals.get(proposal_id)
        if state is None:
            raise PayloadServiceError(
                f"proposal {proposal_id} does not exist"
            )
        return state

    def list_proposals(
        self,
        *,
        status: PayloadStatus | None = None,
    ) -> list[PayloadProposalState]:
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
