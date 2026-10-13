"""CLI for extracted payload proposal review and validation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from config import Settings
from proposals.payload_log import (
    PayloadLogError,
    PayloadProposalState,
)
from proposals.payload_models import (
    PayloadEvent,
    PayloadProposalSnapshot,
    ValidationRecord,
)
from proposals.payload_service import (
    PayloadEventService,
    PayloadServiceError,
)


STATUSES = (
    "pending",
    "changes_requested",
    "tested",
    "accepted",
    "rejected",
)


def _snapshot_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--weakness", required=True)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--family-key", required=True)
    parser.add_argument("--family-name", required=True)
    parser.add_argument("--technology")
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-excerpt", required=True)
    parser.add_argument(
        "--producer-kind",
        required=True,
        choices=("human", "ai", "rule"),
    )
    parser.add_argument("--producer-name", required=True)
    parser.add_argument("--producer-version")
    parser.add_argument("--actor", required=True)
    parser.add_argument(
        "--actor-type",
        required=True,
        choices=("human", "ai", "rule"),
    )


def _parser(
    default_events: str,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Review and validate extracted payload proposals"
        )
    )
    parser.add_argument("--events", default=default_events)
    parser.add_argument(
        "--repo-root",
        default=str(Path.cwd()),
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    create = commands.add_parser("create")
    _snapshot_arguments(create)

    request = commands.add_parser("request-changes")
    request.add_argument("proposal_id")
    request.add_argument("--actor", required=True)
    request.add_argument("--comment", required=True)

    revise = commands.add_parser("revise")
    revise.add_argument("proposal_id")
    revise.add_argument("--response", required=True)
    _snapshot_arguments(revise)

    validate = commands.add_parser("record-validation")
    validate.add_argument("proposal_id")
    validate.add_argument("--revision", required=True, type=int)
    validate.add_argument(
        "--result",
        required=True,
        choices=("passed", "failed", "inconclusive"),
    )
    validate.add_argument("--environment", required=True)
    validate.add_argument("--target-ref", required=True)
    validate.add_argument("--target-hash", required=True)
    validate.add_argument("--execution-ref", required=True)
    validate.add_argument("--execution-hash", required=True)
    validate.add_argument("--observed-outcome", required=True)
    validate.add_argument("--evidence-ref", required=True)
    validate.add_argument("--evidence-hash", required=True)
    validate.add_argument("--comment")
    validate.add_argument("--actor", required=True)

    for name in ("approve", "reject"):
        decision = commands.add_parser(name)
        decision.add_argument("proposal_id")
        decision.add_argument("--actor", required=True)
        decision.add_argument("--comment")

    show = commands.add_parser("show")
    show.add_argument("proposal_id")

    list_command = commands.add_parser("list")
    list_command.add_argument("--status", choices=STATUSES)
    return parser


def _snapshot(
    arguments: argparse.Namespace,
) -> PayloadProposalSnapshot:
    return PayloadProposalSnapshot(
        weaknessId=arguments.weakness,
        payloadValue=arguments.payload,
        familyKey=arguments.family_key,
        familyName=arguments.family_name,
        technology=arguments.technology,
        rationale=arguments.rationale,
        sourceRef=arguments.source_ref,
        sourceExcerpt=arguments.source_excerpt,
        producerKind=arguments.producer_kind,
        producerName=arguments.producer_name,
        producerVersion=arguments.producer_version,
    )


def _event_dict(event: PayloadEvent) -> dict[str, Any]:
    return event.model_dump(
        mode="json",
        exclude_none=True,
    )


def _state_dict(
    state: PayloadProposalState,
) -> dict[str, Any]:
    return {
        "proposalId": state.proposalId,
        "status": state.status,
        "revision": state.revision,
        "snapshot": state.snapshot.model_dump(mode="json"),
        "fingerprint": state.fingerprint,
        "createdAt": state.createdAt.isoformat(),
        "updatedAt": state.updatedAt.isoformat(),
        "testedBy": state.testedBy,
        "testedAt": (
            state.testedAt.isoformat()
            if state.testedAt is not None
            else None
        ),
        "latestValidation": (
            state.latestValidation.model_dump(mode="json")
            if state.latestValidation is not None
            else None
        ),
        "acceptedBy": state.acceptedBy,
        "acceptedAt": (
            state.acceptedAt.isoformat()
            if state.acceptedAt is not None
            else None
        ),
        "events": [
            _event_dict(event) for event in state.events
        ],
    }


def _execute(
    service: PayloadEventService,
    arguments: argparse.Namespace,
) -> dict[str, Any] | list[dict[str, Any]]:
    if arguments.command == "create":
        return _event_dict(
            service.create(
                _snapshot(arguments),
                actor=arguments.actor,
                actor_type=arguments.actor_type,
            )
        )
    if arguments.command == "request-changes":
        return _event_dict(
            service.request_changes(
                arguments.proposal_id,
                actor=arguments.actor,
                comment=arguments.comment,
            )
        )
    if arguments.command == "revise":
        return _event_dict(
            service.revise(
                arguments.proposal_id,
                _snapshot(arguments),
                actor=arguments.actor,
                actor_type=arguments.actor_type,
                response=arguments.response,
            )
        )
    if arguments.command == "record-validation":
        return _event_dict(
            service.record_validation(
                arguments.proposal_id,
                ValidationRecord(
                    revision=arguments.revision,
                    result=arguments.result,
                    environment=arguments.environment,
                    targetRef=arguments.target_ref,
                    targetHash=arguments.target_hash,
                    executionRef=arguments.execution_ref,
                    executionHash=arguments.execution_hash,
                    observedOutcome=arguments.observed_outcome,
                    evidenceRef=arguments.evidence_ref,
                    evidenceHash=arguments.evidence_hash,
                    comment=arguments.comment,
                ),
                actor=arguments.actor,
            )
        )
    if arguments.command == "approve":
        return _event_dict(
            service.approve(
                arguments.proposal_id,
                actor=arguments.actor,
                comment=arguments.comment,
            )
        )
    if arguments.command == "reject":
        return _event_dict(
            service.reject(
                arguments.proposal_id,
                actor=arguments.actor,
                comment=arguments.comment,
            )
        )
    if arguments.command == "show":
        return _state_dict(
            service.get(arguments.proposal_id)
        )
    if arguments.command == "list":
        return [
            _state_dict(state)
            for state in service.list_proposals(
                status=arguments.status
            )
        ]
    raise PayloadServiceError(
        f"unsupported command {arguments.command}"
    )


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    arguments = _parser(
        settings.payload_event_log
    ).parse_args(argv)
    try:
        result = _execute(
            PayloadEventService(
                arguments.events,
                arguments.repo_root,
            ),
            arguments,
        )
    except (
        PayloadLogError,
        PayloadServiceError,
        ValidationError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
