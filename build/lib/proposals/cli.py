from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from pydantic import ValidationError

from config import Settings
from proposals.log import ProposalState, RelationLogError
from proposals.models import ProposalSnapshot, RelationEvent, RetrievalMetadata
from proposals.policy import RelationPolicyError
from proposals.service import (
    RelationEventService,
    RelationServiceError,
)


STATUSES = (
    "pending",
    "changes_requested",
    "accepted",
    "rejected",
    "retracted",
)


def _add_snapshot_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--subject", required=True)
    parser.add_argument(
        "--predicate",
        required=True,
        choices=("CHILD_OF", "SIMILAR_TO"),
    )
    parser.add_argument("--object", required=True)
    parser.add_argument("--dimension")
    parser.add_argument("--rationale", required=True)
    parser.add_argument(
        "--evidence",
        action="append",
        required=True,
        metavar="SOURCE=EXCERPT",
    )
    parser.add_argument(
        "--producer-kind",
        required=True,
        choices=("human", "ai", "rule"),
    )
    parser.add_argument("--producer-name", required=True)
    parser.add_argument("--producer-version")
    parser.add_argument("--retrieval-score", type=float)
    parser.add_argument("--candidate-rank", type=int)
    parser.add_argument("--candidate-set-size", type=int)
    parser.add_argument("--embedding-model")
    parser.add_argument("--subject-text-hash")
    parser.add_argument("--object-text-hash")
    parser.add_argument("--actor", required=True)
    parser.add_argument(
        "--actor-type",
        required=True,
        choices=("human", "ai", "rule"),
    )


def _parser(
    *,
    default_policy: str,
    default_events: str,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Review durable Weakness relation proposals"
    )
    parser.add_argument("--policy", default=default_policy)
    parser.add_argument("--events", default=default_events)
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    create = commands.add_parser("create")
    _add_snapshot_arguments(create)

    request = commands.add_parser("request-changes")
    request.add_argument("proposal_id")
    request.add_argument("--actor", required=True)
    request.add_argument("--comment", required=True)

    revise = commands.add_parser("revise")
    revise.add_argument("proposal_id")
    revise.add_argument("--response", required=True)
    _add_snapshot_arguments(revise)

    for name in ("approve", "reject"):
        decision = commands.add_parser(name)
        decision.add_argument("proposal_id")
        decision.add_argument("--actor", required=True)
        decision.add_argument("--comment")

    retract = commands.add_parser("retract")
    retract.add_argument("proposal_id")
    retract.add_argument("--actor", required=True)
    retract.add_argument("--reason", required=True)

    show = commands.add_parser("show")
    show.add_argument("proposal_id")

    list_command = commands.add_parser("list")
    list_command.add_argument(
        "--status",
        choices=STATUSES,
    )
    return parser


def _evidence(values: list[str]) -> list[dict[str, str]]:
    evidence = []
    for value in values:
        source, separator, excerpt = value.partition("=")
        if not separator or not source.strip() or not excerpt.strip():
            raise RelationServiceError(
                "--evidence must use non-empty SOURCE=EXCERPT"
            )
        evidence.append(
            {
                "sourceRef": source,
                "excerpt": excerpt,
            }
        )
    return evidence


def _snapshot(arguments: argparse.Namespace) -> ProposalSnapshot:
    retrieval_values = (
        arguments.retrieval_score,
        arguments.candidate_rank,
        arguments.candidate_set_size,
        arguments.embedding_model,
        arguments.subject_text_hash,
        arguments.object_text_hash,
    )
    retrieval = None
    if any(value is not None for value in retrieval_values):
        if any(value is None for value in retrieval_values):
            raise RelationServiceError(
                "all retrieval audit arguments are required together"
            )
        retrieval = RetrievalMetadata(
            score=arguments.retrieval_score,
            scoreType="cosine_similarity",
            candidateRank=arguments.candidate_rank,
            candidateSetSize=arguments.candidate_set_size,
            embeddingModel=arguments.embedding_model,
            subjectTextHash=arguments.subject_text_hash,
            objectTextHash=arguments.object_text_hash,
        )
    return ProposalSnapshot(
        subjectWeaknessId=arguments.subject,
        predicate=arguments.predicate,
        objectWeaknessId=arguments.object,
        dimension=arguments.dimension,
        rationale=arguments.rationale,
        evidence=_evidence(arguments.evidence),
        producerKind=arguments.producer_kind,
        producerName=arguments.producer_name,
        producerVersion=arguments.producer_version,
        retrieval=retrieval,
    )


def _event_dict(event: RelationEvent) -> dict[str, Any]:
    return event.model_dump(
        mode="json",
        exclude_none=True,
    )


def _state_dict(state: ProposalState) -> dict[str, Any]:
    return {
        "proposalId": state.proposalId,
        "status": state.status,
        "revision": state.revision,
        "snapshot": state.snapshot.model_dump(mode="json"),
        "fingerprint": state.fingerprint,
        "createdAt": state.createdAt.isoformat(),
        "updatedAt": state.updatedAt.isoformat(),
        "acceptedBy": state.acceptedBy,
        "acceptedAt": (
            state.acceptedAt.isoformat()
            if state.acceptedAt is not None
            else None
        ),
        "retractedBy": state.retractedBy,
        "retractedAt": (
            state.retractedAt.isoformat()
            if state.retractedAt is not None
            else None
        ),
        "retractionReason": state.retractionReason,
        "events": [
            _event_dict(event) for event in state.events
        ],
    }


def _execute(
    service: RelationEventService,
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
    if arguments.command == "retract":
        return _event_dict(
            service.retract(
                arguments.proposal_id,
                actor=arguments.actor,
                reason=arguments.reason,
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
    raise RelationServiceError(
        f"unsupported command {arguments.command}"
    )


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    arguments = _parser(
        default_policy=settings.relation_policy,
        default_events=settings.relation_event_log,
    ).parse_args(argv)
    try:
        service = RelationEventService(
            arguments.policy,
            arguments.events,
        )
        result = _execute(service, arguments)
    except (
        RelationPolicyError,
        RelationLogError,
        RelationServiceError,
        ValidationError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
