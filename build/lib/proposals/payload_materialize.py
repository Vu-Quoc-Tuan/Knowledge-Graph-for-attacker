"""Preflight and materialize reviewed extracted payloads."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from utils.payloads import (
    ASSERTED_TRUST_LEVEL,
    LOCAL_REVIEW_PAYLOAD_SOURCE,
    TESTED_VALIDATION_STATUS,
    payload_id,
)
from db.sink import GraphSink
from proposals.payload_log import (
    FoldedPayloadLog,
    PayloadLogError,
    PayloadProposalState,
    fold_payload_events,
)
from proposals.payload_models import (
    PayloadProposalSnapshot,
    ProposePayloadEvent,
    RecordPayloadValidationEvent,
    RevisePayloadEvent,
)
from schema.models import (
    Payload,
    PayloadEventNode,
    PayloadFamily,
    PayloadProposal,
    Technology,
)


class PayloadMaterializationError(ValueError):
    """Folded payload state conflicts with the current graph."""


def _local_payload_origin(
    states: tuple[PayloadProposalState, ...],
) -> str:
    producer_kinds = {
        state.snapshot.producerKind for state in states
    }
    if "ai" in producer_kinds:
        return "ai_extracted"
    if "rule" in producer_kinds:
        return "rule_extracted"
    return "local_manual"


@dataclass(frozen=True)
class _AcceptedPayload:
    payloadId: str
    snapshot: PayloadProposalSnapshot
    states: tuple[PayloadProposalState, ...]
    exists: bool


@dataclass(frozen=True)
class _Assertion:
    payloadId: str
    weaknessId: str
    states: tuple[PayloadProposalState, ...]
    props: dict[str, Any]


@dataclass(frozen=True)
class _Preflight:
    payloads: tuple[_AcceptedPayload, ...]
    assertions: tuple[_Assertion, ...]
    proposal_targets: dict[tuple[str, str], list[int]]
    families: dict[str, str]
    technologies: tuple[str, ...]


def _timestamp(value) -> str:
    return value.isoformat()


def _snapshot_history(
    state: PayloadProposalState,
) -> Iterable[tuple[int, PayloadProposalSnapshot]]:
    revision = 0
    for event in state.events:
        if isinstance(event, ProposePayloadEvent):
            revision = 1
            yield revision, event.snapshot
        elif isinstance(event, RevisePayloadEvent):
            revision += 1
            yield revision, event.snapshot


def _proposal_model(
    state: PayloadProposalState,
) -> PayloadProposal:
    snapshot = state.snapshot
    return PayloadProposal(
        proposalId=state.proposalId,
        status=state.status,
        revision=state.revision,
        fingerprint=state.fingerprint,
        weaknessId=snapshot.weaknessId,
        payloadValue=snapshot.payloadValue,
        familyKey=snapshot.familyKey,
        familyName=snapshot.familyName,
        technology=snapshot.technology,
        rationale=snapshot.rationale,
        sourceRef=snapshot.sourceRef,
        sourceExcerpt=snapshot.sourceExcerpt,
        producerKind=snapshot.producerKind,
        producerName=snapshot.producerName,
        producerVersion=snapshot.producerVersion,
        createdAt=_timestamp(state.createdAt),
        updatedAt=_timestamp(state.updatedAt),
        latestValidationResult=(
            state.latestValidation.result
            if state.latestValidation is not None
            else None
        ),
        testedBy=state.testedBy,
        testedAt=(
            _timestamp(state.testedAt)
            if state.testedAt is not None
            else None
        ),
        acceptedBy=state.acceptedBy,
        acceptedAt=(
            _timestamp(state.acceptedAt)
            if state.acceptedAt is not None
            else None
        ),
    )


def _event_model(event) -> PayloadEventNode:
    snapshot = getattr(event, "snapshot", None)
    validation = getattr(event, "validation", None)
    comment = getattr(event, "comment", None)
    if validation is not None and comment is None:
        comment = validation.comment
    return PayloadEventNode(
        eventId=event.eventId,
        proposalId=event.proposalId,
        schemaVersion=event.schemaVersion,
        eventType=event.eventType,
        occurredAt=_timestamp(event.occurredAt),
        actor=event.actor,
        actorType=event.actorType,
        comment=comment,
        response=getattr(event, "response", None),
        weaknessId=snapshot.weaknessId if snapshot else None,
        payloadValue=snapshot.payloadValue if snapshot else None,
        familyKey=snapshot.familyKey if snapshot else None,
        familyName=snapshot.familyName if snapshot else None,
        technology=snapshot.technology if snapshot else None,
        rationale=snapshot.rationale if snapshot else None,
        sourceRef=snapshot.sourceRef if snapshot else None,
        sourceExcerpt=(
            snapshot.sourceExcerpt if snapshot else None
        ),
        producerKind=snapshot.producerKind if snapshot else None,
        producerName=snapshot.producerName if snapshot else None,
        producerVersion=(
            snapshot.producerVersion if snapshot else None
        ),
        validationRevision=(
            validation.revision if validation else None
        ),
        validationResult=(
            validation.result if validation else None
        ),
        validationEnvironment=(
            validation.environment if validation else None
        ),
        validationTargetRef=(
            validation.targetRef if validation else None
        ),
        validationTargetHash=(
            validation.targetHash if validation else None
        ),
        validationExecutionRef=(
            validation.executionRef if validation else None
        ),
        validationExecutionHash=(
            validation.executionHash if validation else None
        ),
        validationObservedOutcome=(
            validation.observedOutcome if validation else None
        ),
        validationEvidenceRef=(
            validation.evidenceRef if validation else None
        ),
        validationEvidenceHash=(
            validation.evidenceHash if validation else None
        ),
    )


def _plain(node: dict[str, Any]) -> dict[str, Any]:
    result = dict(node)
    result.pop("_label", None)
    return result


def _assert_audit_matches(
    sink: GraphSink,
    folded: FoldedPayloadLog,
) -> None:
    expected_proposals = set(folded.proposals)
    existing_proposals = {
        node["proposalId"]
        for node in sink.nodes("PayloadProposal")
    }
    stale_proposals = sorted(
        existing_proposals - expected_proposals
    )
    if stale_proposals:
        raise PayloadMaterializationError(
            f"stale PayloadProposal nodes {stale_proposals}; "
            "rerun with --reset"
        )

    expected_events = {
        event.eventId: _event_model(event).to_props()
        for event in folded.events
    }
    existing_events = {
        node["eventId"]: _plain(node)
        for node in sink.nodes("PayloadEvent")
    }
    stale_events = sorted(
        set(existing_events) - set(expected_events)
    )
    if stale_events:
        raise PayloadMaterializationError(
            f"stale PayloadEvent nodes {stale_events}; "
            "rerun with --reset"
        )
    for event_id in sorted(
        set(existing_events) & set(expected_events)
    ):
        if existing_events[event_id] != expected_events[event_id]:
            raise PayloadMaterializationError(
                f"immutable PayloadEvent {event_id} differs "
                "from payload event log; rerun with --reset"
            )

    expected_targets: dict[
        tuple[str, str], list[int]
    ] = defaultdict(list)
    for proposal_id, state in folded.proposals.items():
        for revision, snapshot in _snapshot_history(state):
            expected_targets[
                (proposal_id, snapshot.weaknessId)
            ].append(revision)
    for relation in sink.match_rels(
        "TARGETS",
        from_label="PayloadProposal",
        to_label="Weakness",
    ):
        pair = (
            relation["from_value"],
            relation["to_value"],
        )
        expected_revisions = expected_targets.get(pair)
        if expected_revisions is None:
            raise PayloadMaterializationError(
                f"stale PayloadProposal TARGETS audit relationship "
                f"{pair}; rerun with --reset"
            )
        props = relation["props"]
        current_revisions = props.get("revisions")
        if (
            set(props) != {"revisions"}
            or not isinstance(current_revisions, list)
            or not current_revisions
            or current_revisions
            != expected_revisions[: len(current_revisions)]
        ):
            raise PayloadMaterializationError(
                f"PayloadProposal TARGETS audit relationship "
                f"{pair} differs from payload event log; "
                "rerun with --reset"
            )

    expected_event_links = {
        (event.eventId, event.proposalId)
        for event in folded.events
    }
    for relation in sink.match_rels(
        "APPLIES_TO",
        from_label="PayloadEvent",
        to_label="PayloadProposal",
    ):
        pair = (
            relation["from_value"],
            relation["to_value"],
        )
        if (
            pair not in expected_event_links
            or relation["props"]
        ):
            raise PayloadMaterializationError(
                f"PayloadEvent APPLIES_TO audit relationship "
                f"{pair} differs from payload event log; "
                "rerun with --reset"
            )

    expected_materializations = {
        (
            state.proposalId,
            payload_id(
                state.snapshot.familyKey,
                state.snapshot.payloadValue,
                state.snapshot.technology,
            ),
        )
        for state in folded.proposals.values()
        if state.status == "accepted"
    }
    for relation in sink.match_rels(
        "MATERIALIZES",
        from_label="PayloadProposal",
        to_label="Payload",
    ):
        pair = (
            relation["from_value"],
            relation["to_value"],
        )
        if (
            pair not in expected_materializations
            or relation["props"]
        ):
            raise PayloadMaterializationError(
                f"PayloadProposal MATERIALIZES audit relationship "
                f"{pair} differs from accepted payloads; "
                "rerun with --reset"
            )


def _assertion_props(
    states: tuple[PayloadProposalState, ...],
) -> dict[str, Any]:
    for state in states:
        if (
            state.acceptedBy is None
            or state.acceptedAt is None
            or state.testedBy is None
            or state.testedAt is None
            or state.latestValidation is None
            or state.latestValidation.result != "passed"
        ):
            raise PayloadMaterializationError(
                f"{state.proposalId}: accepted payload is missing "
                "test or review provenance"
            )
    return {
        "source": LOCAL_REVIEW_PAYLOAD_SOURCE,
        "trustLevel": ASSERTED_TRUST_LEVEL,
        "origins": sorted(
            {
                _local_payload_origin((state,))
                for state in states
            }
        ),
        "curationStatus": "human_reviewed",
        "validationStatus": TESTED_VALIDATION_STATUS,
        "proposalIds": [
            state.proposalId for state in states
        ],
        "sourceRefs": [
            state.snapshot.sourceRef for state in states
        ],
        "testedBy": [
            state.testedBy for state in states
        ],
        "testedAt": [
            _timestamp(state.testedAt) for state in states
        ],
        "validationEvidenceRefs": [
            state.latestValidation.evidenceRef
            for state in states
        ],
        "acceptedBy": [
            state.acceptedBy for state in states
        ],
        "acceptedAt": [
            _timestamp(state.acceptedAt) for state in states
        ],
    }


def _assert_existing_targets(
    sink: GraphSink,
    expected: dict[tuple[str, str], dict[str, Any]],
) -> None:
    existing: dict[tuple[str, str], dict[str, Any]] = {}
    for relation in sink.match_rels(
        "TARGETS",
        from_label="Payload",
        to_label="Weakness",
    ):
        pair = (
            relation["from_value"],
            relation["to_value"],
        )
        if pair in existing:
            raise PayloadMaterializationError(
                f"multiple Payload TARGETS edges for {pair}"
            )
        existing[pair] = relation["props"]

    for pair, props in expected.items():
        current = existing.get(pair)
        if current is None:
            continue
        if current.get("source") != LOCAL_REVIEW_PAYLOAD_SOURCE:
            raise PayloadMaterializationError(
                f"{pair}: conflicts with existing non-local "
                "Payload TARGETS assertion"
            )
        if current != props:
            raise PayloadMaterializationError(
                f"{pair}: existing reviewed Payload TARGETS "
                "does not match event log; rerun with --reset"
            )

    stale = sorted(
        pair
        for pair, props in existing.items()
        if props.get("source") == LOCAL_REVIEW_PAYLOAD_SOURCE
        and pair not in expected
    )
    if stale:
        raise PayloadMaterializationError(
            f"stale reviewed Payload TARGETS edges {stale}; "
            "rerun with --reset"
        )


def _preflight(
    sink: GraphSink,
    folded: FoldedPayloadLog,
) -> _Preflight:
    try:
        replayed = fold_payload_events(
            folded.events,
            folded.repoRoot,
        )
    except PayloadLogError as exc:
        raise PayloadMaterializationError(
            f"folded payload state cannot be replayed: {exc}"
        ) from exc
    if replayed != folded:
        raise PayloadMaterializationError(
            "folded payload state does not match its immutable "
            "event history"
        )

    _assert_audit_matches(sink, folded)
    proposal_targets: dict[
        tuple[str, str], list[int]
    ] = defaultdict(list)
    for proposal_id, state in sorted(
        folded.proposals.items()
    ):
        for revision, snapshot in _snapshot_history(state):
            if sink.get_node(
                "Weakness",
                "weaknessId",
                snapshot.weaknessId,
            ) is None:
                raise PayloadMaterializationError(
                    f"{proposal_id}: missing Weakness endpoint "
                    f"{snapshot.weaknessId}"
                )
            proposal_targets[
                (proposal_id, snapshot.weaknessId)
            ].append(revision)

    accepted_by_payload: dict[
        str, list[PayloadProposalState]
    ] = defaultdict(list)
    assertion_groups: dict[
        tuple[str, str], list[PayloadProposalState]
    ] = defaultdict(list)
    families: dict[str, str] = {}
    technologies: set[str] = set()
    for state in folded.proposals.values():
        if state.status != "accepted":
            continue
        snapshot = state.snapshot
        identifier = payload_id(
            snapshot.familyKey,
            snapshot.payloadValue,
            snapshot.technology,
        )
        accepted_by_payload[identifier].append(state)
        assertion_groups[
            (identifier, snapshot.weaknessId)
        ].append(state)
        current_name = families.setdefault(
            snapshot.familyKey,
            snapshot.familyName,
        )
        if current_name != snapshot.familyName:
            raise PayloadMaterializationError(
                f"{snapshot.familyKey}: accepted proposals "
                "disagree on family name"
            )
        if snapshot.technology:
            technologies.add(snapshot.technology)

    payloads: list[_AcceptedPayload] = []
    for identifier, states in sorted(
        accepted_by_payload.items()
    ):
        ordered = tuple(
            sorted(states, key=lambda item: item.proposalId)
        )
        values = {
            state.snapshot.payloadValue for state in ordered
        }
        if len(values) != 1:
            raise PayloadMaterializationError(
                f"{identifier}: payload identity collision"
            )
        existing = sink.get_node(
            "Payload",
            "payloadId",
            identifier,
        )
        if (
            existing is not None
            and existing.get("value")
            != ordered[0].snapshot.payloadValue
        ):
            raise PayloadMaterializationError(
                f"{identifier}: existing Payload value mismatch"
            )
        payloads.append(
            _AcceptedPayload(
                payloadId=identifier,
                snapshot=ordered[0].snapshot,
                states=ordered,
                exists=existing is not None,
            )
        )

    for family_key, family_name in sorted(families.items()):
        existing = sink.get_node(
            "PayloadFamily",
            "key",
            family_key,
        )
        if (
            existing is not None
            and existing.get("name") != family_name
        ):
            raise PayloadMaterializationError(
                f"{family_key}: existing family name "
                f"{existing.get('name')!r} does not match "
                f"{family_name!r}"
            )

    assertions = tuple(
        _Assertion(
            payloadId=pair[0],
            weaknessId=pair[1],
            states=tuple(
                sorted(
                    states,
                    key=lambda item: item.proposalId,
                )
            ),
            props=_assertion_props(
                tuple(
                    sorted(
                        states,
                        key=lambda item: item.proposalId,
                    )
                )
            ),
        )
        for pair, states in sorted(assertion_groups.items())
    )
    _assert_existing_targets(
        sink,
        {
            (item.payloadId, item.weaknessId): item.props
            for item in assertions
        },
    )
    return _Preflight(
        payloads=tuple(payloads),
        assertions=assertions,
        proposal_targets={
            key: sorted(set(revisions))
            for key, revisions in proposal_targets.items()
        },
        families=families,
        technologies=tuple(sorted(technologies)),
    )


def materialize_payload_log(
    sink: GraphSink,
    folded: FoldedPayloadLog,
) -> dict[str, int | list[str]]:
    """Validate the complete view, then write it deterministically."""

    preflight = _preflight(sink, folded)
    statuses = Counter(
        state.status for state in folded.proposals.values()
    )

    for proposal_id, state in sorted(
        folded.proposals.items()
    ):
        sink.merge_node(
            "PayloadProposal",
            "proposalId",
            _proposal_model(state).to_props(),
        )
    for (proposal_id, weakness_id), revisions in sorted(
        preflight.proposal_targets.items()
    ):
        sink.merge_rel(
            "PayloadProposal",
            "proposalId",
            proposal_id,
            "TARGETS",
            "Weakness",
            "weaknessId",
            weakness_id,
            {"revisions": revisions},
        )
    for event in folded.events:
        sink.merge_node(
            "PayloadEvent",
            "eventId",
            _event_model(event).to_props(),
        )
        sink.merge_rel(
            "PayloadEvent",
            "eventId",
            event.eventId,
            "APPLIES_TO",
            "PayloadProposal",
            "proposalId",
            event.proposalId,
        )

    for family_key, family_name in sorted(
        preflight.families.items()
    ):
        if sink.get_node(
            "PayloadFamily", "key", family_key
        ) is None:
            sink.merge_node(
                "PayloadFamily",
                "key",
                PayloadFamily(
                    key=family_key,
                    name=family_name,
                    source=LOCAL_REVIEW_PAYLOAD_SOURCE,
                ).to_props(),
            )
    for technology in preflight.technologies:
        if sink.get_node(
            "Technology", "name", technology
        ) is None:
            sink.merge_node(
                "Technology",
                "name",
                Technology(name=technology).to_props(),
            )
    for accepted in preflight.payloads:
        if not accepted.exists:
            sink.merge_node(
                "Payload",
                "payloadId",
                Payload(
                    payloadId=accepted.payloadId,
                    value=accepted.snapshot.payloadValue,
                    source=LOCAL_REVIEW_PAYLOAD_SOURCE,
                    origin=_local_payload_origin(accepted.states),
                    curationStatus="human_reviewed",
                    validationStatus=TESTED_VALIDATION_STATUS,
                ).to_props(),
            )
        sink.merge_rel(
            "Payload",
            "payloadId",
            accepted.payloadId,
            "IN_FAMILY",
            "PayloadFamily",
            "key",
            accepted.snapshot.familyKey,
        )
        if accepted.snapshot.technology:
            sink.merge_rel(
                "Payload",
                "payloadId",
                accepted.payloadId,
                "ON_TECH",
                "Technology",
                "name",
                accepted.snapshot.technology,
            )
        for state in accepted.states:
            sink.merge_rel(
                "PayloadProposal",
                "proposalId",
                state.proposalId,
                "MATERIALIZES",
                "Payload",
                "payloadId",
                accepted.payloadId,
            )
    for assertion in preflight.assertions:
        sink.merge_rel(
            "Payload",
            "payloadId",
            assertion.payloadId,
            "TARGETS",
            "Weakness",
            "weaknessId",
            assertion.weaknessId,
            assertion.props,
        )

    validations = [
        event
        for event in folded.events
        if isinstance(event, RecordPayloadValidationEvent)
    ]
    return {
        "proposals": len(folded.proposals),
        "pending": statuses["pending"],
        "changes_requested": statuses["changes_requested"],
        "tested": statuses["tested"],
        "accepted": statuses["accepted"],
        "rejected": statuses["rejected"],
        "validation_events": len(validations),
        "failed_validations": sum(
            event.validation.result == "failed"
            for event in validations
        ),
        "inconclusive_validations": sum(
            event.validation.result == "inconclusive"
            for event in validations
        ),
        "materialized_payloads": len(preflight.payloads),
        "materialized_assertions": len(
            preflight.assertions
        ),
        "reproposal_warnings": list(
            folded.reproposalWarnings
        ),
    }
