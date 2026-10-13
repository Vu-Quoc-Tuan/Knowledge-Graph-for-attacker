"""Preflight and materialize durable relation proposal state."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from db.sink import GraphSink
from proposals.log import (
    FoldedRelationLog,
    ProposalState,
    RelationLogError,
    canonical_endpoints,
    fold_relation_events,
)
from proposals.models import (
    ProposalSnapshot,
    ProposeEvent,
    ReviseEvent,
)
from proposals.policy import RelationPolicy
from schema.models import RelationEventNode, RelationProposal


LOCAL_REVIEW_SOURCE = "local-human-review"
ASSERTED_TRUST = "asserted"


class RelationMaterializationError(ValueError):
    """Folded proposal state conflicts with the current graph."""


@dataclass(frozen=True)
class _ChildAssertion:
    child: str
    parent: str
    state: ProposalState
    props: dict[str, Any]


@dataclass(frozen=True)
class _SimilarityAssertion:
    left: str
    right: str
    states: tuple[ProposalState, ...]
    props: dict[str, Any]


@dataclass(frozen=True)
class _Preflight:
    children: tuple[_ChildAssertion, ...]
    similarities: tuple[_SimilarityAssertion, ...]
    subject_revisions: dict[tuple[str, str], list[int]]
    object_revisions: dict[tuple[str, str], list[int]]


def _timestamp(value) -> str:
    return value.isoformat()


def _snapshot_endpoints(
    snapshot: ProposalSnapshot,
    policy: RelationPolicy,
) -> tuple[str, str]:
    try:
        return canonical_endpoints(snapshot, policy)
    except RelationLogError as exc:
        raise RelationMaterializationError(str(exc)) from exc


def _snapshot_history(
    state: ProposalState,
) -> Iterable[tuple[int, ProposalSnapshot]]:
    revision = 0
    for event in state.events:
        if isinstance(event, ProposeEvent):
            revision = 1
            yield revision, event.snapshot
        elif isinstance(event, ReviseEvent):
            revision += 1
            yield revision, event.snapshot


def _proposal_graph_model(
    state: ProposalState,
) -> RelationProposal:
    snapshot = state.snapshot
    retrieval = snapshot.retrieval
    return RelationProposal(
        proposalId=state.proposalId,
        status=state.status,
        revision=state.revision,
        fingerprint=state.fingerprint,
        subjectWeaknessId=snapshot.subjectWeaknessId,
        predicate=snapshot.predicate,
        objectWeaknessId=snapshot.objectWeaknessId,
        dimension=snapshot.dimension,
        rationale=snapshot.rationale,
        evidenceSourceRefs=[
            item.sourceRef for item in snapshot.evidence
        ],
        evidenceExcerpts=[
            item.excerpt for item in snapshot.evidence
        ],
        producerKind=snapshot.producerKind,
        producerName=snapshot.producerName,
        producerVersion=snapshot.producerVersion,
        retrievalScore=retrieval.score if retrieval else None,
        retrievalScoreType=retrieval.scoreType if retrieval else None,
        candidateRank=retrieval.candidateRank if retrieval else None,
        candidateSetSize=retrieval.candidateSetSize if retrieval else None,
        embeddingModel=retrieval.embeddingModel if retrieval else None,
        subjectTextHash=retrieval.subjectTextHash if retrieval else None,
        objectTextHash=retrieval.objectTextHash if retrieval else None,
        createdAt=_timestamp(state.createdAt),
        updatedAt=_timestamp(state.updatedAt),
        acceptedBy=state.acceptedBy,
        acceptedAt=(
            _timestamp(state.acceptedAt)
            if state.acceptedAt is not None
            else None
        ),
        retractedBy=state.retractedBy,
        retractedAt=(
            _timestamp(state.retractedAt)
            if state.retractedAt is not None
            else None
        ),
        retractionReason=state.retractionReason,
    )


def _event_graph_model(event) -> RelationEventNode:
    snapshot = getattr(event, "snapshot", None)
    retrieval = snapshot.retrieval if snapshot else None
    return RelationEventNode(
        eventId=event.eventId,
        proposalId=event.proposalId,
        schemaVersion=event.schemaVersion,
        eventType=event.eventType,
        occurredAt=_timestamp(event.occurredAt),
        actor=event.actor,
        actorType=event.actorType,
        comment=getattr(event, "comment", None),
        response=getattr(event, "response", None),
        reason=getattr(event, "reason", None),
        subjectWeaknessId=(
            snapshot.subjectWeaknessId if snapshot else None
        ),
        predicate=snapshot.predicate if snapshot else None,
        objectWeaknessId=(
            snapshot.objectWeaknessId if snapshot else None
        ),
        dimension=snapshot.dimension if snapshot else None,
        rationale=snapshot.rationale if snapshot else None,
        producerKind=(
            snapshot.producerKind if snapshot else None
        ),
        producerName=(
            snapshot.producerName if snapshot else None
        ),
        producerVersion=(
            snapshot.producerVersion if snapshot else None
        ),
        retrievalScore=retrieval.score if retrieval else None,
        retrievalScoreType=retrieval.scoreType if retrieval else None,
        candidateRank=retrieval.candidateRank if retrieval else None,
        candidateSetSize=retrieval.candidateSetSize if retrieval else None,
        embeddingModel=retrieval.embeddingModel if retrieval else None,
        subjectTextHash=retrieval.subjectTextHash if retrieval else None,
        objectTextHash=retrieval.objectTextHash if retrieval else None,
        evidenceSourceRefs=(
            [item.sourceRef for item in snapshot.evidence]
            if snapshot
            else None
        ),
        evidenceExcerpts=(
            [item.excerpt for item in snapshot.evidence]
            if snapshot
            else None
        ),
    )


def _child_props(state: ProposalState) -> dict[str, Any]:
    if state.acceptedBy is None or state.acceptedAt is None:
        raise RelationMaterializationError(
            f"{state.proposalId}: accepted proposal is missing "
            "review provenance"
        )
    return {
        "source": LOCAL_REVIEW_SOURCE,
        "trustLevel": ASSERTED_TRUST,
        "proposalId": state.proposalId,
        "assertedBy": state.acceptedBy,
        "assertedAt": _timestamp(state.acceptedAt),
        "rationale": state.snapshot.rationale,
        "evidenceSourceRefs": [
            item.sourceRef for item in state.snapshot.evidence
        ],
        "evidenceExcerpts": [
            item.excerpt for item in state.snapshot.evidence
        ],
    }


def _similarity_props(
    states: tuple[ProposalState, ...],
) -> dict[str, Any]:
    for state in states:
        if state.acceptedBy is None or state.acceptedAt is None:
            raise RelationMaterializationError(
                f"{state.proposalId}: accepted proposal is missing "
                "review provenance"
            )
    return {
        "source": LOCAL_REVIEW_SOURCE,
        "trustLevel": ASSERTED_TRUST,
        "dimensions": [
            state.snapshot.dimension for state in states
        ],
        "proposalIds": [
            state.proposalId for state in states
        ],
        "assertedBy": [
            state.acceptedBy for state in states
        ],
        "assertedAt": [
            _timestamp(state.acceptedAt)
            for state in states
        ],
        "rationales": [
            state.snapshot.rationale for state in states
        ],
        "evidenceSourceRefs": [
            item.sourceRef
            for state in states
            for item in state.snapshot.evidence
        ],
        "evidenceExcerpts": [
            item.excerpt
            for state in states
            for item in state.snapshot.evidence
        ],
    }


def _existing_by_pair(
    sink: GraphSink,
    relation_type: str,
    *,
    symmetric: bool = False,
) -> dict[tuple[str, str], dict[str, Any]]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for relation in sink.match_rels(
        relation_type,
        from_label="Weakness",
        to_label="Weakness",
    ):
        raw_pair = (
            relation["from_value"],
            relation["to_value"],
        )
        pair = (
            tuple(sorted(raw_pair))
            if symmetric
            else raw_pair
        )
        if symmetric and raw_pair != pair:
            raise RelationMaterializationError(
                "non-canonical existing SIMILAR_TO edge "
                f"{raw_pair}; rerun with --reset"
            )
        if pair in found:
            raise RelationMaterializationError(
                f"multiple existing {relation_type} edges for {pair}"
            )
        found[pair] = relation
    return found


def _plain_node(node: dict[str, Any]) -> dict[str, Any]:
    props = dict(node)
    props.pop("_label", None)
    return props


def _assert_audit_nodes_match(
    sink: GraphSink,
    folded: FoldedRelationLog,
) -> None:
    expected_proposals = set(folded.proposals)
    existing_proposals = {
        node["proposalId"]
        for node in sink.nodes("RelationProposal")
    }
    stale_proposals = sorted(
        existing_proposals - expected_proposals
    )
    if stale_proposals:
        raise RelationMaterializationError(
            f"stale RelationProposal nodes {stale_proposals}; "
            "rerun with --reset"
        )

    expected_events = {
        event.eventId: _event_graph_model(event).to_props()
        for event in folded.events
    }
    existing_events = {
        node["eventId"]: _plain_node(node)
        for node in sink.nodes("RelationEvent")
    }
    stale_events = sorted(
        set(existing_events) - set(expected_events)
    )
    if stale_events:
        raise RelationMaterializationError(
            f"stale RelationEvent nodes {stale_events}; "
            "rerun with --reset"
        )
    for event_id in sorted(
        set(existing_events) & set(expected_events)
    ):
        if existing_events[event_id] != expected_events[event_id]:
            raise RelationMaterializationError(
                f"immutable RelationEvent {event_id} differs "
                "from relation event log; rerun with --reset"
            )


def _assert_existing_edges_match(
    *,
    relation_type: str,
    existing: dict[tuple[str, str], dict[str, Any]],
    expected: dict[tuple[str, str], dict[str, Any]],
) -> None:
    for pair, props in expected.items():
        relation = existing.get(pair)
        if relation is None:
            continue
        current = relation["props"]
        source = current.get("source", "unknown")
        if source != LOCAL_REVIEW_SOURCE:
            raise RelationMaterializationError(
                f"{pair}: conflicts with existing {source} "
                f"{relation_type}"
            )
        if current != props:
            raise RelationMaterializationError(
                f"{pair}: existing local {relation_type} "
                "does not match relation event log; rerun with --reset"
            )

    stale = sorted(
        pair
        for pair, relation in existing.items()
        if relation["props"].get("source")
        == LOCAL_REVIEW_SOURCE
        and pair not in expected
    )
    if stale:
        raise RelationMaterializationError(
            f"stale local {relation_type} edges {stale}; "
            "rerun with --reset"
        )


def _assert_acyclic(
    pairs: set[tuple[str, str]],
) -> None:
    adjacency: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    for child, parent in pairs:
        adjacency[child].add(parent)
        nodes.update((child, parent))

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, path: tuple[str, ...]) -> None:
        if node in visiting:
            cycle = " -> ".join((*path, node))
            raise RelationMaterializationError(
                f"CHILD_OF cycle detected: {cycle}"
            )
        if node in visited:
            return
        visiting.add(node)
        for parent in sorted(adjacency.get(node, ())):
            visit(parent, (*path, node))
        visiting.remove(node)
        visited.add(node)

    for node in sorted(nodes):
        visit(node, ())


def _preflight(
    sink: GraphSink,
    policy: RelationPolicy,
    folded: FoldedRelationLog,
) -> _Preflight:
    _assert_audit_nodes_match(sink, folded)

    subject_revisions: dict[
        tuple[str, str], list[int]
    ] = defaultdict(list)
    object_revisions: dict[
        tuple[str, str], list[int]
    ] = defaultdict(list)

    for proposal_id, state in sorted(
        folded.proposals.items()
    ):
        # Defend the materialization boundary even if a caller manually
        # constructs a FoldedRelationLog instead of using the strict folder.
        _snapshot_endpoints(state.snapshot, policy)
        for revision, snapshot in _snapshot_history(state):
            _snapshot_endpoints(snapshot, policy)
            for weakness_id in (
                snapshot.subjectWeaknessId,
                snapshot.objectWeaknessId,
            ):
                if sink.get_node(
                    "Weakness",
                    "weaknessId",
                    weakness_id,
                ) is None:
                    raise RelationMaterializationError(
                        f"{proposal_id}: missing Weakness endpoint "
                        f"{weakness_id}"
                    )
            subject_revisions[
                (proposal_id, snapshot.subjectWeaknessId)
            ].append(revision)
            object_revisions[
                (proposal_id, snapshot.objectWeaknessId)
            ].append(revision)

    try:
        replayed = fold_relation_events(
            folded.events, policy
        )
    except RelationLogError as exc:
        raise RelationMaterializationError(
            f"folded relation state cannot be replayed: {exc}"
        ) from exc
    if replayed != folded:
        raise RelationMaterializationError(
            "folded relation state does not match its immutable "
            "event history"
        )

    child_groups: dict[
        tuple[str, str], list[ProposalState]
    ] = defaultdict(list)
    similar_groups: dict[
        tuple[str, str], list[ProposalState]
    ] = defaultdict(list)
    for state in folded.proposals.values():
        if state.status != "accepted":
            continue
        left, right = _snapshot_endpoints(
            state.snapshot, policy
        )
        if state.snapshot.predicate == "CHILD_OF":
            child_groups[(left, right)].append(state)
        elif state.snapshot.predicate == "SIMILAR_TO":
            similar_groups[(left, right)].append(state)

    duplicate_children = sorted(
        pair
        for pair, states in child_groups.items()
        if len(states) > 1
    )
    if duplicate_children:
        raise RelationMaterializationError(
            "multiple accepted CHILD_OF proposals for "
            f"{duplicate_children}"
        )

    children = tuple(
        _ChildAssertion(
            child=pair[0],
            parent=pair[1],
            state=states[0],
            props=_child_props(states[0]),
        )
        for pair, states in sorted(child_groups.items())
    )
    similarities = tuple(
        _SimilarityAssertion(
            left=pair[0],
            right=pair[1],
            states=tuple(
                sorted(
                    states,
                    key=lambda state: (
                        state.snapshot.dimension or "",
                        state.proposalId,
                    ),
                )
            ),
            props=_similarity_props(
                tuple(
                    sorted(
                        states,
                        key=lambda state: (
                            state.snapshot.dimension or "",
                            state.proposalId,
                        ),
                    )
                )
            ),
        )
        for pair, states in sorted(similar_groups.items())
    )

    existing_children = _existing_by_pair(sink, "CHILD_OF")
    expected_children = {
        (item.child, item.parent): item.props
        for item in children
    }
    _assert_existing_edges_match(
        relation_type="CHILD_OF",
        existing=existing_children,
        expected=expected_children,
    )

    existing_similarities = _existing_by_pair(
        sink, "SIMILAR_TO", symmetric=True
    )
    expected_similarities = {
        (item.left, item.right): item.props
        for item in similarities
    }
    _assert_existing_edges_match(
        relation_type="SIMILAR_TO",
        existing=existing_similarities,
        expected=expected_similarities,
    )

    _assert_acyclic(
        set(existing_children) | set(expected_children)
    )
    return _Preflight(
        children=children,
        similarities=similarities,
        subject_revisions={
            key: sorted(set(revisions))
            for key, revisions in subject_revisions.items()
        },
        object_revisions={
            key: sorted(set(revisions))
            for key, revisions in object_revisions.items()
        },
    )


def materialize_relation_log(
    sink: GraphSink,
    policy: RelationPolicy,
    folded: FoldedRelationLog,
) -> dict[str, int | list[str]]:
    """Validate the complete relation view, then write it deterministically."""

    preflight = _preflight(sink, policy, folded)
    statuses = Counter(
        state.status for state in folded.proposals.values()
    )

    for proposal_id, state in sorted(
        folded.proposals.items()
    ):
        proposal = _proposal_graph_model(state)
        sink.merge_node(
            "RelationProposal",
            "proposalId",
            proposal.to_props(),
        )

    for (proposal_id, weakness_id), revisions in sorted(
        preflight.subject_revisions.items()
    ):
        sink.merge_rel(
            "RelationProposal",
            "proposalId",
            proposal_id,
            "SUBJECT",
            "Weakness",
            "weaknessId",
            weakness_id,
            {"revisions": revisions},
        )
    for (proposal_id, weakness_id), revisions in sorted(
        preflight.object_revisions.items()
    ):
        sink.merge_rel(
            "RelationProposal",
            "proposalId",
            proposal_id,
            "OBJECT",
            "Weakness",
            "weaknessId",
            weakness_id,
            {"revisions": revisions},
        )

    for event in folded.events:
        graph_event = _event_graph_model(event)
        sink.merge_node(
            "RelationEvent",
            "eventId",
            graph_event.to_props(),
        )
        sink.merge_rel(
            "RelationEvent",
            "eventId",
            event.eventId,
            "APPLIES_TO",
            "RelationProposal",
            "proposalId",
            event.proposalId,
        )

    for assertion in preflight.children:
        sink.merge_rel(
            "Weakness",
            "weaknessId",
            assertion.child,
            "CHILD_OF",
            "Weakness",
            "weaknessId",
            assertion.parent,
            assertion.props,
        )
    for assertion in preflight.similarities:
        sink.merge_rel(
            "Weakness",
            "weaknessId",
            assertion.left,
            "SIMILAR_TO",
            "Weakness",
            "weaknessId",
            assertion.right,
            assertion.props,
        )

    return {
        "proposals": len(folded.proposals),
        "pending": statuses["pending"],
        "changes_requested": statuses["changes_requested"],
        "accepted": statuses["accepted"],
        "rejected": statuses["rejected"],
        "retracted": statuses["retracted"],
        "review_events": len(folded.events),
        "materialized_child_of": len(preflight.children),
        "materialized_similar_to": len(
            preflight.similarities
        ),
        "reproposal_warnings": list(
            folded.reproposalWarnings
        ),
    }
