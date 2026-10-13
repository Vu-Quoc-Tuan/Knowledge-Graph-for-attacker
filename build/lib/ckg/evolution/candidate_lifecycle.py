"""Candidate promotion plus an append-only status history event."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from ckg.domain.enums.fact_status import FactStatus
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository


def advance(status: FactStatus, *, independent_evidence_count: int, verified: bool = False, rejected: bool = False) -> FactStatus:
    """Promotion policy for noncanonical candidates; canonical status is immutable here."""
    if status == FactStatus.CANONICAL:
        return status
    # Terminal adjudications cannot be silently overwritten by a later batch
    # with weaker/missing support. Re-opening them is an explicit curator
    # workflow, not an automatic lifecycle transition.
    if status in {FactStatus.VALIDATED, FactStatus.REJECTED}:
        return status
    if rejected:
        return FactStatus.REJECTED
    if verified:
        return FactStatus.VALIDATED
    if independent_evidence_count >= 2:
        return FactStatus.SUPPORTED
    return FactStatus.INFERRED


@dataclass(frozen=True)
class CandidateTransition:
    candidate_id: str
    previous_status: FactStatus
    current_status: FactStatus
    event_id: str


def transition_candidate(
    repository: GraphRepository,
    *,
    candidate_id: str,
    independent_evidence_count: int,
    transitioned_at: datetime,
    verified: bool = False,
    rejected: bool = False,
) -> CandidateTransition:
    """Persist an idempotent promotion without losing the old epistemic state."""
    candidate = next((node for node in repository.nodes("CandidateRelation") if node.node_id == candidate_id), None)
    if candidate is None:
        raise ValueError(f"candidate relation does not exist: {candidate_id}")
    previous = FactStatus(candidate.props.get("status", FactStatus.INFERRED))
    current = advance(previous, independent_evidence_count=independent_evidence_count, verified=verified, rejected=rejected)
    if current == previous:
        return CandidateTransition(candidate_id, previous, current, "")
    event_id = "CANDIDATE-STATUS-" + hashlib.sha256(f"{candidate_id}|{previous.value}|{current.value}|{transitioned_at.isoformat()}".encode()).hexdigest()[:24]
    updated = GraphNode(label=candidate.label, node_id=candidate.node_id, props={**candidate.props, "status": current.value, "independent_evidence_count": independent_evidence_count})
    event = GraphNode(label="CandidateStatusEvent", node_id=event_id, props={"candidate_id": candidate_id, "previous_status": previous.value, "current_status": current.value, "transitioned_at": transitioned_at.isoformat(), "verified": verified, "rejected": rejected})
    repository.atomic_write(nodes=[updated, event], edges=[GraphEdge(edge_id=f"EDGE-CANDIDATE-STATUS-{event_id}", edge_type="HAS_STATUS_EVENT", subject_id=candidate_id, object_id=event_id)])
    return CandidateTransition(candidate_id, previous, current, event_id)
