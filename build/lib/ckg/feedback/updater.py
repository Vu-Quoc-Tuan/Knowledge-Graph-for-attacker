"""Execution feedback is scoped and idempotent; it never mutates canonical CWE."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from ckg.domain.entities.observation import ExecutionObservation, ObservationResult
from ckg.feedback.bayesian import BetaPosterior
from ckg.feedback.evidence_quality import ObservationQuality, update_weight
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository


import threading

_FEEDBACK_LOCK = threading.Lock()


@dataclass(frozen=True)
class FeedbackUpdate:
    posterior_id: str
    posterior: BetaPosterior
    applied_weight: float
    deduplicated: bool


def _posterior_id(scope_key: str) -> str:
    return "BETA-" + hashlib.sha256(scope_key.encode()).hexdigest()[:24]


def _apply_result(current: BetaPosterior, result: ObservationResult, weight: float) -> BetaPosterior:
    if result == ObservationResult.REPRODUCED:
        return current.positive(weight)
    if result == ObservationResult.NO_SIGNAL:
        return current.negative(weight)
    return current


def _validate_observation_targets(
    existing: dict[str, GraphNode],
    observation: ExecutionObservation,
    environment_node: GraphNode | None = None,
) -> None:
    scenario = existing.get(observation.scenario_id)
    environment = existing.get(observation.environment_id)
    if environment is None and environment_node is not None and environment_node.node_id == observation.environment_id:
        environment = environment_node
    if scenario is None or scenario.label != "Scenario":
        raise ValueError(f"unknown scenario: {observation.scenario_id}")
    if scenario.props.get("scenario_revision") != observation.scenario_revision:
        raise ValueError(f"scenario revision mismatch: {observation.scenario_id}")
    if environment is None or environment.label != "Environment":
        raise ValueError(f"unknown environment: {observation.environment_id}")
    if len(observation.evidence_ids) != len(observation.evidence_digests):
        raise ValueError("observation evidence IDs and digests must have equal length")
    for evidence_id, digest in zip(observation.evidence_ids, observation.evidence_digests, strict=True):
        evidence = existing.get(evidence_id)
        if evidence is None or evidence.label != "Evidence":
            raise ValueError(f"unknown execution evidence: {evidence_id}")
        if evidence.props.get("content_digest") != digest:
            raise ValueError(f"execution evidence digest mismatch: {evidence_id}")
        if evidence.props.get("kind") != "execution_receipt":
            raise ValueError(f"evidence is not an execution receipt: {evidence_id}")
        storage_uri = evidence.props.get("storage_uri")
        if not isinstance(storage_uri, str) or not Path(storage_uri).is_file():
            raise ValueError(f"execution evidence artifact does not exist: {evidence_id}")
        artifact_digest = "sha256:" + hashlib.sha256(Path(storage_uri).read_bytes()).hexdigest()
        if artifact_digest != digest:
            raise ValueError(f"execution evidence artifact digest mismatch: {evidence_id}")


def process_observation(
    repository: GraphRepository,
    *,
    observation: ExecutionObservation,
    scope_key: str,
    quality: ObservationQuality,
    environment_node: GraphNode | None = None,
) -> FeedbackUpdate:
    """Update only a caller-selected context bucket with transaction lock; global aggregation is separate."""
    with _FEEDBACK_LOCK:
        existing = {node.node_id: node for node in repository.nodes()}
        posterior_id = _posterior_id(scope_key)
        if observation.observation_id in existing:
            if existing[observation.observation_id].props != observation.model_dump(mode="json"):
                raise ValueError(f"observation ID conflicts with different payload: {observation.observation_id}")
            existing_updates = [e for e in repository.edges("UPDATES_BELIEF") if e.subject_id == observation.observation_id]
            if existing_updates and existing_updates[0].object_id != posterior_id:
                raise ValueError(f"observation {observation.observation_id} was already recorded under a different scope")
            posterior_node = existing.get(posterior_id)
            posterior = BetaPosterior(float(posterior_node.props["alpha"]), float(posterior_node.props["beta"])) if posterior_node else BetaPosterior()
            return FeedbackUpdate(posterior_id, posterior, 0.0, True)
        _validate_observation_targets(existing, observation, environment_node=environment_node)
        weight = update_weight(observation.result, quality)
        # Rebuild by observed time, not arrival time.  A delayed January
        # receipt must revise January's snapshot without putting March evidence
        # into a February historical query.
        prior: list[tuple[ExecutionObservation, float]] = []
        for node in existing.values():
            if node.label != "ExecutionObservation":
                continue
            receipt = existing.get(f"RECEIPT-{node.node_id}")
            if receipt is None or receipt.props.get("scope_key") != scope_key:
                continue
            prior.append((ExecutionObservation.model_validate(node.props), float(receipt.props.get("quality_weight", 0.0))))
        timeline = [*prior, (observation, weight)]
        timeline.sort(key=lambda item: (item[0].observed_at, item[0].observation_id))
        current = BetaPosterior()
        revision_nodes: list[GraphNode] = []
        for timed_observation, timed_weight in timeline:
            current = _apply_result(current, timed_observation.result, timed_weight)
            revision_nodes.append(
                GraphNode(
                    label="ScopedBeliefPosteriorRevision",
                    node_id=f"{posterior_id}-OBS-{timed_observation.observation_id}",
                    props={
                        "scope_key": scope_key,
                        "posterior_id": posterior_id,
                        "alpha": current.alpha,
                        "beta": current.beta,
                        "mean": current.mean,
                        "observed_at": timed_observation.observed_at.isoformat(),
                    },
                )
            )
        updated = current
        observation_node = GraphNode(label="ExecutionObservation", node_id=observation.observation_id, props=observation.model_dump(mode="json"))
        latest_observation = timeline[-1][0]
        posterior_node = GraphNode(label="ScopedBeliefPosterior", node_id=posterior_id, props={"scope_key": scope_key, "alpha": updated.alpha, "beta": updated.beta, "mean": updated.mean, "updated_at": latest_observation.observed_at.isoformat(), "observed_at": latest_observation.observed_at.isoformat()})
        receipt_node = GraphNode(
            label="ObservationReceipt",
            node_id=f"RECEIPT-{observation.observation_id}",
            props={
                "observation_id": observation.observation_id,
                "scope_key": scope_key,
                "quality_weight": weight,
                "scenario_revision": observation.scenario_revision,
                "posterior_id": posterior_id,
                "result": observation.result.value,
                "previous_mean": current.mean,
                "updated_mean": updated.mean,
            },
        )
        nodes_to_write = [observation_node, posterior_node, *revision_nodes, receipt_node]
        if environment_node is not None and environment_node.node_id not in existing:
            nodes_to_write.append(environment_node)
        repository.atomic_write(nodes=nodes_to_write, edges=[
            GraphEdge(edge_id=f"EDGE-OBSERVATION-SCENARIO-{observation.observation_id}", edge_type="EXECUTED_AS", subject_id=observation.observation_id, object_id=observation.scenario_id),
            GraphEdge(edge_id=f"EDGE-OBSERVATION-ENV-{observation.observation_id}", edge_type="IN_ENVIRONMENT", subject_id=observation.observation_id, object_id=observation.environment_id),
            GraphEdge(edge_id=f"EDGE-OBSERVATION-UPDATES-{observation.observation_id}-{posterior_id}", edge_type="UPDATES_BELIEF", subject_id=observation.observation_id, object_id=posterior_id, props={"quality_weight": weight}),
            GraphEdge(edge_id=f"EDGE-POSTERIOR-REVISION-{observation.observation_id}", edge_type="REVISES_POSTERIOR", subject_id=f"{posterior_id}-OBS-{observation.observation_id}", object_id=posterior_id),
            GraphEdge(edge_id=f"EDGE-RECEIPT-OBSERVATION-{observation.observation_id}", edge_type="RECEIPT_FOR", subject_id=receipt_node.node_id, object_id=observation.observation_id),
        ])
        return FeedbackUpdate(posterior_id, updated, weight, False)
