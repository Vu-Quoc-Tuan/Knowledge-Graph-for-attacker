from ckg.domain.entities.observation import ObservationResult
from ckg.feedback.evidence_quality import ObservationQuality, update_weight


def test_no_signal_without_source_evidence_has_zero_bayesian_weight() -> None:
    quality = ObservationQuality(
        oracle_observable=True,
        environment_complete=True,
        source_evidence_present=False,
    )

    assert update_weight(ObservationResult.NO_SIGNAL, quality) == 0.0


def test_feedback_rejects_unknown_or_mismatched_execution_evidence() -> None:
    from datetime import datetime, timezone
    from ckg.domain.entities.observation import ExecutionObservation
    from ckg.feedback.updater import process_observation
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="Scenario", node_id="SCN-1", props={"scenario_revision": 1}),
        GraphNode(label="Environment", node_id="ENV-1", props={}),
        GraphNode(label="Evidence", node_id="EVID-1", props={"content_digest": "sha256:" + "a" * 64}),
    ], edges=[])
    observation = ExecutionObservation(
        observation_id="OBS-1", scenario_id="SCN-1", environment_id="ENV-1",
        result=ObservationResult.REPRODUCED,
        observed_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
        evidence_ids=("EVID-1",), evidence_digests=("sha256:" + "b" * 64,),
    )

    try:
        process_observation(
            repository, observation=observation, scope_key="scope",
            quality=ObservationQuality(True, True, True),
        )
    except ValueError as error:
        assert "digest mismatch" in str(error)
    else:
        raise AssertionError("mismatched execution evidence must be rejected")
