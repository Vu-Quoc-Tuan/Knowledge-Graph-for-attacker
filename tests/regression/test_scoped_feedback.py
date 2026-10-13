from datetime import datetime, timezone
import hashlib
from pathlib import Path
import tempfile


_ARTIFACT_DIR = tempfile.TemporaryDirectory()
_ARTIFACT = Path(_ARTIFACT_DIR.name) / "execution-receipt.json"
_ARTIFACT.write_bytes(b'{"verified":"execution"}')
_DIGEST = "sha256:" + hashlib.sha256(_ARTIFACT.read_bytes()).hexdigest()


def _repository():
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="Scenario", node_id="SCN-1", props={"scenario_id": "SCN-1", "scenario_revision": 2}),
        GraphNode(label="Environment", node_id="ENV-A", props={"environment_id": "ENV-A"}),
        GraphNode(label="Environment", node_id="ENV-B", props={"environment_id": "ENV-B"}),
        GraphNode(label="Evidence", node_id="EVID-execution", props={"content_digest": _DIGEST, "kind": "execution_receipt", "storage_uri": str(_ARTIFACT)}),
    ], edges=[])
    return repository


def _observation(identifier, result, environment="ENV-A"):
    from ckg.domain.entities.observation import ExecutionObservation

    return ExecutionObservation(observation_id=identifier, scenario_id="SCN-1", scenario_revision=2, environment_id=environment, result=result, observed_at=datetime(2026, 9, 14, tzinfo=timezone.utc), evidence_ids=("EVID-execution",), evidence_digests=(_DIGEST,))


def test_positive_feedback_updates_only_its_context_bucket_and_deduplicates_execution_id() -> None:
    from ckg.domain.entities.observation import ObservationResult
    from ckg.feedback.evidence_quality import ObservationQuality
    from ckg.feedback.updater import process_observation

    repository = _repository()
    quality = ObservationQuality(oracle_observable=True, environment_complete=True, source_evidence_present=True)
    first = process_observation(repository, observation=_observation("OBS-1", ObservationResult.REPRODUCED), scope_key="CWE-611|Python|lxml|config-a", quality=quality)
    retry = process_observation(repository, observation=_observation("OBS-1", ObservationResult.REPRODUCED), scope_key="CWE-611|Python|lxml|config-a", quality=quality)
    other = process_observation(repository, observation=_observation("OBS-2", ObservationResult.REPRODUCED, environment="ENV-B"), scope_key="CWE-611|Java|xerces|config-a", quality=quality)

    assert first.posterior.alpha == 2.0
    assert retry.deduplicated is True
    assert retry.posterior.alpha == 2.0
    assert other.posterior_id != first.posterior_id
    assert len(repository.nodes("ScopedBeliefPosterior")) == 2


def test_no_signal_without_observable_or_complete_conditions_is_not_negative_global_evidence() -> None:
    from ckg.domain.entities.observation import ObservationResult
    from ckg.feedback.evidence_quality import ObservationQuality
    from ckg.feedback.updater import process_observation

    repository = _repository()
    weak_quality = ObservationQuality(oracle_observable=False, environment_complete=False, source_evidence_present=True)
    result = process_observation(repository, observation=_observation("OBS-3", ObservationResult.NO_SIGNAL), scope_key="CWE-611|Python|lxml|config-a", quality=weak_quality)
    blocked = process_observation(repository, observation=_observation("OBS-4", ObservationResult.BLOCKED), scope_key="CWE-611|Python|lxml|config-a", quality=ObservationQuality(True, True, True))

    assert result.applied_weight == 0.0
    assert result.posterior.beta == 1.0
    assert blocked.applied_weight == 0.0
    assert blocked.posterior.beta == 1.0


def test_observation_receipt_and_replay_scope_conflict() -> None:
    import pytest
    from ckg.domain.entities.observation import ObservationResult
    from ckg.feedback.evidence_quality import ObservationQuality
    from ckg.feedback.updater import process_observation

    repository = _repository()
    quality = ObservationQuality(oracle_observable=True, environment_complete=True, source_evidence_present=True)
    obs = _observation("OBS-SCOPE-TEST", ObservationResult.REPRODUCED)
    process_observation(repository, observation=obs, scope_key="CWE-611|scope-1", quality=quality)

    # Check receipt
    receipts = [n for n in repository.nodes("ObservationReceipt") if n.node_id == "RECEIPT-OBS-SCOPE-TEST"]
    assert len(receipts) == 1
    assert receipts[0].props["scope_key"] == "CWE-611|scope-1"
    assert receipts[0].props["result"] == "REPRODUCED"

    # Replay with different scope must raise ValueError
    with pytest.raises(ValueError, match="recorded under a different scope"):
        process_observation(repository, observation=obs, scope_key="CWE-611|scope-2", quality=quality)


def test_feedback_loop_updates_next_scenario_confidence() -> None:
    from ckg.domain.entities.observation import ObservationResult
    from ckg.feedback.evidence_quality import ObservationQuality
    from ckg.feedback.updater import process_observation
    from ckg.scenario.discoverer import _apply_feedback_posteriors
    from ckg.domain.enums.scenario_type import ScenarioType
    from ckg.scenario.composer import compose

    repository = _repository()
    candidate = compose(
        target_vulnerability_id="CVE-2026-10001",
        scenario_type=ScenarioType.INHERITED,
        weakness_ids=("CWE-611",),
        relevance=0.8,
        evidence_coverage=0.8,
        derivation_ids=("D1",),
        premises=("p",),
    )

    # Before feedback: confidence is 0.8
    assert candidate.scenario.confidence.final == 0.8

    # Process positive feedback for SCN-1 (which maps to CWE-611)
    quality = ObservationQuality(True, True, True)
    process_observation(repository, observation=_observation("OBS-FEEDBACK", ObservationResult.REPRODUCED), scope_key="CWE-611|Python", quality=quality)

    # CWE-only scope cannot be applied to another candidate with an unknown
    # runtime/configuration context.
    updated = _apply_feedback_posteriors(repository, candidate)
    assert updated.scenario.confidence.historical_support is None
    assert updated.scenario.confidence.final == 0.8

    # Test direct EXECUTED_AS graph edge path
    candidate_direct = candidate.model_copy(
        update={"scenario": candidate.scenario.model_copy(update={"scenario_id": "SCN-1"})}
    )
    updated_direct = _apply_feedback_posteriors(repository, candidate_direct)
    assert updated_direct.scenario.confidence.historical_support is not None
    assert updated_direct.scenario.confidence.historical_support > 0.6


def test_atomic_environment_validation_rejects_without_writing() -> None:
    import pytest
    from ckg.domain.entities.observation import ExecutionObservation, ObservationResult
    from ckg.feedback.evidence_quality import ObservationQuality
    from ckg.feedback.updater import process_observation
    from ckg.graph.models import GraphNode

    repository = _repository()
    quality = ObservationQuality(oracle_observable=True, environment_complete=True, source_evidence_present=True)
    obs = ExecutionObservation(
        observation_id="OBS-ATOMIC",
        scenario_id="SCN-DOES-NOT-EXIST",
        scenario_revision=2,
        environment_id="ENV-NEW-ATOMIC",
        result=ObservationResult.REPRODUCED,
        observed_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
        evidence_ids=("EVID-execution",),
        evidence_digests=(_DIGEST,),
    )
    env_node = GraphNode(label="Environment", node_id="ENV-NEW-ATOMIC", props={"environment_id": "ENV-NEW-ATOMIC"})

    with pytest.raises(ValueError, match="unknown scenario"):
        process_observation(
            repository,
            observation=obs,
            scope_key="CWE-611|Python",
            quality=quality,
            environment_node=env_node,
        )

    # Ensure ENV-NEW-ATOMIC was NOT written to the repository
    assert "ENV-NEW-ATOMIC" not in {n.node_id for n in repository.nodes()}


def test_feedback_posterior_temporal_isolation() -> None:
    from ckg.domain.entities.observation import ExecutionObservation, ObservationResult
    from ckg.domain.enums.scenario_type import ScenarioType
    from ckg.feedback.evidence_quality import ObservationQuality
    from ckg.feedback.updater import process_observation
    from ckg.scenario.composer import compose
    from ckg.scenario.discoverer import _apply_feedback_posteriors

    repository = _repository()
    candidate = compose(
        target_vulnerability_id="CVE-2026-10001",
        scenario_type=ScenarioType.INHERITED,
        weakness_ids=("CWE-611",),
        relevance=0.8,
        evidence_coverage=0.8,
        derivation_ids=("D1",),
        premises=("p",),
    )

    t_observed = datetime(2026, 6, 1, tzinfo=timezone.utc)
    obs = ExecutionObservation(
        observation_id="OBS-TEMPORAL",
        scenario_id="SCN-1",
        scenario_revision=2,
        environment_id="ENV-A",
        result=ObservationResult.REPRODUCED,
        observed_at=t_observed,
        evidence_ids=("EVID-execution",),
        evidence_digests=(_DIGEST,),
    )
    quality = ObservationQuality(oracle_observable=True, environment_complete=True, source_evidence_present=True)
    process_observation(repository, observation=obs, scope_key="CWE-611|Python", quality=quality)

    t_past = datetime(2026, 1, 1, tzinfo=timezone.utc)
    past_applied = _apply_feedback_posteriors(repository, candidate, as_of=t_past)
    assert past_applied.scenario.confidence.final == 0.8
    assert past_applied.scenario.confidence.historical_support is None

    t_future = datetime(2026, 7, 1, tzinfo=timezone.utc)
    future_applied = _apply_feedback_posteriors(repository, candidate, as_of=t_future)
    assert future_applied.scenario.confidence.historical_support is None
    assert future_applied.scenario.confidence.final == 0.8


def test_late_observation_replays_posterior_without_future_leakage() -> None:
    from ckg.domain.entities.observation import ExecutionObservation, ObservationResult
    from ckg.feedback.evidence_quality import ObservationQuality
    from ckg.feedback.updater import process_observation
    from ckg.scenario.discoverer import _apply_feedback_posteriors
    from ckg.domain.enums.scenario_type import ScenarioType
    from ckg.scenario.composer import compose

    repository = _repository()
    quality = ObservationQuality(True, True, True)
    march = ExecutionObservation(
        observation_id="OBS-MARCH", scenario_id="SCN-1", scenario_revision=2, environment_id="ENV-A",
        result=ObservationResult.REPRODUCED, observed_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        evidence_ids=("EVID-execution",), evidence_digests=(_DIGEST,),
    )
    january = march.model_copy(update={"observation_id": "OBS-JAN", "observed_at": datetime(2026, 1, 1, tzinfo=timezone.utc)})
    process_observation(repository, observation=march, scope_key="SCN-1", quality=quality)
    process_observation(repository, observation=january, scope_key="SCN-1", quality=quality)

    candidate = compose(target_vulnerability_id="CVE-2026-10001", scenario_type=ScenarioType.INHERITED, weakness_ids=("CWE-611",), relevance=0.8, evidence_coverage=0.8, derivation_ids=("D1",), premises=("p",)).model_copy(
        update={"scenario": compose(target_vulnerability_id="CVE-2026-10001", scenario_type=ScenarioType.INHERITED, weakness_ids=("CWE-611",), relevance=0.8, evidence_coverage=0.8, derivation_ids=("D1",), premises=("p",)).scenario.model_copy(update={"scenario_id": "SCN-1"})}
    )
    february = _apply_feedback_posteriors(repository, candidate, as_of=datetime(2026, 2, 1, tzinfo=timezone.utc))
    april = _apply_feedback_posteriors(repository, candidate, as_of=datetime(2026, 4, 1, tzinfo=timezone.utc))
    assert february.scenario.confidence.historical_support == 2 / 3
    assert april.scenario.confidence.historical_support == 3 / 4
