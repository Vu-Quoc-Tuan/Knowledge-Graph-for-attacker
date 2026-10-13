from ckg.constraints.evaluator import EnvironmentSnapshot, evaluate
from ckg.domain.enums.applicability import Applicability


def test_all_any_not_preserve_three_valued_logic() -> None:
    environment = EnvironmentSnapshot(
        environment_id="ENV-1",
        configuration={"external_entities": True},
        network={"dns_egress": None},
    )
    expression = {
        "all": [
            {"kind": "configuration", "key": "external_entities", "equals": True},
            {"any": [
                {"kind": "network", "key": "dns_egress", "equals": True},
                {"kind": "network", "key": "http_egress", "equals": True},
            ]},
        ]
    }

    result = evaluate(expression, environment)

    assert result.applicability == Applicability.UNKNOWN
    assert result.satisfied == ("$/all/0",)
    assert "$/all/1/any/0" in result.unknown


def test_unsatisfied_constraint_dominates_unknown_in_all() -> None:
    result = evaluate(
        {"all": [
            {"kind": "configuration", "key": "external_entities", "equals": True},
            {"kind": "network", "key": "dns_egress", "equals": True},
        ]},
        EnvironmentSnapshot(environment_id="ENV-2", configuration={"external_entities": False}, network={"dns_egress": None}),
    )

    assert result.applicability == Applicability.NOT_APPLICABLE
    assert result.unsatisfied == ("$/all/0",)
    assert result.unknown == ("$/all/1",)


def test_not_unknown_and_unparseable_versions_are_unknown_not_false() -> None:
    unknown_not = evaluate({"not": {"kind": "feature", "key": "xxe", "equals": True}}, EnvironmentSnapshot(environment_id="ENV-3", features={"xxe": None}))
    invalid_version = evaluate({"kind": "version", "operator": "<", "value": "2.0"}, EnvironmentSnapshot(environment_id="ENV-3", version="dev-build"))

    assert unknown_not.applicability == Applicability.UNKNOWN
    assert invalid_version.applicability == Applicability.UNKNOWN


def test_missing_constraint_definition_makes_scenario_applicability_unknown() -> None:
    from ckg.domain.enums.fact_status import FactStatus
    from ckg.domain.enums.scenario_type import ScenarioType
    from ckg.domain.value_objects.confidence import Confidence
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode
    from ckg.scenario.composer import compose
    from ckg.scenario.discoverer import _apply_constraints

    repository = InMemoryGraphRepository()
    candidate = compose(
        target_vulnerability_id="CVE-2026-10001",
        scenario_type=ScenarioType.NOVEL,
        weakness_ids=("CWE-611",),
        constraint_ids=("CONSTRAINT-KNOWN", "CONSTRAINT-MISSING"),
        relevance=0.7,
        evidence_coverage=0.7,
        derivation_ids=("source",),
        premises=("test",),
    )
    repository.atomic_write(nodes=[
        GraphNode(
            label="ApplicabilityConstraint",
            node_id="CONSTRAINT-KNOWN",
            props={"expression": '{"kind":"network","key":"dns_egress","equals":true}'},
        ),
    ], edges=[])

    evaluated = _apply_constraints(
        repository,
        candidate,
        EnvironmentSnapshot(environment_id="ENV", network={"dns_egress": True}),
    )
    assert evaluated.scenario.applicability == Applicability.UNKNOWN


def test_scenario_composer_requires_explicit_confidence_inputs() -> None:
    from ckg.domain.enums.scenario_type import ScenarioType
    from ckg.scenario.composer import compose

    try:
        compose(
            target_vulnerability_id="CVE-2026-10001",
            scenario_type=ScenarioType.NOVEL,
            weakness_ids=("CWE-611",),
            derivation_ids=("source",),
            premises=("test",),
        )
    except TypeError as error:
        assert "relevance" in str(error)
    else:
        raise AssertionError("scenario confidence must be explicit")
