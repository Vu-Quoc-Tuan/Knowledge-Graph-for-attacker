from db.sink import DryRunSink
from retrieval.queries import scenario_card, scenarios_of
from schema.models import Scenario, Weakness


def test_scenarios_of_never_inherits_from_similar_weakness() -> None:
    sink = DryRunSink()
    for weakness_id, namespace in (("LOCAL-1", "LOCAL"), ("CWE-89", "CWE")):
        sink.merge_node(
            "Weakness",
            "weaknessId",
            Weakness(weaknessId=weakness_id, namespace=namespace).to_props(),
        )
    sink.merge_node(
        "Scenario",
        "scenarioId",
        Scenario(scenarioId="SCN-CWE-89-sqli.generic").to_props(),
    )
    sink.merge_rel(
        "Scenario",
        "scenarioId",
        "SCN-CWE-89-sqli.generic",
        "TARGETS",
        "Weakness",
        "weaknessId",
        "CWE-89",
    )
    sink.merge_rel(
        "Weakness",
        "weaknessId",
        "LOCAL-1",
        "SIMILAR_TO",
        "Weakness",
        "weaknessId",
        "CWE-89",
        {"dimensions": ["mechanism"]},
    )

    assert scenarios_of(sink, "LOCAL-1") == []
    direct = scenario_card(sink, "SCN-CWE-89-sqli.generic")
    assert direct is not None
    assert direct["testReady"] is False
