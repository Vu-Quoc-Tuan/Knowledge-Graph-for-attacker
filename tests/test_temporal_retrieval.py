from pathlib import Path
import pytest

from db.sink import DryRunSink
from ingest.fragment_loader import load_fragments
from ingest.vulnerability_loader import load_vulnerabilities
from retrieval.scenario_planner import synthesize_candidate_scenario
from retrieval.vulnerability_card import vulnerability_card


@pytest.fixture
def populated_sink():
    sink = DryRunSink()
    load_vulnerabilities(sink, "registry/vulnerabilities.yaml")
    load_fragments(sink, "registry/scenario_fragments.yaml")
    return sink


def test_vulnerability_card_basic(populated_sink):
    card = vulnerability_card(populated_sink, "CVE-2024-44541")
    assert card is not None
    assert card["identity"]["vulnId"] == "CVE-2024-44541"
    assert card["product"]["name"] == "Fides"
    assert card["component"]["name"] == "fides.js"
    assert "< 2.45.1" in card["affectedVersions"]
    assert card["classification"]["weaknessId"] == "CWE-79"
    assert card["facts"]["inputVector"] == "URL_QUERY"
    assert card["facts"]["inputParameter"] == "fides_description"
    assert card["facts"]["mechanism"] == "UNSAFE_HTML_RENDER"

    # Fragments
    frag_ids = [f["fragmentId"] for f in card["applicableFragments"]]
    assert "FRAG-MUT-URL-QUERY-MARKER" in frag_ids
    assert "FRAG-TRIG-UI-RENDER" in frag_ids
    assert "FRAG-ORACLE-DOM-MARKER" in frag_ids


def test_temporal_isolation_anti_data_leakage(populated_sink):
    # Establish a future relationship discovered in 2025
    populated_sink.merge_rel(
        "Vulnerability",
        "vulnId",
        "CVE-2024-44541",
        "SIMILAR_TO",
        "Vulnerability",
        "vulnId",
        "CVE-2021-43798",
        {
            "dimension": "mechanism",
            "score": 0.88,
            "rationale": "Discovered in 2025 research",
            "knownAt": "2025-01-15T00:00:00Z",
        },
    )

    # 1. Querying at 2024 (before the relation was known)
    card_2024 = vulnerability_card(
        populated_sink,
        "CVE-2024-44541",
        as_of="2024-10-01T00:00:00Z",
    )
    assert card_2024 is not None
    # Zero data leakage: the 2025 relation MUST NOT be visible!
    assert len(card_2024["similarVulnerabilities"]) == 0

    # 2. Querying at 2025 (after the relation was known)
    card_2025 = vulnerability_card(
        populated_sink,
        "CVE-2024-44541",
        as_of="2025-02-01T00:00:00Z",
    )
    assert card_2025 is not None
    assert len(card_2025["similarVulnerabilities"]) == 1
    assert card_2025["similarVulnerabilities"][0]["targetVulnId"] == "CVE-2021-43798"
    assert card_2025["similarVulnerabilities"][0]["dimension"] == "mechanism"

    # 3. Querying at 2023 (before CVE-2024-44541 was even published in Sep 2024)
    card_2023 = vulnerability_card(
        populated_sink,
        "CVE-2024-44541",
        as_of="2023-01-01T00:00:00Z",
    )
    # The vulnerability was not yet published, so card is None
    assert card_2023 is None


def test_synthesize_candidate_scenario(populated_sink):
    candidate = synthesize_candidate_scenario(
        populated_sink,
        "CVE-2024-44541",
        canary_marker="__canary_val_99__",
    )
    assert candidate is not None
    assert candidate["candidateId"] == "SCN-CAND-CVE-2024-44541"
    assert candidate["targetVulnId"] == "CVE-2024-44541"
    assert candidate["status"] == "proposed"
    assert candidate["applicability"] == "unknown"
    assert candidate["hypothesis"]["sourceChannel"] == "URL_QUERY"
    assert candidate["hypothesis"]["mutationStrategy"] == "CONTROLLED_MARKER_INJECTION"
    assert candidate["hypothesis"]["oracleFamily"] == "UNENCODED_DOM_SINK"

    # Steps verification
    steps = candidate["steps"]
    assert len(steps) >= 3
    # Step 2 input mutation should have parameter fides_description and canary marker substituted
    mut_step = [s for s in steps if s["kind"] == "input_mutation"][0]
    assert "fides_description" in mut_step["action"]
    assert "__canary_val_99__" in mut_step["action"]

    # Trigger step should render component #fides.js
    trig_step = [s for s in steps if s["kind"] == "trigger"][0]
    assert "#fides.js" in trig_step["action"]
