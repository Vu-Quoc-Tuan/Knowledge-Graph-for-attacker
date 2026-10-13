import hashlib
from pathlib import Path
import pytest

from db.sink import DryRunSink
from ingest.fragment_loader import load_fragments
from ingest.vulnerability_loader import VulnerabilityEntry, load_vulnerabilities
from proposals.incremental_materialize import (
    incremental_materialize_scenario,
    incremental_materialize_vulnerability,
)
from proposals.scenario_models import (
    ScenarioValidationRecord,
    ValidatedScenarioRecord,
)
from retrieval.scenario_planner import synthesize_candidate_scenario
from retrieval.vulnerability_card import vulnerability_card


def test_closed_loop_knowledge_accumulation(tmp_path: Path):
    # ----------------------------------------------------
    # Stage 0: Initial Knowledge Graph KG_0
    # ----------------------------------------------------
    sink = DryRunSink()
    load_vulnerabilities(sink, "registry/vulnerabilities.yaml")
    load_fragments(sink, "registry/scenario_fragments.yaml")

    fides_id = "CVE-2024-44541"
    fides_card = vulnerability_card(sink, fides_id)
    assert fides_card is not None

    # Synthesize candidate scenario for Fides
    cand = synthesize_candidate_scenario(sink, fides_id, canary_marker="<canary_x>")
    assert cand is not None
    cand_id = cand["candidateId"]

    # ----------------------------------------------------
    # Stage 1: Lab Execution & Validation
    # ----------------------------------------------------
    artifact = tmp_path / "fides-run-01.json"
    artifact.write_bytes(b'{"receipt":"verified target execution"}')
    digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    val_record = ScenarioValidationRecord(
        validationId="VAL-1111222233334444",
        candidateId=cand_id,
        targetVulnId=fides_id,
        environment="isolated-docker-sandbox",
        vulnerableTargetResult="passed",
        patchedTargetResult="passed",
        observedOutcome="canary marker reflected into DOM unescaped on v2.45.0; properly sanitized on v2.45.1",
        executionDigest=digest,
        evidenceRef=str(artifact),
        evidenceHash=digest,
        validatedAt="2024-09-07T12:00:00Z",
        validatedBy="lead_pentester",
        executionMode="target",
        status="passed",
    )

    validated_scenario = ValidatedScenarioRecord(
        scenarioId=f"SCN-VALIDATED-{fides_id}",
        candidateId=cand_id,
        targetVulnId=fides_id,
        validationId=val_record.validationId,
        hypothesisId=cand["hypothesis"]["hypothesisId"],
        groundingScore=0.95,
        steps=cand["steps"],
        acceptedAt="2024-09-07T14:00:00Z",
        acceptedBy="security_architect",
    )

    # ----------------------------------------------------
    # Stage 2: Write Path — Re-ingest into KG (KG_0 -> KG_1)
    # ----------------------------------------------------
    mat_res = incremental_materialize_scenario(sink, validated_scenario, val_record)
    assert mat_res["scenarios"] == 1
    assert mat_res["edges"] == 3

    # Check edges in KG_1
    scn_node = sink.get_node("Scenario", "scenarioId", validated_scenario.scenarioId)
    assert scn_node is not None
    assert scn_node["testReady"] is True

    detected_by = sink.match_rels(
        "DETECTED_BY",
        from_label="Vulnerability",
        from_value=fides_id,
        to_label="Scenario",
        to_value=validated_scenario.scenarioId,
    )
    assert len(detected_by) == 1

    with pytest.raises(ValueError, match="synthetic"):
        incremental_materialize_scenario(
            sink,
            validated_scenario,
            val_record.model_copy(update={"executionMode": "synthetic"}),
        )

    # ----------------------------------------------------
    # Stage 3: A NEW Vulnerability arrives: CVE-2026-88888
    # ----------------------------------------------------
    new_vuln_entry = VulnerabilityEntry.model_validate({
        "vuln_id": "CVE-2026-88888",
        "title": "Reflected XSS in Customer Portal via query redirect",
        "description": "Unsanitized query parameter redirect_to is rendered into modal DOM.",
        "published_at": "2026-03-01T00:00:00Z",
        "cwe_id": "CWE-79",
        "epistemic_status": "observed",
        "product": {"name": "CustomerPortal", "vendor": "ACME"},
        "component": {"name": "auth_modal.js"},
        "facts": {
            "input_vector": "URL_QUERY",
            "input_parameter": "redirect_to",
            "mechanism": "UNSAFE_HTML_RENDER",
            "impact": "SCRIPT_EXECUTION",
        },
    })

    # Incrementally ingest new vuln into KG_1
    incremental_materialize_vulnerability(sink, new_vuln_entry)

    # Link SIMILAR_TO with Fides (which now has validated scenario)
    sink.merge_rel(
        "Vulnerability",
        "vulnId",
        "CVE-2026-88888",
        "SIMILAR_TO",
        "Vulnerability",
        "vulnId",
        fides_id,
        {
            "dimension": "mechanism",
            "score": 0.94,
            "rationale": "Identical DOM reflection mechanism and query input vector",
            "knownAt": "2026-03-02T00:00:00Z",
        },
    )

    # ----------------------------------------------------
    # Stage 4: Querying for CVE-2026-88888 benefits from KG_1
    # ----------------------------------------------------
    new_card = vulnerability_card(sink, "CVE-2026-88888", as_of="2026-03-05T00:00:00Z")
    assert new_card is not None
    assert len(new_card["similarVulnerabilities"]) >= 1
    top_similar = new_card["similarVulnerabilities"][0]
    assert top_similar["targetVulnId"] == fides_id
    assert top_similar["dimension"] == "mechanism"
    assert top_similar["score"] == 0.94

    # Synthesize candidate scenario for the new CVE
    new_candidate = synthesize_candidate_scenario(
        sink,
        "CVE-2026-88888",
        as_of="2026-03-05T00:00:00Z",
        canary_marker="__canary_2026__",
    )
    assert new_candidate is not None
    assert new_candidate["hypothesis"]["basedOnVulnId"] == fides_id
    assert new_candidate["groundingScore"] == 0.94

    # Step action should have substituted new vuln's parameter: redirect_to
    steps = new_candidate["steps"]
    mut_step = [s for s in steps if s["kind"] == "input_mutation"][0]
    assert "redirect_to" in mut_step["action"]
    assert "__canary_2026__" in mut_step["action"]
