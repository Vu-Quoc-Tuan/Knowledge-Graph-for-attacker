"""Synthesize DetectionHypothesis and ScenarioCandidate from grounded graph context."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from db.sink import GraphSink
from retrieval.vulnerability_card import vulnerability_card


def synthesize_candidate_scenario(
    sink: GraphSink,
    vuln_id: str,
    *,
    as_of: datetime | str | None = None,
    canary_marker: str = "__canary_marker_x7__",
) -> dict[str, Any] | None:
    card = vulnerability_card(sink, vuln_id, as_of=as_of)
    if not card:
        return None

    facts = card["facts"]
    input_vec = facts.get("inputVector") or "URL_QUERY"
    param_name = facts.get("inputParameter") or "test_param"
    mechanism = facts.get("mechanism") or "GENERIC_INJECTION"
    weakness_id = (card.get("classification") or {}).get("weaknessId")

    # Determine similar vulnerability context
    similar = card.get("similarVulnerabilities", [])
    based_on_vuln = similar[0]["targetVulnId"] if similar else None
    confidence = similar[0]["score"] if similar and similar[0].get("score") else 0.75

    # Determine mutation strategy, trigger pattern, and oracle family
    if mechanism == "UNSAFE_HTML_RENDER":
        mutation_strategy = "CONTROLLED_MARKER_INJECTION"
        trigger_pattern = "CLIENT_UI_RENDER"
        oracle_family = "UNENCODED_DOM_SINK"
    elif mechanism == "UNSANITIZED_FILE_PATH_CONCAT":
        mutation_strategy = "DIRECTORY_TRAVERSAL_SEQUENCE"
        trigger_pattern = "HTTP_GET_RESOURCE"
        oracle_family = "KNOWN_FILE_CONTENT_SIGNATURE"
    elif mechanism == "UNSAFE_JDBC_CONNECTION_STRING":
        mutation_strategy = "JDBC_SQL_DIRECTIVE_INJECTION"
        trigger_pattern = "DATABASE_VALIDATION_ENDPOINT"
        oracle_family = "COMMAND_EXECUTION_OUTCOME"
    elif mechanism == "UNVALIDATED_REMOTE_FETCH":
        mutation_strategy = "CUSTOM_HOST_HEADER_OVERRIDE"
        trigger_pattern = "AVATAR_REMOTE_FETCH"
        oracle_family = "OUT_OF_BAND_DNS_INTERACTION"
    else:
        mutation_strategy = "PAYLOAD_TAMPERING"
        trigger_pattern = "DISPATCH_REQUEST"
        oracle_family = "RESPONSE_DIFFERENTIAL"

    hypothesis_id = f"HYP-{vuln_id}"
    hypothesis = {
        "hypothesisId": hypothesis_id,
        "targetVulnId": vuln_id,
        "sourceChannel": input_vec,
        "mutationStrategy": mutation_strategy,
        "triggerPattern": trigger_pattern,
        "oracleFamily": oracle_family,
        "confidence": confidence,
        "basedOnVulnId": based_on_vuln,
        "basedOnWeaknessId": weakness_id,
        "status": "proposed",
    }

    # Compose concrete steps from fragments
    fragments = card.get("applicableFragments", [])
    steps = []

    # Step 1: Setup
    setup_frags = [f for f in fragments if f.get("kind") == "setup"]
    if setup_frags:
        steps.append({
            "step": 1,
            "kind": "setup",
            "fragmentId": setup_frags[0]["fragmentId"],
            "description": setup_frags[0]["description"],
            "action": setup_frags[0]["actionTemplate"].format(
                target_url=f"http://target.local/{vuln_id.lower()}"
            ),
        })

    # Step 2: Input Mutation
    mut_frags = [f for f in fragments if f.get("kind") == "input_mutation"]
    if mut_frags:
        act = mut_frags[0]["actionTemplate"]
        act = act.replace("{parameter_name}", param_name)
        act = act.replace("{marker_value}", canary_marker)
        act = act.replace("{target_file}", "etc/passwd")
        act = act.replace("{depth}", "7")
        act = act.replace("{command}", "id")
        act = act.replace("{header_name}", "X-Forwarded-Host")
        act = act.replace("{callback_url}", "http://listener.local/callback")
        steps.append({
            "step": len(steps) + 1,
            "kind": "input_mutation",
            "fragmentId": mut_frags[0]["fragmentId"],
            "description": mut_frags[0]["description"],
            "action": act,
        })

    # Step 3: Trigger
    trig_frags = [f for f in fragments if f.get("kind") == "trigger"]
    if trig_frags:
        comp_name = (card.get("component") or {}).get("name", "target_component")
        act = trig_frags[0]["actionTemplate"]
        act = act.replace("{component_selector}", f"#{comp_name}")
        act = act.replace("{endpoint_url}", f"http://target.local/endpoint")
        act = act.replace("{json_payload}", '{"details": {"db": "h2"}}')
        steps.append({
            "step": len(steps) + 1,
            "kind": "trigger",
            "fragmentId": trig_frags[0]["fragmentId"],
            "description": trig_frags[0]["description"],
            "action": act,
        })

    # Step 4: Oracle assertion
    oracle_frags = [f for f in fragments if f.get("kind") == "oracle"]
    if oracle_frags:
        act = oracle_frags[0]["actionTemplate"]
        act = act.replace("{marker_value}", canary_marker)
        act = act.replace("{dom_sink_selector}", "#target_dom_sink")
        act = act.replace("{expected_signature}", "root:x:0:0:")
        act = act.replace("{canary_subdomain}", f"{vuln_id.lower()}.listener.local")
        steps.append({
            "step": len(steps) + 1,
            "kind": "oracle",
            "fragmentId": oracle_frags[0]["fragmentId"],
            "description": oracle_frags[0]["description"],
            "action": act,
        })

    candidate_id = f"SCN-CAND-{vuln_id}"
    return {
        "candidateId": candidate_id,
        "targetVulnId": vuln_id,
        "status": "proposed",
        "applicability": "unknown",
        "groundingScore": round(confidence, 2),
        "hypothesis": hypothesis,
        "steps": steps,
        "unknowns": card.get("unknowns", []),
    }
