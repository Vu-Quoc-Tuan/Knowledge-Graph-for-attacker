"""Tests for real ephemeral sandbox runner and socket execution."""

from __future__ import annotations

import html
from sandbox.runner import EphemeralTargetHandler, run_scenario_execution


def test_ephemeral_sandbox_execution_success() -> None:
    candidate = {
        "candidateId": "SCN-TEST-001",
        "targetVulnId": "CVE-2024-44541",
        "steps": [
            {"step": 1, "kind": "setup"},
            {"step": 2, "kind": "input_mutation"},
            {"step": 3, "kind": "trigger"},
            {"step": 4, "kind": "oracle"},
        ],
    }
    canary = "<script>__unit_test_canary_x7__</script>"

    result = run_scenario_execution(candidate, canary_marker=canary)

    assert result["status"] == "passed"
    assert result["targetHost"] == "127.0.0.1"
    assert result["targetPort"] > 0
    assert result["canaryToken"] == canary

    # Vulnerable run assertions
    vuln = result["vulnerableRun"]
    assert vuln["status"] == 200
    assert vuln["oracleMatched"] is True
    assert vuln["bytesReceived"] > 0
    assert vuln["latencyMs"] >= 0

    # Patched run assertions
    patched = result["patchedRun"]
    assert patched["status"] == 200
    assert patched["oracleProtected"] is True
    assert patched["bytesReceived"] > 0

    # Validation record assertions
    val_rec = result["validationRecord"]
    assert val_rec["validationId"].startswith("VAL-")
    assert val_rec["candidateId"] == "SCN-TEST-001"
    assert val_rec["targetVulnId"] == "CVE-2024-44541"
    assert val_rec["executionDigest"].startswith("sha256:")
    assert val_rec["evidenceHash"].startswith("sha256:")
    assert val_rec["vulnerableTargetResult"] == "passed"
    assert val_rec["patchedTargetResult"] == "passed"
    assert val_rec["status"] == "passed"

    # Verify execution logs contains live socket logs
    logs = result["executionLogs"]
    assert len(logs) >= 10
    assert any("SOCKET BIND:" in l for l in logs)
    assert any("Vulnerable Target" in l for l in logs)
    assert any("Patched Target" in l for l in logs)
    assert any("COMPLETION:" in l for l in logs)
