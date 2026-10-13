import json
from pathlib import Path
import subprocess
import sys


def test_ckg_cli_help() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ckg", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "build" in result.stdout
    assert "serve" in result.stdout
    assert "analyze" in result.stdout
    assert "ingest" in result.stdout
    assert "feedback" in result.stdout
    assert "rebuild" in result.stdout


def test_ckg_cli_build_memory() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ckg", "build", "--memory"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(result.stdout)
    assert "cwe" in data
    assert "capec" in data
    assert data["node_count"] >= 5000
    assert data["edge_count"] >= 10000


def test_ckg_cli_rebuild_memory() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ckg", "rebuild", "--memory"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(result.stdout)
    assert "profiles" in data
    assert "cooccurrence" in data


def test_ckg_cli_ingest_cve_memory(tmp_path: Path) -> None:
    cve_data = {
        "cveMetadata": {
            "cveId": "CVE-2026-10001",
            "state": "PUBLISHED",
            "serial": 1,
            "datePublished": "2026-01-01T00:00:00Z",
            "dateUpdated": "2026-01-02T00:00:00Z",
        },
        "containers": {
            "cna": {
                "title": "Test Vulnerability",
                "descriptions": [{"lang": "en", "value": "A test vulnerability description."}],
                "problemTypes": [{"descriptions": [{"lang": "en", "cweId": "CWE-79", "description": "XSS"}]}],
                "affected": [{"vendor": "Acme", "product": "Widget", "versions": [{"version": "1.0", "lessThan": "2.0", "status": "affected"}]}],
                "references": [{"url": "https://example.test/advisory"}],
            }
        },
    }
    cve_file = tmp_path / "cve.json"
    cve_file.write_text(json.dumps(cve_data), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ckg",
            "ingest",
            "--cve",
            "CVE-2026-10001",
            "--file",
            str(cve_file),
            "--memory",
            "--snapshot-root",
            str(tmp_path / "snapshots"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(result.stdout)
    assert data["cve"] == "CVE-2026-10001"
    assert "snapshot_digest" in data
    assert data["report"]["source_record_count"] == 1


def test_ckg_cli_feedback_refuses_to_fabricate_scenario_and_evidence() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ckg",
            "feedback",
            "--observation-id",
            "OBS-TEST-01",
            "--scenario-id",
            "SCEN-TEST-01",
            "--environment-id",
            "ENV-TEST-01",
            "--result",
            "REPRODUCED",
            "--memory",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "feedback scenario must already exist" in result.stderr


def test_ckg_cli_analyze_fails_on_unknown_cve() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ckg",
            "analyze",
            "CVE-NONEXISTENT-9999",
            "--memory",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "unknown vulnerability: CVE-NONEXISTENT-9999" in result.stderr
