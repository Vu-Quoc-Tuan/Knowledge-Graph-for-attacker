from datetime import datetime, timezone
import json
import threading
from http.server import ThreadingHTTPServer

import requests


def _node(label, node_id, **props):
    from ckg.graph.models import GraphNode
    return GraphNode(label=label, node_id=node_id, props=props)


def _edge(edge_id, edge_type, source, target):
    from ckg.graph.models import GraphEdge
    return GraphEdge(edge_id=edge_id, edge_type=edge_type, subject_id=source, object_id=target)


def test_v2_api_exposes_module1_contracts_and_feedback(tmp_path) -> None:
    from ckg.api.main import CKGApplication, make_handler
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    receipt = tmp_path / "receipt.json"
    receipt.write_bytes(b'{"executed":true}')
    import hashlib
    receipt_digest = "sha256:" + hashlib.sha256(receipt.read_bytes()).hexdigest()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", title="Test", published_at="2026-01-01T00:00:00+00:00"),
        _node("CWE", "CWE-611", name="XXE"),
        _node("CWE", "CWE-79", name="XSS"),
        _node("WeaknessAssertion", "WAS-1", provenance={"retrieved_at": "2026-01-01T00:00:00+00:00"}, evidence_spans=[{"evidence_id": "EVID-1"}]),
        _node("Evidence", "EVID-1", retrieved_at="2026-01-01T00:00:00+00:00", content_digest=receipt_digest, kind="execution_receipt", storage_uri=str(receipt)),
        _node("Scenario", "SCN-1", scenario_id="SCN-1", scenario_revision=2, weakness_ids=["CWE-611"]),
        _node("CWEContextProfile", "CWE-PROFILE-CWE-611", cwe_id="CWE-611"),
    ], edges=[
        _edge("1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "WAS-1"), _edge("2", "MAPS_TO", "WAS-1", "CWE-611"), _edge("3", "SUPPORTED_BY", "CVE-2026-10001", "EVID-1"),
    ])
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        cve = requests.get(f"{base}/cves/CVE-2026-10001", timeout=2)
        health = requests.get(f"{base}/healthz", timeout=2)
        graph = requests.get(f"{base}/cves/CVE-2026-10001/subgraph?as_of=2026-09-14T00:00:00Z", timeout=2)
        weaknesses = requests.get(f"{base}/cves/CVE-2026-10001/weaknesses", timeout=2)
        history = requests.get(f"{base}/cves/CVE-2026-10001/historical-neighbors", timeout=2)
        scenarios = requests.get(f"{base}/cves/CVE-2026-10001/scenarios", timeout=2)
        profile = requests.get(f"{base}/cwes/CWE-611/profile", timeout=2)
        cwe_scenarios = requests.get(f"{base}/cwes/CWE-611/scenarios", timeout=2)
        cwe_context = requests.get(f"{base}/cwes/CWE-611/context", timeout=2)
        unknown_cwe_context = requests.get(f"{base}/cwes/CWE-404/context", timeout=2)
        ui = requests.get(f"{base}/ui/v2", timeout=2)
        css = requests.get(f"{base}/ui/v2/styles.css", timeout=2)
        js = requests.get(f"{base}/ui/v2/app.js", timeout=2)
        analysis = requests.post(
            f"{base}/analyze/cve/CVE-2026-10001",
            json={"retrieved_at": "2026-09-14T00:00:00Z"},
            timeout=2,
        )
        feedback = requests.post(f"{base}/feedback/executions", json={
            "observation_id": "OBS-1", "scenario_id": "SCN-1", "scenario_revision": 2, "result": "REPRODUCED", "observed_at": "2026-09-14T00:00:00Z", "evidence_ids": ["EVID-1"], "evidence_digests": [receipt_digest], "scope_key": "CWE-611|Python", "quality": {"oracle_observable": True, "environment_complete": True, "source_evidence_present": True}, "environment": {"environment_id": "ENV-1", "network": {"dns_egress": True}},
        }, timeout=2)
    finally:
        server.shutdown()
        server.server_close()

    assert health.status_code == 200
    assert health.json()["graphSchema"] == "ckg-v2"
    assert health.json()["backend"] == "in-memory"
    assert cve.status_code == weaknesses.status_code == history.status_code == scenarios.status_code == profile.status_code == cwe_scenarios.status_code == 200
    assert cwe_context.status_code == 200
    assert cwe_context.json()["contract_version"] == 1
    assert cwe_context.json()["cwe"]["id"] == "CWE-611"
    assert cwe_context.json()["missing_components"] == ["cwe", "wstg_methods"]
    assert unknown_cwe_context.status_code == 404
    assert graph.status_code == 200
    assert graph.json()["truncated"] is False
    assert feedback.status_code == 200
    assert analysis.status_code == 200
    assert analysis.json()["cve"]["id"] == "CVE-2026-10001"
    assert "abstentions" in analysis.json()
    assert feedback.json()["alpha"] == 2.0
    assert ui.status_code == css.status_code == js.status_code == 200
    assert "Evidence before execution" in ui.text
    assert "prefers-reduced-motion" in css.text
    assert "historical-neighbors" in js.text


def test_v2_api_ingest_endpoint_is_idempotent_by_source_snapshot(tmp_path) -> None:
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[_node("CWE", "CWE-79", name="XSS")], edges=[])
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    raw = json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2026-10002", "published": "2026-01-01T00:00:00Z", "lastModified": "2026-01-01T00:00:00Z", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "test"}], "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}]}}]})
    payload = {"source_kind": "nvd", "raw_payload": raw, "source_url": "https://example.test/nvd", "retrieved_at": "2026-09-14T00:00:00Z"}

    first = app.ingest_cve("CVE-2026-10002", payload)
    retry = app.ingest_cve("CVE-2026-10002", payload)

    assert first["job_id"] == retry["job_id"]
    assert len(repository.nodes("IngestionJob")) == 1
    assert len(repository.nodes("WeaknessAssertion")) == 1


def test_v2_api_does_not_implicitly_enable_model_from_environment(tmp_path, monkeypatch) -> None:
    from ckg.api import main as api_module
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[_node("CWE", "CWE-79", name="XSS")], edges=[])
    app = api_module.CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    raw = json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2026-10002", "published": "2026-01-01T00:00:00Z", "lastModified": "2026-01-01T00:00:00Z", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "test"}], "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}]}}]})
    real_ingest = api_module.ingest_structured_source
    observed: list[bool] = []

    def spy_ingest(*args, **kwargs):
        observed.append(kwargs["use_model"])
        return real_ingest(*args, **kwargs)

    monkeypatch.setenv("AI_API_KEY", "configured-but-not-opted-in")
    monkeypatch.setattr(api_module, "ingest_structured_source", spy_ingest)

    app.ingest_cve(
        "CVE-2026-10002",
        {"source_kind": "nvd", "raw_payload": raw, "source_url": "https://example.test/nvd"},
    )

    assert observed == [False]


def test_v2_api_refuses_mismatched_ingest_target_without_graph_side_effect(tmp_path) -> None:
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    raw = json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2026-10003", "published": "2026-01-01T00:00:00Z", "lastModified": "2026-01-01T00:00:00Z", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "test"}]}}]})

    try:
        app.ingest_cve("CVE-2026-99999", {"source_kind": "nvd", "raw_payload": raw, "source_url": "https://example.test/nvd"})
    except ValueError as exc:
        assert "did not describe" in str(exc)
    else:
        raise AssertionError("mismatched target must be rejected")
    assert repository.nodes() == []


def test_v2_api_searches_cves_by_technology_and_year(tmp_path) -> None:
    from ckg.api.main import CKGApplication, make_handler
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            _node("CVE", "CVE-2026-11111", title="Grafana issue", published_at="2026-02-01T00:00:00+00:00"),
            _node("Product", "PRODUCT-GRAFANA", name="grafana", vendor="grafana", ecosystem="cpe"),
        ],
        edges=[_edge("A1", "AFFECTS", "CVE-2026-11111", "PRODUCT-GRAFANA")],
    )
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        response = requests.get(
            f"{base}/cves?technology=Grafana&from_year=2026&to_year=2026&limit=10",
            timeout=2,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert response.status_code == 200
    assert response.json()["cves"][0]["id"] == "CVE-2026-11111"
    assert response.json()["query"] == {"technology": "Grafana", "from_year": 2026, "to_year": 2026}


def test_v2_api_reports_nvd_rate_limit_with_retry_after(tmp_path, monkeypatch) -> None:
    from ckg.api import main as api_main
    from ckg.api.main import CKGApplication, make_handler
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.ingestion.cve.nvd_client import NVDRateLimitError

    def rate_limited_search(*args, **kwargs):
        raise NVDRateLimitError(23)

    monkeypatch.setattr(api_main, "search_cves", rate_limited_search)
    repository = InMemoryGraphRepository()
    snapshot_root = tmp_path / "snapshots"
    app = CKGApplication(repository, snapshot_root=str(snapshot_root))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        response = requests.post(
            f"http://127.0.0.1:{server.server_port}/ingest/cves/search",
            json={"technology": "Grafana", "from_year": 2026, "to_year": 2026},
            timeout=2,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert response.status_code == 429
    assert response.json() == {
        "error": "NVD rate limit reached; retry the search later (Retry-After: 23s)",
        "retry_after_seconds": 23,
    }
    assert repository.nodes() == []
    assert not snapshot_root.exists()


def test_v2_api_rejects_oversized_json_body(tmp_path) -> None:
    from ckg.api.main import CKGApplication, make_handler
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app, max_request_body_bytes=8))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        response = requests.post(
            f"http://127.0.0.1:{server.server_port}/ingest/cve",
            json={"cveId": "CVE-2026-11111"},
            timeout=2,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert response.status_code == 413
    assert response.json() == {"error": "request body too large"}


def test_v2_api_does_not_return_internal_exception_details(tmp_path) -> None:
    from ckg.api.main import CKGApplication, make_handler
    from ckg.graph.memory import InMemoryGraphRepository

    class ExplodingApplication(CKGApplication):
        def ingest_cve(self, identifier, payload):
            raise RuntimeError("secret internal detail")

    repository = InMemoryGraphRepository()
    app = ExplodingApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        response = requests.post(
            f"http://127.0.0.1:{server.server_port}/ingest/cve",
            json={"cveId": "CVE-2026-11111"},
            timeout=2,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert response.status_code == 500
    assert response.json() == {"error": "internal server error"}
    assert "secret internal detail" not in response.text
