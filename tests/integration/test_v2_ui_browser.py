"""Real-browser smoke test for the static v2 case-file UI.

The test is skipped only when Chrome is absent; CI runs it against a local
synthetic graph, never a target application or live vulnerability source.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest


def _dump_dom(chrome: str, url: str, profile_dir: Path) -> subprocess.CompletedProcess[str]:
    """Run each smoke case with an isolated Chrome profile.

    Reusing Chrome's implicit profile across consecutive headless invocations
    can leave a singleton/profile lock behind long enough for the next process
    to hang.  A per-test profile makes the browser lifecycle deterministic.
    """
    last_timeout: subprocess.TimeoutExpired | None = None
    for attempt in range(2):
        try:
            return subprocess.run(
                [
                    chrome,
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--no-first-run",
                    f"--user-data-dir={profile_dir / f'attempt-{attempt}'}",
                    "--dump-dom",
                    "--virtual-time-budget=1500",
                    url,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except subprocess.TimeoutExpired as error:
            # Chrome occasionally stalls during headless startup in CI. Retry
            # once with a fresh profile; a repeated timeout remains a failure.
            last_timeout = error
    assert last_timeout is not None
    raise last_timeout


def test_v2_case_file_ui_renders_a_loaded_case_in_chrome(tmp_path) -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if not chrome:
        pytest.skip("Chrome is unavailable for browser smoke test")
    from ckg.api.main import CKGApplication, make_handler
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            GraphNode(label="CVE", node_id="CVE-2026-10001", props={"title": "Synthetic browser case", "published_at": "2026-01-01T00:00:00+00:00"}),
            GraphNode(label="CWE", node_id="CWE-611", props={"name": "XXE"}),
            GraphNode(label="WeaknessAssertion", node_id="WAS-1", props={"cwe_id": "CWE-611", "status": "REPORTED", "evidence_spans": []}),
        ],
        edges=[
            GraphEdge(edge_id="EDGE-HAS-WAS", edge_type="HAS_WEAKNESS_ASSERTION", subject_id="CVE-2026-10001", object_id="WAS-1"),
            GraphEdge(edge_id="EDGE-WAS-MAPS", edge_type="MAPS_TO", subject_id="WAS-1", object_id="CWE-611"),
        ],
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _dump_dom(
            chrome,
            f"http://127.0.0.1:{server.server_port}/ui/v2?cve=CVE-2026-10001",
            tmp_path / "chrome-profile",
        )
    finally:
        server.shutdown()
        server.server_close()
    assert "Case file loaded" in result.stdout
    assert "Synthetic browser case" in result.stdout
    assert "Backend: in-memory" in result.stdout
    assert "Cypher Query" not in result.stdout
    assert "btn-copy-cypher" not in result.stdout


def test_v2_ui_labels_unverified_command_as_template_without_copy(tmp_path) -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if not chrome:
        pytest.skip("Chrome is unavailable for browser smoke test")
    from ckg.api.main import CKGApplication, make_handler
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode

    class TemplateApplication(CKGApplication):
        def scenarios(self, identifier, *, environment=None, as_of=None):
            return {"vulnerability_id": identifier, "scenarios": [{
                "scenario": {
                    "scenario_id": "SCN-TEMPLATE", "scenario_type": "NOVEL",
                    "status": "INFERRED", "applicability": "UNKNOWN",
                    "weakness_ids": ["CWE-89"], "technique_ids": [],
                    "constraint_ids": [], "title": "Unverified test template",
                    "description": "For research only", "steps": ["Review source"],
                    "confidence": {"final": 0, "evidence_coverage": 0},
                    "poc_command": "curl <TARGET_ENDPOINT>",
                    "missing_bindings": ["target_endpoint"],
                },
                "premises": ["Example"], "evidence_ids": [],
                "missing_bindings": ["target_endpoint"],
            }]}

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[GraphNode(
        label="CVE", node_id="CVE-2026-10001", props={"title": "Template case"},
    )], edges=[])
    app = TemplateApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _dump_dom(
            chrome,
            f"http://127.0.0.1:{server.server_port}/ui/v2?cve=CVE-2026-10001",
            tmp_path / "chrome-profile",
        )
    finally:
        server.shutdown()
        server.server_close()
    assert "Mẫu lệnh tham khảo · chưa xác minh trên đích" in result.stdout
    assert "Chưa có nguồn CWE" in result.stdout
    assert "btn-copy-poc" not in result.stdout


def test_v2_case_file_ui_reports_partial_resource_failure_in_chrome(tmp_path) -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if not chrome:
        pytest.skip("Chrome is unavailable for browser smoke test")
    from ckg.api.main import CKGApplication, make_handler
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode

    class PartialApplication(CKGApplication):
        def scenarios(self, identifier, *, environment=None, as_of=None):
            raise RuntimeError("synthetic scenarios failure")

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            GraphNode(label="CVE", node_id="CVE-2026-10001", props={"title": "Synthetic partial case", "published_at": "2026-01-01T00:00:00+00:00"}),
        ],
        edges=[],
    )
    app = PartialApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _dump_dom(
            chrome,
            f"http://127.0.0.1:{server.server_port}/ui/v2?cve=CVE-2026-10001",
            tmp_path / "chrome-profile",
        )
    finally:
        server.shutdown()
        server.server_close()
    assert "Partial load: scenarios" in result.stdout


def test_v2_case_file_ui_rejects_missing_case_before_secondary_queries(tmp_path) -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if not chrome:
        pytest.skip("Chrome is unavailable for browser smoke test")
    from ckg.api.main import CKGApplication, make_handler
    from ckg.graph.memory import InMemoryGraphRepository

    class MissingCaseApplication(CKGApplication):
        def __init__(self, repository, *, snapshot_root):
            super().__init__(repository, snapshot_root=snapshot_root)
            self.secondary_calls: list[str] = []

        def historical_neighbors(self, identifier, *, as_of=None):
            self.secondary_calls.append("historical-neighbors")
            return super().historical_neighbors(identifier, as_of=as_of)

        def scenarios(self, identifier, *, environment=None, as_of=None):
            self.secondary_calls.append("scenarios")
            return super().scenarios(identifier, environment=environment, as_of=as_of)

        def subgraph(self, identifier, *, as_of=None):
            self.secondary_calls.append("subgraph")
            return super().subgraph(identifier, as_of=as_of)

        def cve_payloads(self, identifier):
            self.secondary_calls.append("payloads")
            return super().cve_payloads(identifier)

    app = MissingCaseApplication(
        InMemoryGraphRepository(), snapshot_root=str(tmp_path / "snapshots")
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _dump_dom(
            chrome,
            f"http://127.0.0.1:{server.server_port}/ui/v2?cve=CVE-2026-10001-MISSING",
            tmp_path / "chrome-profile",
        )
    finally:
        server.shutdown()
        server.server_close()

    assert "Không tìm thấy case file" in result.stdout
    assert "Đang tải đồ thị" not in result.stdout
    assert app.secondary_calls == []
