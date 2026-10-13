from ckg.api.main import CKGApplication
from ckg.application.ingest_patt import ingest_patt_sources
from ckg.graph.memory import InMemoryGraphRepository
from ckg.graph.models import GraphEdge, GraphNode
from ckg.ingestion.patt.payload_importer import PATTSourceFile


def test_cwe_and_cve_payload_queries_are_reference_only(tmp_path) -> None:
    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CWE", node_id="CWE-79", props={}),
        GraphNode(label="CVE", node_id="CVE-2026-0001", props={}),
        GraphNode(label="WeaknessAssertion", node_id="WAS-1", props={"evidence_spans": [{"evidence_id": "EVID-1"}]}),
        GraphNode(label="Evidence", node_id="EVID-1", props={"content_digest": "sha256:" + "a" * 64}),
    ], edges=[
        GraphEdge(edge_id="EDGE-HAS-WAS", edge_type="HAS_WEAKNESS_ASSERTION", subject_id="CVE-2026-0001", object_id="WAS-1"),
        GraphEdge(edge_id="EDGE-MAPS", edge_type="MAPS_TO", subject_id="WAS-1", object_id="CWE-79"),
    ])
    ingest_patt_sources(
        repository,
        slice_cwe_id="CWE-79",
        sources=(PATTSourceFile("xss.txt", "https://example.test/xss", "a" * 40, "<svg/onload=1>", kind="wordlist"),),
        retrieved_at=__import__("datetime").datetime(2026, 9, 22, tzinfo=__import__("datetime").timezone.utc),
        snapshot_root=tmp_path / "snapshots",
    )
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))

    by_cwe = app.cwe_payloads("CWE-79")
    by_cve = app.cve_payloads("CVE-2026-0001")

    assert by_cwe["reference_only"] is by_cve["reference_only"] is True
    assert by_cve["weakness_ids"] == ["CWE-79"]
    assert by_cve["reference_scope"] == "cwe"
    assert by_cve["payloads"][0]["validation_status"] == "untested"
    assert by_cve["payload_storage"] == "sidecar_index"
    assert by_cve["total"] == 1
    assert by_cve["truncated"] is False
    assert repository.nodes("Payload") == []
    assert "Scenario" not in {node.label for node in repository.nodes()}


def test_cve_payload_query_does_not_inherit_unverified_legacy_cwe(tmp_path) -> None:
    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CWE", node_id="CWE-79", props={}),
        GraphNode(label="CVE", node_id="CVE-2026-0001", props={}),
        GraphNode(label="WeaknessAssertion", node_id="WAS-1", props={
            "evidence_spans": [{"evidence_id": "EVID-MISSING"}],
            "all_source_snapshots_available": False,
        }),
    ], edges=[
        GraphEdge(edge_id="EDGE-HAS-WAS", edge_type="HAS_WEAKNESS_ASSERTION", subject_id="CVE-2026-0001", object_id="WAS-1"),
        GraphEdge(edge_id="EDGE-MAPS", edge_type="MAPS_TO", subject_id="WAS-1", object_id="CWE-79"),
    ])
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    result = app.cve_payloads("CVE-2026-0001")
    assert result["weakness_ids"] == []
    assert result["payloads"] == []
