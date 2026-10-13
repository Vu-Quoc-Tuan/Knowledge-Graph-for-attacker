import hashlib

from ckg.api.main import CKGApplication
from ckg.graph.memory import InMemoryGraphRepository
from ckg.graph.models import GraphEdge, GraphNode
from ckg.ingestion.wstg.catalog import canonical_wstg_source_bytes


def _edge(edge_id, edge_type, source, target, **props):
    return GraphEdge(
        edge_id=edge_id,
        edge_type=edge_type,
        subject_id=source,
        object_id=target,
        props=props,
    )


def _populated_app(tmp_path):
    repository = InMemoryGraphRepository()
    cwe_digest = "sha256:" + "a" * 64
    wstg_digest = "sha256:" + hashlib.sha256(canonical_wstg_source_bytes("WSTG-INPV-05")).hexdigest()
    repository.atomic_write(
        nodes=[
            GraphNode(label="CWE", node_id="CWE-89", props={"name": "stale identity name"}),
            GraphNode(label="CWEContentRevision", node_id="REV-CWE-89", props={
                "canonical_id": "CWE-89",
                "name": "Improper Neutralization of Special Elements used in an SQL Command",
                "description": "The software constructs an SQL command using externally influenced input.",
                "source_release": "4.20",
                "source_snapshot_digest": cwe_digest,
                "retrieved_at": "2026-09-20T00:00:00+00:00",
            }),
            GraphNode(label="WSTGCase", node_id="WSTG-INPV-05", props={
                "title": "Testing for SQL Injection",
                "source_release": "4.2",
                "source_snapshot_digest": wstg_digest,
                "retrieved_at": "2026-09-20T00:00:00+00:00",
            }),
            GraphNode(label="TestStrategy", node_id="TSTRAT-WSTG-INPV-05", props={
                "name": "Testing for SQL Injection", "source_kind": "wstg",
            }),
            GraphNode(label="Evidence", node_id="EVID-WSTG-05", props={
                "content_digest": wstg_digest,
                "source_url": "https://owasp.org/wstg/WSTG-INPV-05",
                "retrieved_at": "2026-09-20T00:00:00+00:00",
            }),
            GraphNode(label="Technique", node_id="TECH-BLIND", props={"name": "Blind testing"}),
            GraphNode(label="InputSurface", node_id="INPUT-QUERY", props={"name": "Query parameter"}),
            GraphNode(label="Oracle", node_id="ORACLE-RESPONSE", props={"name": "Response difference"}),
            GraphNode(label="CallbackChannel", node_id="CHANNEL-HTTP", props={"name": "HTTP"}),
        ],
        edges=[
            _edge("MAP-CWE", "TARGETS_WEAKNESS", "TSTRAT-WSTG-INPV-05", "CWE-89", source_snapshot_digest=wstg_digest),
            _edge("DESCRIBES", "DESCRIBES", "WSTG-INPV-05", "TSTRAT-WSTG-INPV-05", source_snapshot_digest=wstg_digest),
            _edge("SUPPORTS-WSTG", "SUPPORTED_BY", "WSTG-INPV-05", "EVID-WSTG-05"),
            _edge("USES-TECH", "USES_TECHNIQUE", "TSTRAT-WSTG-INPV-05", "TECH-BLIND", source_snapshot_digest=wstg_digest),
            _edge("USES-INPUT", "APPLIES_TO", "TSTRAT-WSTG-INPV-05", "INPUT-QUERY", source_snapshot_digest=wstg_digest),
            _edge("USES-ORACLE", "USES_ORACLE", "TSTRAT-WSTG-INPV-05", "ORACLE-RESPONSE", source_snapshot_digest=wstg_digest),
            _edge("USES-CHANNEL", "USES_CHANNEL", "TSTRAT-WSTG-INPV-05", "CHANNEL-HTTP", source_snapshot_digest=wstg_digest),
        ],
    )
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    return app


def test_cwe_context_returns_only_pinned_cwe_and_explicit_wstg_methodology(tmp_path):
    app = _populated_app(tmp_path)

    result = app.cwe_context("CWE-89")

    assert result["contract_version"] == 1
    assert result["cwe"] == {
        "id": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command",
        "description": "The software constructs an SQL command using externally influenced input.",
        "source": {
            "name": "MITRE CWE",
            "release": "4.20",
            "snapshot_digest": "sha256:" + "a" * 64,
            "retrieved_at": "2026-09-20T00:00:00+00:00",
        },
    }
    assert result["wstg_methods"][0]["id"] == "WSTG-INPV-05"
    assert result["wstg_methods"][0]["method_summary"] == (
        "Verify whether user-supplied input alters SQL syntax execution through error, "
        "boolean differential, or time delays."
    )
    assert result["wstg_methods"][0]["techniques"] == [{"id": "TECH-BLIND", "name": "Blind testing"}]
    assert result["wstg_methods"][0]["input_surfaces"] == [{"id": "INPUT-QUERY", "name": "Query parameter"}]
    assert result["wstg_methods"][0]["observable_signals"] == [{"id": "ORACLE-RESPONSE", "name": "Response difference"}]
    assert result["wstg_methods"][0]["channels"] == [{"id": "CHANNEL-HTTP", "name": "HTTP"}]
    assert result["wstg_methods"][0]["source"] == {
        "name": "OWASP WSTG",
        "representation": "ckg_curated_semantic_projection",
        "url": "https://owasp.org/wstg/WSTG-INPV-05",
        "release": "4.2",
        "snapshot_digest": "sha256:" + hashlib.sha256(canonical_wstg_source_bytes("WSTG-INPV-05")).hexdigest(),
        "evidence_id": "EVID-WSTG-05",
        "retrieved_at": "2026-09-20T00:00:00+00:00",
    }
    assert result["availability"] == {
        "cwe": "available", "wstg_methods": "available",
    }
    assert result["missing_components"] == []
    assert "patt_references" not in result


def test_cwe_context_marks_missing_content_and_sources_explicitly(tmp_path):
    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[GraphNode(label="CWE", node_id="CWE-89", props={})], edges=[])
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))

    result = app.cwe_context("CWE-89")

    assert result["cwe"]["name"] is None
    assert result["wstg_methods"] == []
    assert result["availability"] == {
        "cwe": "missing", "wstg_methods": "missing",
    }
    assert result["missing_components"] == ["cwe", "wstg_methods"]


def test_cwe_context_ignores_wstg_mapping_without_matching_source_evidence(tmp_path):
    app = _populated_app(tmp_path)
    app.repository.atomic_write(nodes=[], edges=[
        _edge("STALE-MAP", "TARGETS_WEAKNESS", "TSTRAT-WSTG-INPV-05", "CWE-89", source_snapshot_digest="sha256:" + hashlib.sha256(canonical_wstg_source_bytes("WSTG-INPV-05")).hexdigest(), stale=True),
        GraphEdge(edge_id="DESCRIBES", edge_type="DESCRIBES", subject_id="WSTG-INPV-05", object_id="TSTRAT-WSTG-INPV-05", props={"stale": True, "source_snapshot_digest": "sha256:" + hashlib.sha256(canonical_wstg_source_bytes("WSTG-INPV-05")).hexdigest()}),
    ])

    result = app.cwe_context("CWE-89")

    assert result["wstg_methods"] == []
    assert result["availability"]["wstg_methods"] == "missing"


def test_cwe_context_returns_not_found_for_unknown_cwe(tmp_path):
    app = _populated_app(tmp_path)

    try:
        app.cwe_context("CWE-404")
    except KeyError as error:
        assert error.args == ("CWE-404",)
    else:
        raise AssertionError("unknown CWE must raise KeyError")
