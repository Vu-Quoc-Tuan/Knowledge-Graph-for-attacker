from datetime import datetime, timezone


def _node(label, node_id, **props):
    from ckg.graph.models import GraphNode

    return GraphNode(label=label, node_id=node_id, props=props)


def _edge(edge_id, edge_type, source, target, **props):
    from ckg.graph.models import GraphEdge

    return GraphEdge(edge_id=edge_id, edge_type=edge_type, subject_id=source, object_id=target, props=props)


def test_technology_search_returns_only_versions_for_matching_product():
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            _node("CVE", "CVE-2026-0300", published_at="2026-01-01T00:00:00+00:00"),
            _node("Product", "PRODUCT-ALPHA", name="Alpha"),
            _node("Product", "PRODUCT-BETA", name="Beta"),
            _node("VersionRange", "VERSION-ALPHA", expression="< 2"),
            _node("VersionRange", "VERSION-BETA", expression=">= 3"),
            _node("VersionRange", "VERSION-LEGACY", expression="all"),
        ],
        edges=[
            _edge("A1", "AFFECTS", "CVE-2026-0300", "PRODUCT-ALPHA"),
            _edge("A2", "AFFECTS", "CVE-2026-0300", "PRODUCT-BETA"),
            _edge("V1", "AFFECTS_VERSION", "CVE-2026-0300", "VERSION-ALPHA", product_ids=["PRODUCT-ALPHA"]),
            _edge("V2", "AFFECTS_VERSION", "CVE-2026-0300", "VERSION-BETA", product_ids=["PRODUCT-BETA"]),
            _edge("V3", "AFFECTS_VERSION", "CVE-2026-0300", "VERSION-LEGACY"),
        ],
    )

    alpha = repository.search_vulnerabilities("Alpha", from_year=2026, to_year=2026, limit=10)
    beta = repository.search_vulnerabilities("Beta", from_year=2026, to_year=2026, limit=10)
    assert {version.node_id for version in alpha[0].versions} == {"VERSION-ALPHA", "VERSION-LEGACY"}
    assert {version.node_id for version in beta[0].versions} == {"VERSION-BETA", "VERSION-LEGACY"}


def test_technology_search_excludes_stale_legacy_product_and_version():
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-0300", published_at="2026-01-01T00:00:00+00:00"),
        _node("Product", "PRODUCT-OLD", name="WrongProduct"),
        _node("Product", "PRODUCT-NEW", name="CorrectProduct"),
        _node("VersionRange", "VERSION-OLD", expression="< 1"),
        _node("VersionRange", "VERSION-NEW", expression="< 2"),
    ], edges=[
        _edge("A-OLD", "AFFECTS", "CVE-2026-0300", "PRODUCT-OLD", stale=True),
        _edge("A-NEW", "AFFECTS", "CVE-2026-0300", "PRODUCT-NEW"),
        _edge("V-OLD", "AFFECTS_VERSION", "CVE-2026-0300", "VERSION-OLD", stale=True),
        _edge("V-NEW", "AFFECTS_VERSION", "CVE-2026-0300", "VERSION-NEW", product_id="PRODUCT-NEW"),
    ])

    assert repository.search_vulnerabilities("WrongProduct", from_year=2026, to_year=2026) == []
    matches = repository.search_vulnerabilities("CorrectProduct", from_year=2026, to_year=2026)
    assert [item.node_id for item in matches[0].versions] == ["VERSION-NEW"]


def test_neo4j_technology_query_scopes_versions_to_selected_products():
    from ckg.graph.neo4j.driver import Neo4jGraphRepository

    class Session:
        query = ""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def run(self, query, **_params):
            self.query = query
            return []

    session = Session()
    repository = object.__new__(Neo4jGraphRepository)
    repository._driver = type("Driver", (), {"session": lambda self: session})()
    assert repository.search_vulnerabilities("Alpha", from_year=2026, to_year=2026) == []
    assert "properties(version_rel)['product_ids']" in session.query
    assert "product.nodeId IN coalesce(properties(version_rel)['product_ids'], [])" in session.query
    assert "properties(version_rel)['product_id'] IS NULL" in session.query
    assert "coalesce(affect.stale, false) = false" in session.query
    assert "coalesce(version_rel.stale, false) = false" in session.query
    assert "version_rel.product_id" not in session.query


def test_technology_search_filters_years_suppressed_records_and_folds_cve_ghsa_aliases():
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            _node("CVE", "CVE-2025-0001", title="Grafana CVE", published_at="2025-03-01T00:00:00+00:00"),
            _node("GHSA", "GHSA-aaaa-bbbb-cccc", title="Grafana advisory", published_at="2025-03-01T00:00:00+00:00", aliases=["CVE-2025-0001"]),
            _node("CVE", "CVE-2023-0002", title="Old Grafana CVE", published_at="2023-03-01T00:00:00+00:00"),
            _node("CVE", "CVE-2025-0003", title="Rejected Grafana CVE", published_at="2025-04-01T00:00:00+00:00", current_source_state="REJECTED"),
            _node("Product", "PRODUCT-GRAFANA", name="grafana", vendor="grafana", ecosystem="cpe"),
            _node("Product", "PRODUCT-OLD", name="grafana", vendor="grafana", ecosystem="cpe"),
            _node("Product", "PRODUCT-OPENSSL", name="openssl", vendor="openssl", ecosystem="cpe"),
            _node("VersionRange", "VERSION-1", expression=">= 8.0, < 8.5", status="affected", ecosystem="cpe"),
            _node("VulnerabilitySourceRecord", "SRC-REJECTED", record_id="CVE-2025-0003", state="REJECTED"),
        ],
        edges=[
            _edge("A1", "AFFECTS", "CVE-2025-0001", "PRODUCT-GRAFANA"),
            _edge("A2", "AFFECTS", "GHSA-aaaa-bbbb-cccc", "PRODUCT-GRAFANA"),
            _edge("A3", "AFFECTS", "CVE-2023-0002", "PRODUCT-OLD"),
            _edge("A4", "AFFECTS", "CVE-2025-0003", "PRODUCT-GRAFANA"),
            _edge("V1", "AFFECTS_VERSION", "CVE-2025-0001", "VERSION-1"),
            _edge("S1", "DESCRIBES", "SRC-REJECTED", "CVE-2025-0003"),
        ],
    )

    matches = repository.search_vulnerabilities("Grafana", from_year=2024, to_year=2026, limit=10)

    assert [match.vulnerability.node_id for match in matches] == ["CVE-2025-0001"]
    assert {product.node_id for product in matches[0].products} == {"PRODUCT-GRAFANA"}
    assert matches[0].versions[0].props["expression"] == ">= 8.0, < 8.5"
    assert "GHSA-aaaa-bbbb-cccc" in matches[0].vulnerability.props["aliases"]


def test_application_lists_products_versions_and_sources_for_technology_query(tmp_path):
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            _node("CVE", "CVE-2026-0001", title="OpenSSL issue", description="desc", published_at="2026-01-02T00:00:00+00:00"),
            _node("Product", "PRODUCT-OPENSSL", name="openssl", vendor="openssl", ecosystem="cpe", source_pointer="/cve/configurations/0"),
            _node("VersionRange", "VERSION-OPENSSL", expression="< 3.0.1", status="affected", ecosystem="cpe", source_pointer="/cve/configurations/0"),
            _node("VulnerabilitySourceRecord", "SRC-OPENSSL", record_id="CVE-2026-0001", source_kind="nvd", source_url="https://nvd.example/CVE-2026-0001", source_revision="2026-01-03", state="ANALYZED", snapshot_digest="sha256:abc"),
        ],
        edges=[
            _edge("A1", "AFFECTS", "CVE-2026-0001", "PRODUCT-OPENSSL"),
            _edge("V1", "AFFECTS_VERSION", "CVE-2026-0001", "VERSION-OPENSSL"),
            _edge("S1", "DESCRIBES", "SRC-OPENSSL", "CVE-2026-0001"),
        ],
    )
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))

    results = app.list_cves(technology="OpenSSL", from_year=2026, to_year=2026)

    assert results[0]["id"] == "CVE-2026-0001"
    assert results[0]["affected_products"][0]["name"] == "openssl"
    assert results[0]["affected_versions"][0]["expression"] == "< 3.0.1"
    assert results[0]["sources"][0]["source_kind"] == "nvd"


def test_technology_search_ranks_product_identity_and_ignores_ecosystem_only_match():
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            _node("CVE", "CVE-2026-0100", published_at="2026-01-01T00:00:00+00:00"),
            _node("CVE", "CVE-2026-0101", published_at="2026-01-01T00:00:00+00:00"),
            _node("CVE", "CVE-2026-0102", published_at="2026-01-01T00:00:00+00:00"),
            _node("Product", "PRODUCT-EXACT", name="grafana", vendor="acme", ecosystem="cpe", aliases=["grafana/grafana"]),
            _node("Product", "PRODUCT-VENDOR", name="dashboard", vendor="grafana", ecosystem="cpe"),
            _node("Product", "PRODUCT-ECOSYSTEM", name="unrelated-dashboard", vendor="acme", ecosystem="grafana"),
        ],
        edges=[
            _edge("A1", "AFFECTS", "CVE-2026-0100", "PRODUCT-EXACT"),
            _edge("A2", "AFFECTS", "CVE-2026-0101", "PRODUCT-VENDOR"),
            _edge("A3", "AFFECTS", "CVE-2026-0102", "PRODUCT-ECOSYSTEM"),
        ],
    )

    matches = repository.search_vulnerabilities("grafana", from_year=2026, to_year=2026, limit=10)

    assert [match.vulnerability.node_id for match in matches] == ["CVE-2026-0100", "CVE-2026-0101"]
    assert matches[0].relevance > matches[1].relevance
    assert matches[0].match_reason == "exact_product"
    assert matches[1].match_reason == "vendor"


def test_batch_nvd_search_snapshots_and_imports_cpe_products(tmp_path, monkeypatch):
    import json
    from ckg.api import main as api_main
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    raw = json.dumps({
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2026-0004",
                "published": "2026-02-01T00:00:00Z",
                "lastModified": "2026-02-01T00:00:00Z",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Grafana issue."}],
                "configurations": [{"nodes": [{"cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "9.0.0",
                }]}]}],
            }
        }],
    }).encode()
    fetch_metadata = {
        "truncated": False,
        "upstream_total_known": True,
        "search_mode": "technology_cpe",
        "cpe_families": ["cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"],
        "cpe_candidates_truncated": False,
        "cpe_candidate_count": 1,
    }
    monkeypatch.setattr(api_main, "search_cves", lambda *args, **kwargs: (raw, fetch_metadata))

    repository = InMemoryGraphRepository()
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))
    result = app.ingest_cve_search({
        "technology": "Grafana",
        "from_year": 2026,
        "to_year": 2026,
        "nvd_api_key": "test-key-must-not-be-persisted",
    })

    assert result["report"]["vulnerability_count"] == 1
    assert result["search_mode"] == "technology_cpe"
    assert result["cpe_families"] == fetch_metadata["cpe_families"]
    assert result["cpe_candidate_count"] == 1
    assert app.list_cves(technology="grafana", from_year=2026, to_year=2026)[0]["id"] == "CVE-2026-0004"
    jobs = repository.nodes("IngestionJob")
    assert len(jobs) == 1
    assert jobs[0].props["search_mode"] == "technology_cpe"
    assert jobs[0].props["cpe_families"] == fetch_metadata["cpe_families"]
    assert "test-key-must-not-be-persisted" not in repr(repository.nodes())


def test_nvd_technology_no_cpe_match_does_not_snapshot_or_write_graph(tmp_path, monkeypatch):
    from ckg.api import main as api_main
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    monkeypatch.setattr(api_main, "search_cves", lambda *args, **kwargs: (
        b'{"totalResults":0,"vulnerabilities":[]}',
        {
            "truncated": False,
            "upstream_total_known": False,
            "search_mode": "no_cpe_match",
            "cpe_families": [],
            "cpe_candidates_truncated": False,
            "cpe_candidate_count": 0,
        },
    ))
    repository = InMemoryGraphRepository()
    snapshot_root = tmp_path / "snapshots"
    app = CKGApplication(repository, snapshot_root=str(snapshot_root))

    result = app.ingest_cve_search({"technology": "unknown product", "from_year": 2026, "to_year": 2026})

    assert result == {
        "status": "NO_CPE_MATCH",
        "query": {"from_year": 2026, "to_year": 2026, "technology": "unknown product"},
        "search_mode": "no_cpe_match",
        "cpe_families": [],
        "cpe_candidate_count": 0,
        "cpe_candidates_truncated": False,
    }
    assert repository.nodes() == []
    assert not snapshot_root.exists()


def test_capped_unresolved_cpe_search_reports_incomplete_without_writes(tmp_path, monkeypatch):
    from ckg.api import main as api_main
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    monkeypatch.setattr(api_main, "search_cves", lambda *args, **kwargs: (
        b'{"totalResults":0,"vulnerabilities":[]}',
        {
            "truncated": False,
            "upstream_total_known": False,
            "search_mode": "no_cpe_match",
            "cpe_families": [],
            "cpe_candidates_truncated": True,
            "cpe_candidate_count": 2_000,
        },
    ))
    repository = InMemoryGraphRepository()
    snapshot_root = tmp_path / "snapshots"
    app = CKGApplication(repository, snapshot_root=str(snapshot_root))

    result = app.ingest_cve_search({"technology": "ambiguous product", "from_year": 2026, "to_year": 2026})

    assert result["status"] == "CPE_RESOLUTION_INCOMPLETE"
    assert result["cpe_candidates_truncated"] is True
    assert repository.nodes() == []
    assert not snapshot_root.exists()


def test_exact_cpe_search_is_supported_and_recorded(tmp_path, monkeypatch):
    import json
    from ckg.api import main as api_main
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    cpe_name = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"
    calls = []
    monkeypatch.setattr(api_main, "search_cves", lambda *args, **kwargs: (
        calls.append((args, kwargs)) or json.dumps({"totalResults": 0, "vulnerabilities": []}).encode(),
        {
            "truncated": False,
            "upstream_total_known": True,
            "search_mode": "exact_cpe",
            "cpe_families": [cpe_name],
            "cpe_candidates_truncated": False,
            "cpe_candidate_count": 1,
        },
    ))
    repository = InMemoryGraphRepository()
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))

    result = app.ingest_cve_search({"cpe_name": cpe_name, "from_year": 2026, "to_year": 2026})

    assert calls[0][0] == (None,)
    assert calls[0][1]["cpe_name"] == cpe_name
    assert result["query"] == {"from_year": 2026, "to_year": 2026, "cpe_name": cpe_name}
    assert result["search_mode"] == "exact_cpe"
    assert repository.nodes("IngestionJob")[0].props["cpe_name"] == cpe_name


def test_nvd_search_requires_exactly_one_technology_or_cpe_name(tmp_path):
    import pytest
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    app = CKGApplication(InMemoryGraphRepository(), snapshot_root=str(tmp_path / "snapshots"))
    with pytest.raises(ValueError, match="exactly one"):
        app.ingest_cve_search({"from_year": 2026, "to_year": 2026})
    with pytest.raises(ValueError, match="exactly one"):
        app.ingest_cve_search({
            "technology": "Widget",
            "cpe_name": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
            "from_year": 2026,
            "to_year": 2026,
        })


def test_graph_technology_search_never_calls_nvd(monkeypatch, tmp_path):
    from ckg.api import main as api_main
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            _node("CVE", "CVE-2026-0005", title="Widget issue", published_at="2026-01-01T00:00:00+00:00"),
            _node("Product", "PRODUCT-WIDGET", name="widget"),
        ],
        edges=[_edge("A-WIDGET", "AFFECTS", "CVE-2026-0005", "PRODUCT-WIDGET")],
    )
    def unexpected_nvd_call(*args, **kwargs):
        raise AssertionError("NVD should not be called")

    monkeypatch.setattr(api_main, "search_cves", unexpected_nvd_call)
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))

    results = app.list_cves(technology="widget", from_year=2026, to_year=2026)

    assert [item["id"] for item in results] == ["CVE-2026-0005"]


def test_application_paginates_technology_results_with_metadata(tmp_path):
    from ckg.api.main import CKGApplication
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            _node("CVE", "CVE-2026-0200", title="Grafana one", published_at="2026-01-01T00:00:00+00:00"),
            _node("CVE", "CVE-2026-0201", title="Grafana two", published_at="2026-01-01T00:00:00+00:00"),
            _node("Product", "PRODUCT-GRAFANA-1", name="grafana"),
            _node("Product", "PRODUCT-GRAFANA-2", name="grafana"),
        ],
        edges=[
            _edge("A1", "AFFECTS", "CVE-2026-0200", "PRODUCT-GRAFANA-1"),
            _edge("A2", "AFFECTS", "CVE-2026-0201", "PRODUCT-GRAFANA-2"),
        ],
    )
    app = CKGApplication(repository, snapshot_root=str(tmp_path / "snapshots"))

    page = app.list_cves_page(technology="Grafana", from_year=2026, to_year=2026, limit=1, offset=1)

    assert [item["id"] for item in page["cves"]] == ["CVE-2026-0200"]
    assert page["total"] == 2
    assert page["returned"] == 1
    assert page["offset"] == 1
    assert page["truncated"] is False
