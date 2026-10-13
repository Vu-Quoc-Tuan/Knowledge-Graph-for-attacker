from datetime import datetime, timezone
import json

from tests.unit.test_canonical_catalogs import CAPEC_XML, CWE_XML
from tests.unit.test_structured_vulnerability_ingestion import NVD_PAYLOAD


def test_foundation_pipeline_builds_canonical_then_imports_multi_cwe_source(tmp_path) -> None:
    from ckg.application.build_initial_graph import build_initial_graph
    from ckg.application.ingest_cve import ingest_structured_source
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    now = datetime(2026, 9, 14, tzinfo=timezone.utc)
    from ckg.ingestion.digests import sha256_digest

    build_initial_graph(
        repository,
        cwe_xml=CWE_XML,
        cwe_snapshot_digest=sha256_digest(CWE_XML),
        cwe_retrieved_at=now,
        cwe_source_url="https://example.test/cwe",
        capec_xml=CAPEC_XML,
        capec_snapshot_digest=sha256_digest(CAPEC_XML),
        capec_retrieved_at=now,
        capec_source_url="https://example.test/capec",
    )
    result = ingest_structured_source(
        repository,
        source_kind="nvd",
        raw_payload=json.dumps(NVD_PAYLOAD).encode(),
        source_url="https://example.test/nvd",
        retrieved_at=now,
        snapshot_root=tmp_path / "snapshots",
    )

    assert result.report.weakness_assertion_count == 2
    assert len(repository.nodes("WeaknessAssertion")) == 2
    assert all(edge.edge_type != "INSTANCE_OF" for edge in repository.edges())


def test_batch_ingestion_enriches_each_cve_and_refreshes_global_state_once(tmp_path, monkeypatch) -> None:
    """Batch enrichment must defer shared graph maintenance until all CVEs exist."""
    from ckg.application import ingest_cve as ingest_module
    from ckg.application.build_initial_graph import build_initial_graph
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.ingestion.digests import sha256_digest

    repository = InMemoryGraphRepository()
    now = datetime(2026, 9, 14, tzinfo=timezone.utc)
    build_initial_graph(
        repository,
        cwe_xml=CWE_XML,
        cwe_snapshot_digest=sha256_digest(CWE_XML),
        cwe_retrieved_at=now,
        cwe_source_url="https://example.test/cwe",
        capec_xml=CAPEC_XML,
        capec_snapshot_digest=sha256_digest(CAPEC_XML),
        capec_retrieved_at=now,
        capec_source_url="https://example.test/capec",
    )
    payload = json.loads(json.dumps(NVD_PAYLOAD))
    payload["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "CWE-79 is reported."
    second = json.loads(json.dumps(NVD_PAYLOAD["vulnerabilities"][0]))
    second["cve"]["id"] = "CVE-2026-10002"
    second["cve"]["descriptions"][0]["value"] = "A separate CWE-89 weakness is reported."
    second["cve"]["weaknesses"] = [{"description": [{"lang": "en", "value": "CWE-89"}]}]
    payload["vulnerabilities"].append(second)

    calls = 0
    real_refresh = ingest_module.refresh_global_maintenance

    def spy_refresh(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_refresh(*args, **kwargs)

    monkeypatch.setattr(ingest_module, "refresh_global_maintenance", spy_refresh)
    result = ingest_module.ingest_structured_source(
        repository,
        source_kind="nvd",
        raw_payload=json.dumps(payload).encode(),
        source_url="https://example.test/nvd",
        retrieved_at=now,
        snapshot_root=tmp_path / "snapshots",
    )

    assert calls == 1
    assert result.global_maintenance is not None
    assert {analysis.vulnerability_id for analysis in result.analyses} == {
        "CVE-2026-10001",
        "CVE-2026-10002",
    }
    assert all(analysis.weakness_assertion_ids for analysis in result.analyses)
    assert all(analysis.scenarios.scenario_count > 0 for analysis in result.analyses)
    assert all(analysis.scenarios.scenario_ids for analysis in result.analyses)
    assert all(analysis.profiles is result.global_maintenance.profiles for analysis in result.analyses)
    assert all(analysis.cooccurrence is result.global_maintenance.cooccurrence for analysis in result.analyses)

    from ckg.application.analyze_vulnerability import analyze_vulnerability

    single = analyze_vulnerability(repository, "CVE-2026-10001", retrieved_at=now)
    assert single.profiles is not None
    assert single.cooccurrence is not None


def test_structured_ingestion_runs_evidence_grounded_multifacet_enrichment(tmp_path) -> None:
    from ckg.application.ingest_cve import ingest_structured_source
    from ckg.domain.entities.cwe import CanonicalWeakness
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(
            label="CWE",
            node_id="CWE-611",
            props=CanonicalWeakness(
                cwe_id="CWE-611",
                name="Improper Restriction of XML External Entity Reference",
                source_release="4.20",
                source_snapshot_digest="sha256:" + "a" * 64,
            ).model_dump(mode="json"),
        ),
        GraphNode(label="Technique", node_id="TECH-OUT_OF_BAND", props={"name": "OutOfBand"}),
        GraphNode(label="Technique", node_id="TECH-BLIND", props={"name": "Blind"}),
        GraphNode(label="CallbackChannel", node_id="CHANNEL-DNS", props={"name": "DNS"}),
        GraphNode(label="DataFormat", node_id="FORMAT-XML", props={"name": "XML"}),
        GraphNode(label="Language", node_id="LANG-PYTHON", props={"name": "Python"}),
        GraphNode(label="Component", node_id="COMPONENT-XML-PARSER", props={"name": "XMLParser"}),
        GraphNode(label="Mechanism", node_id="MECHANISM-EXTERNAL-ENTITY-RESOLUTION", props={"name": "ExternalEntityResolution"}),
    ], edges=[])
    payload = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2026-61101",
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-02T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{
                    "lang": "en",
                    "value": (
                        "A Python XML parser processes external entities in a blind "
                        "out-of-band flow and triggers a DNS callback. External entities "
                        "are enabled and DNS egress is allowed."
                    ),
                }],
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-611"}]}],
                "references": [],
            }
        }]
    }

    result = ingest_structured_source(
        repository,
        source_kind="nvd",
        raw_payload=json.dumps(payload).encode(),
        source_url="https://example.test/nvd",
        retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
        snapshot_root=tmp_path / "snapshots",
    )

    analysis = result.analyses[0]
    assert analysis.vulnerability_id == "CVE-2026-61101"
    assert analysis.evidence_id is not None
    assert analysis.weakness_assertion_ids
    assert len(analysis.technique_assertion_ids) == 2
    # Multiple exact mentions remain separate evidence-backed assertions; the
    # normalized context set is still the three expected facets.
    context_maps = {
        edge.object_id
        for edge in repository.edges("MAPS_TO")
        if edge.subject_id in set(analysis.context_assertion_ids)
    }
    assert context_maps == {
        "CHANNEL-DNS",
        "FORMAT-XML",
        "LANG-PYTHON",
        "COMPONENT-XML-PARSER",
        "MECHANISM-EXTERNAL-ENTITY-RESOLUTION",
    }
    assert analysis.constraint_ids == (
        "CONSTRAINT-EXTERNAL-ENTITIES-ENABLED",
        "CONSTRAINT-NETWORK-EGRESS-ALLOWED",
    )
    assertions = {node.node_id: node for node in repository.nodes("TechniqueAssertion")}
    assert all(assertions[item].props["evidence_spans"] for item in analysis.technique_assertion_ids)
    assert all(assertions[item].props["provenance"]["source_kind"] == "facet_extraction" for item in analysis.technique_assertion_ids)

    from ckg.application.analyze_vulnerability import analyze_cve

    contract = analyze_cve(
        repository,
        "CVE-2026-61101",
        retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )
    assert contract.cve["id"] == "CVE-2026-61101"
    assert any(item["targets"] == ["CWE-611"] for item in contract.weaknesses)
    assert {item["targets"][0] for item in contract.facets["techniques"]} == {
        "TECH-BLIND",
        "TECH-OUT_OF_BAND",
    }
    assert {item["constraint_id"] for item in contract.constraints} == {
        "CONSTRAINT-EXTERNAL-ENTITIES-ENABLED",
        "CONSTRAINT-NETWORK-EGRESS-ALLOWED",
    }
    assert contract.provenance
    assert contract.local_subgraph["node_ids"]
