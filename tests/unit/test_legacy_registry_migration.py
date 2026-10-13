from pathlib import Path


def _registry_yaml() -> str:
    return """schema_version: 1
vulnerabilities:
  - vuln_id: CVE-2026-10001
    title: Test multi evidence record
    description: A test vulnerability.
    published_at: '2026-01-01T00:00:00Z'
    cwe_id: CWE-79
    epistemic_status: canonical
    product: {name: Example, vendor: Acme}
    component: {name: renderer, path: src/renderer.py}
    version_ranges:
      - {spec: '< 1.2.3', status: affected}
    evidence:
      - evidence_id: EVD-aaaaaaaa
        source_ref: https://example.test/advisory
        source_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        excerpt: Untrusted script is rendered.
  - vuln_id: CVE-2026-10002
    title: Missing source snapshot must not be validated
    published_at: '2026-01-02T00:00:00Z'
    cwe_id: CWE-89
    epistemic_status: validated
    evidence:
      - evidence_id: EVD-bbbbbbbb
        source_ref: https://example.test/advisory-2
        source_hash: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        excerpt: SQL injection.
  - vuln_id: CVE-2026-10003
    title: Unknown CWE stays unresolved
    published_at: '2026-01-03T00:00:00Z'
    cwe_id: CWE-999999
    evidence:
      - evidence_id: EVD-cccccccc
        source_ref: https://example.test/advisory-3
        source_hash: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
        excerpt: Unknown weakness.
  - vuln_id: CVE-2026-10004
    title: Evidence-free claim is not asserted
    published_at: '2026-01-04T00:00:00Z'
    cwe_id: CWE-79
"""


def test_legacy_registry_migration_reifies_claims_and_preserves_missing_source_state(tmp_path: Path) -> None:
    from ckg.domain.entities.cwe import CanonicalWeakness
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode
    from ckg.migration.legacy_registry import migrate_legacy_vulnerability_registry

    registry = tmp_path / "vulnerabilities.yaml"
    registry.write_text(_registry_yaml(), encoding="utf-8")
    objects = tmp_path / "objects"
    objects.mkdir()
    (objects / ("a" * 64)).write_text("upstream bytes", encoding="utf-8")

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            GraphNode(label="CWE", node_id="CWE-79", props=CanonicalWeakness(cwe_id="CWE-79", name="XSS", source_release="4.20", source_snapshot_digest="sha256:" + "d" * 64).model_dump(mode="json")),
            GraphNode(label="CWE", node_id="CWE-89", props=CanonicalWeakness(cwe_id="CWE-89", name="SQLi", source_release="4.20", source_snapshot_digest="sha256:" + "d" * 64).model_dump(mode="json")),
        ],
        edges=[],
    )

    report = migrate_legacy_vulnerability_registry(repository, registry, snapshot_object_dir=objects)

    assert report.target_schema == "ckg-v2"
    assert report.vulnerability_count == 4
    assert report.weakness_assertion_count == 2
    assert report.unresolved_cwe_ids == ("CWE-999999",)
    assert report.missing_snapshot_evidence_ids == (
        "EVID-legacy-EVD-bbbbbbbb".replace("EVD-", ""),
        "EVID-legacy-EVD-cccccccc".replace("EVD-", ""),
    )
    assert report.skipped_assertion_vulnerability_ids == ("CVE-2026-10003", "CVE-2026-10004")
    diagnostic_codes = {code for code, _, _ in report.diagnostics}
    assert diagnostic_codes == {
        "MISSING_EVIDENCE_SPAN",
        "MISSING_SNAPSHOT_ARTIFACT",
        "UNRESOLVED_CWE_TARGET",
    }
    assert any(
        code == "MISSING_SNAPSHOT_ARTIFACT" and identifier == "EVID-legacy-bbbbbbbb"
        for code, identifier, _ in report.diagnostics
    )
    assert not repository.edges("INSTANCE_OF")
    assert len(repository.edges("HAS_WEAKNESS_ASSERTION")) == 2
    assert len(repository.edges("MAPS_TO")) == 2
    assertions = {node.node_id: node for node in repository.nodes("WeaknessAssertion")}
    statuses = {node.props["vulnerability_id"]: node.props["status"] for node in assertions.values()}
    assert statuses == {"CVE-2026-10001": "REPORTED", "CVE-2026-10002": "REPORTED"}
    assert next(node for node in assertions.values() if node.props["vulnerability_id"] == "CVE-2026-10002").props["stale"] is True
    assert repository.nodes("CWE")[-1].node_id != "CWE-999999"

    second_report = migrate_legacy_vulnerability_registry(repository, registry, snapshot_object_dir=objects)
    assert second_report == report
    assert len(repository.nodes("WeaknessAssertion")) == 2
    assert len(repository.edges("MAPS_TO")) == 2
