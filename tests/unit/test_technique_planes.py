from datetime import datetime, timezone
from pathlib import Path


WSTG_MARKDOWN = """# Testing XML Entity Processing

## Blind out-of-band detection through DNS

Use an out-of-band DNS callback when response behavior is blind.

## General notes

This text is not a payload.
"""

PATT_MARKDOWN = """# XML testing

## Out-of-band DNS bypass

```xml
<!-- raw payload stays outside graph -->
```

## References
"""


def _repository():
    from ckg.domain.entities.cwe import CanonicalWeakness
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[GraphNode(label="CWE", node_id="CWE-611", props=CanonicalWeakness(cwe_id="CWE-611", name="XXE", source_release="4.20", source_snapshot_digest="sha256:" + "a" * 64).model_dump(mode="json"))], edges=[])
    return repository


def test_wstg_oob_and_dns_are_reusable_semantics_with_exact_source_locators() -> None:
    from ckg.ingestion.wstg.importer import import_wstg_case
    from ckg.ingestion.digests import sha256_digest

    repository = _repository()
    report = import_wstg_case(
        repository, wstg_id="WSTG-INPV-07", title="Testing XML", markdown=WSTG_MARKDOWN,
        source_release="latest-pinned", source_snapshot_digest=sha256_digest(WSTG_MARKDOWN.encode()),
        source_url="https://example.test/wstg", retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
        mapping_path=Path("datasets/mappings/technique_aliases.yaml"), target_cwe_ids=("CWE-611",),
    )

    assert report.technique_count == 2
    assert report.channel_count == 1
    assert report.oracle_count == 2
    assert report.input_surface_count == 0
    assert report.target_cwe_count == 1
    assert {node.node_id for node in repository.nodes("Technique")} == {"TECH-BLIND", "TECH-OUT_OF_BAND"}
    channels = repository.nodes("CallbackChannel")
    assert [node.node_id for node in channels] == ["CHANNEL-DNS"]
    assert all(edge.props["locator"] == "/sections/1" for edge in repository.edges("USES_TECHNIQUE"))
    assert not repository.nodes("Payload")
    assert len(repository.nodes("Evidence")) == 1


def test_patt_keeps_payload_out_of_graph_but_records_bypass_heading() -> None:
    from ckg.ingestion.patt.importer import import_patt_document
    from ckg.ingestion.digests import sha256_digest

    repository = _repository()
    report = import_patt_document(
        repository, document_id="PATT-XXE", title="XXE", markdown=PATT_MARKDOWN, source_commit="abc123",
        source_snapshot_digest=sha256_digest(PATT_MARKDOWN.encode()), source_url="https://example.test/patt",
        retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc), mapping_path=Path("datasets/mappings/technique_aliases.yaml"),
    )

    assert report.bypass_count == 1
    assert report.technique_count == 1
    assert not repository.nodes("Payload")
    assert len(repository.nodes("BypassTechnique")) == 1
    assert len(repository.nodes("ProbeFamily")) == 1
    assert len(repository.edges("DESCRIBES_TECHNIQUE")) == 1
    assert [node.node_id for node in repository.nodes("CallbackChannel")] == ["CHANNEL-DNS"]
    assert len(repository.edges("USES_CHANNEL")) == 1
    assert len(repository.nodes("Evidence")) == 1


def test_context_normalizer_abstains_on_unknown_values() -> None:
    from ckg.linking.context.normalizer import normalize_context

    assert normalize_context("Python").context_id == "LANG-PYTHON"
    assert normalize_context("some new framework") is None


def test_ambiguous_technique_alias_is_reported_not_resolved(tmp_path) -> None:
    from ckg.ingestion.wstg.semantic_normalizer import alias_conflicts, normalize_section
    from ckg.ingestion.wstg.section_parser import parse_sections

    mapping = tmp_path / "aliases.yaml"
    mapping.write_text("techniques:\n  A: {name: A, aliases: [same]}\n  B: {name: B, aliases: [same]}\nchannels: {}\noracles: {}\ninput_surfaces: {}\n", encoding="utf-8")
    assert alias_conflicts(mapping) == ("techniques:same:A,B",)
    with __import__("pytest").raises(ValueError, match="ambiguous"):
        normalize_section(parse_sections("# same")[0], mapping_path=mapping)
