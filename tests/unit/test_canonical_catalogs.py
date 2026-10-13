from datetime import datetime, timezone
import io
import zipfile

import pytest


CWE_XML = b"""<?xml version='1.0'?>
<Weakness_Catalog Name='CWE' Version='4.18' xmlns='http://cwe.mitre.org/cwe-7'>
  <Weaknesses>
    <Weakness ID='79' Name='Improper Neutralization of Input During Web Page Generation' Abstraction='Base' Status='Stable'>
      <Description>Untrusted web content is generated without neutralization.</Description>
      <Applicable_Platforms>
        <Language Class='Not Language-Specific' Prevalence='Undetermined'/>
        <Technology Name='Web Server' Prevalence='Often'/>
      </Applicable_Platforms>
      <Mapping_Notes>
        <Usage>Allowed</Usage>
        <Rationale>Base abstraction.</Rationale>
        <Comments>Use only with suitable evidence.</Comments>
        <Reasons><Reason Type='Acceptable-Use'/></Reasons>
      </Mapping_Notes>
      <Related_Weaknesses>
        <Related_Weakness Nature='ChildOf' CWE_ID='20' View_ID='1000'/>
        <Related_Weakness Nature='CanPrecede' CWE_ID='200' View_ID='1000'/>
        <Related_Weakness Nature='CanFollow' CWE_ID='201' View_ID='1000'/>
        <Related_Weakness Nature='StartsWith' CWE_ID='202' View_ID='1000'/>
        <Related_Weakness Nature='Requires' CWE_ID='203' View_ID='1000'/>
        <Related_Weakness Nature='RequiredBy' CWE_ID='204' View_ID='1000'/>
        <Related_Weakness Nature='PeerOf' CWE_ID='205' View_ID='1000'/>
        <Related_Weakness Nature='CanAlsoBe' CWE_ID='206' View_ID='1000'/>
        <Related_Weakness Nature='ParentOf' CWE_ID='207' View_ID='1000'/>
      </Related_Weaknesses>
    </Weakness>
    <Weakness ID='20' Name='Improper Input Validation' Abstraction='Class' Status='Deprecated'>
      <Description>Input is not validated.</Description>
    </Weakness>
    <Weakness ID='89' Name='Improper Neutralization of Special Elements used in an SQL Command' Abstraction='Base' Status='Stable'>
      <Description>SQL command elements are not neutralized.</Description>
    </Weakness>
  </Weaknesses>
  <Categories>
    <Category ID='1' Name='Input Validation' Status='Stable'>
      <Summary>Input category.</Summary>
      <Relationships><Has_Member CWE_ID='79' View_ID='1000'/></Relationships>
    </Category>
  </Categories>
  <Views>
    <View ID='1000' Name='Research Concepts' Status='Stable'>
      <Objective>Research view.</Objective>
      <Members><Has_Member CWE_ID='20'/><Has_Member CWE_ID='79'/></Members>
    </View>
  </Views>
</Weakness_Catalog>
"""

CAPEC_XML = b"""<?xml version='1.0'?>
<Attack_Pattern_Catalog Name='CAPEC' Version='3.9' xmlns='http://capec.mitre.org/capec-3'>
  <Attack_Patterns>
    <Attack_Pattern ID='63' Name='Cross-Site Scripting'>
      <Description>Inject script into a web page.</Description>
      <Execution_Flow>
        <Attack_Step><Phase>Explore</Phase><Description>Find a reflected input.</Description></Attack_Step>
        <Attack_Step><Phase>Exploit</Phase><Description>Submit script.</Description></Attack_Step>
      </Execution_Flow>
      <Prerequisites><Prerequisite>The target accepts input.</Prerequisite></Prerequisites>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID='79'/>
        <Related_Weakness CWE_ID='611'/>
      </Related_Weaknesses>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


def test_cwe_parser_keeps_relation_nature_view_release_and_snapshot() -> None:
    from ckg.ingestion.cwe.parser import parse_cwe_catalog

    catalog = parse_cwe_catalog(
        CWE_XML,
        source_snapshot_digest="sha256:" + "a" * 64,
        retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
        source_url="https://example.test/cwe.xml.zip",
    )

    assert [weakness.cwe_id for weakness in catalog.weaknesses] == ["CWE-20", "CWE-79", "CWE-89"]
    assert {relation.predicate for relation in catalog.relations} == {
        "CanAlsoBe", "CanFollow", "CanPrecede", "ChildOf", "ParentOf",
        "PeerOf", "RequiredBy", "Requires", "StartsWith",
    }
    weakness = next(item for item in catalog.weaknesses if item.cwe_id == "CWE-79")
    assert weakness.mapping_usage == "Allowed"
    assert weakness.mapping_reasons == ("Acceptable-Use",)
    assert weakness.applicable_platforms == (
        "Language:Class=Not Language-Specific;Prevalence=Undetermined",
        "Technology:Name=Web Server;Prevalence=Often",
    )
    assert next(item for item in catalog.weaknesses if item.cwe_id == "CWE-20").lifecycle_status == "Deprecated"
    assert [(group.group_id, group.kind) for group in catalog.groups] == [
        ("CWE-CATEGORY-1", "CATEGORY"),
        ("CWE-VIEW-1000", "VIEW"),
    ]
    assert catalog.group_memberships == (
        ("CWE-CATEGORY-1", "CWE-79", "1000"),
        ("CWE-VIEW-1000", "CWE-20", None),
        ("CWE-VIEW-1000", "CWE-79", None),
    )
    assert all(relation.source_release == "4.18" for relation in catalog.relations)
    assert all(relation.source_snapshot_digest == "sha256:" + "a" * 64 for relation in catalog.relations)


def test_capec_parser_preserves_multiple_related_weaknesses_without_composing_them() -> None:
    from ckg.ingestion.capec.parser import parse_capec_catalog

    catalog = parse_capec_catalog(
        CAPEC_XML,
        source_snapshot_digest="sha256:" + "b" * 64,
        retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )

    assert [pattern.capec_id for pattern in catalog.patterns] == ["CAPEC-63"]
    assert {relation.cwe_id for relation in catalog.related_weaknesses} == {"CWE-79", "CWE-611"}
    assert not hasattr(catalog, "composition")
    assert [(step.ordinal, step.phase) for step in catalog.steps] == [(1, "Explore"), (2, "Exploit")]
    assert catalog.prerequisites[0].description == "The target accepts input."


def test_capec_import_reports_unresolved_cwe_without_creating_a_placeholder() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.ingestion.capec.importer import import_capec_catalog
    from ckg.ingestion.capec.parser import parse_capec_catalog
    from ckg.ingestion.cwe.importer import import_cwe_catalog
    from ckg.ingestion.cwe.parser import parse_cwe_catalog

    repository = InMemoryGraphRepository()
    cwe_catalog = parse_cwe_catalog(
        CWE_XML,
        source_snapshot_digest="sha256:" + "a" * 64,
        retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )
    capec_catalog = parse_capec_catalog(
        CAPEC_XML,
        source_snapshot_digest="sha256:" + "b" * 64,
        retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )

    import_cwe_catalog(repository, cwe_catalog)
    report = import_capec_catalog(repository, capec_catalog)

    assert report.unresolved_cwe_ids == ("CWE-611",)
    assert repository.nodes("CWE") == sorted(repository.nodes("CWE"), key=lambda node: node.node_id)
    related_weaknesses = repository.edges("RELATED_WEAKNESS")
    assert len(related_weaknesses) == 1
    assert related_weaknesses[0].object_id == "CWE-79"
    assert {node.node_id for node in repository.nodes("CWE")} == {"CWE-20", "CWE-79", "CWE-89"}


def test_cwe_import_reports_group_members_that_are_absent_from_this_release() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.ingestion.cwe.importer import import_cwe_catalog
    from ckg.ingestion.cwe.parser import parse_cwe_catalog

    modified = CWE_XML.replace(b"<Has_Member CWE_ID='79' View_ID='1000'/>", b"<Has_Member CWE_ID='999999' View_ID='1000'/>")
    catalog = parse_cwe_catalog(
        modified,
        source_snapshot_digest="sha256:" + "a" * 64,
        retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )
    report = import_cwe_catalog(InMemoryGraphRepository(), catalog)

    assert report.membership_count == 2
    assert report.unresolved_group_memberships == (("CWE-CATEGORY-1", "CWE-999999", "1000"),)


def test_cwe_import_preserves_immutable_content_revisions_and_as_of_projection() -> None:
    from ckg.graph.canonical import canonical_content_by_id
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.ingestion.cwe.importer import import_cwe_catalog
    from ckg.ingestion.cwe.parser import parse_cwe_catalog

    repository = InMemoryGraphRepository()
    first = parse_cwe_catalog(
        CWE_XML,
        source_snapshot_digest="sha256:" + "a" * 64,
        retrieved_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    second_xml = (
        CWE_XML.replace(b"Version='4.18'", b"Version='4.19'")
        .replace(
            b"Untrusted web content is generated without neutralization.",
            b"Updated canonical definition for release 4.19.",
        )
    )
    second = parse_cwe_catalog(
        second_xml,
        source_snapshot_digest="sha256:" + "c" * 64,
        retrieved_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )

    import_cwe_catalog(repository, first)
    import_cwe_catalog(repository, second)

    revisions = [
        node for node in repository.nodes("CWEContentRevision")
        if node.props["canonical_id"] == "CWE-79"
    ]
    assert len(revisions) == 2
    assert {node.props["source_release"] for node in revisions} == {"4.18", "4.19"}
    assert canonical_content_by_id(
        repository, "CWE", as_of=datetime(2026, 1, 15, tzinfo=timezone.utc)
    )["CWE-79"].props["description"] == "Untrusted web content is generated without neutralization."
    assert canonical_content_by_id(repository, "CWE")["CWE-79"].props["description"] == "Updated canonical definition for release 4.19."
    memberships = repository.edges("HAS_MEMBER")
    assert len({edge.edge_id for edge in memberships}) == 6


def test_cwe_replay_does_not_move_content_revision_availability() -> None:
    from ckg.graph.canonical import canonical_content_by_id
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.ingestion.cwe.importer import import_cwe_catalog
    from ckg.ingestion.cwe.parser import parse_cwe_catalog

    repository = InMemoryGraphRepository()
    digest = "sha256:" + "d" * 64
    january = parse_cwe_catalog(CWE_XML, source_snapshot_digest=digest, retrieved_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    march = parse_cwe_catalog(CWE_XML, source_snapshot_digest=digest, retrieved_at=datetime(2026, 3, 1, tzinfo=timezone.utc))
    import_cwe_catalog(repository, january)
    import_cwe_catalog(repository, march)

    current = canonical_content_by_id(repository, "CWE", as_of=datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert current["CWE-79"].props["retrieved_at"] == "2026-01-01T00:00:00+00:00"


def test_sidecar_only_canonical_lookup_respects_as_of_and_latest(tmp_path) -> None:
    from ckg.graph.canonical import canonical_content_by_id
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode
    from ckg.provenance.compact_details import CompactDetailStore, export_compact_details

    repository = InMemoryGraphRepository()
    store = CompactDetailStore(tmp_path / "compact_details.sqlite3")
    revisions = [
        GraphNode(
            label="CWEContentRevision", node_id=f"CWE-89-{version}",
            props={
                "canonical_id": "CWE-89",
                "retrieved_at": retrieved_at,
                "description": version,
            },
        )
        for version, retrieved_at in (
            ("old", "2026-01-01T00:00:00+00:00"),
            ("new", "2026-03-01T00:00:00+00:00"),
        )
    ]
    export_compact_details(revisions, [], store)
    repository.set_compact_detail_store(store)

    assert repository.nodes("CWEContentRevision") == []
    assert canonical_content_by_id(repository, "CWE", as_of=datetime(2025, 12, 31, tzinfo=timezone.utc)) == {}
    assert canonical_content_by_id(repository, "CWE", as_of=datetime(2026, 2, 1, tzinfo=timezone.utc))["CWE-89"].props["description"] == "old"


    # Importer replay can re-create a compacted identity in the graph; the
    # original sidecar timestamp must remain authoritative.
    repository.atomic_write(nodes=[
        GraphNode(
            label="CWEContentRevision", node_id="CWE-89-old",
            props={"canonical_id": "CWE-89", "retrieved_at": "2026-05-01T00:00:00+00:00", "description": "replayed"},
        )
    ], edges=[])
    assert canonical_content_by_id(repository, "CWE", as_of=datetime(2026, 2, 1, tzinfo=timezone.utc))["CWE-89"].props["description"] == "old"
    assert canonical_content_by_id(repository, "CWE")["CWE-89"].props["description"] == "new"

    repository.atomic_write(nodes=[
        GraphNode(
            label="CWEContentRevision", node_id="CWE-89-newest",
            props={"canonical_id": "CWE-89", "retrieved_at": "2026-04-01T00:00:00+00:00", "description": "graph release"},
        )
    ], edges=[])
    assert canonical_content_by_id(repository, "CWE")["CWE-89"].props["description"] == "graph release"
    assert canonical_content_by_id(repository, "CWE", as_of=datetime(2026, 2, 1, tzinfo=timezone.utc))["CWE-89"].props["description"] == "old"


def test_release_scoped_edge_without_selected_content_fails_closed(tmp_path) -> None:
    from ckg.graph.canonical import canonical_content_by_id, canonical_edge_visible
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode
    from ckg.provenance.compact_details import CompactDetailStore

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CWE", node_id="CWE-89", props={}),
        GraphNode(label="CWE", node_id="CWE-74", props={}),
    ], edges=[])
    repository.set_compact_detail_store(CompactDetailStore(tmp_path / "missing.sqlite3"))
    edge = GraphEdge(
        edge_id="CHILD-89-74", edge_type="CHILD_OF",
        subject_id="CWE-89", object_id="CWE-74",
        props={"source_release": "4.18"},
    )
    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert canonical_content_by_id(repository, "CWE", as_of=cutoff) == {}
    assert canonical_edge_visible(repository, edge, as_of=cutoff) is False


def test_release_scoped_edge_after_as_of_cutoff_fails_closed() -> None:
    from ckg.graph.canonical import canonical_edge_visible
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CAPEC", node_id="CAPEC-63", props={}),
        GraphNode(label="CWE", node_id="CWE-79", props={}),
        GraphNode(
            label="CAPECContentRevision", node_id="CAPEC-63-rev",
            props={"canonical_id": "CAPEC-63", "source_release": "3.9", "retrieved_at": "2026-03-01T00:00:00+00:00"},
        ),
    ], edges=[])
    edge = GraphEdge(
        edge_id="CAPEC-63-CWE-79", edge_type="RELATED_WEAKNESS",
        subject_id="CAPEC-63", object_id="CWE-79",
        props={"source_release": "3.9"},
    )
    assert canonical_edge_visible(repository, edge) is True
    assert canonical_edge_visible(repository, edge, as_of=datetime(2026, 2, 1, tzinfo=timezone.utc)) is False


def test_release_scoped_cwe_edge_requires_every_endpoint_revision() -> None:
    from ckg.graph.canonical import canonical_edge_visible
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CWE", node_id="CWE-89", props={}),
        GraphNode(label="CWE", node_id="CWE-74", props={}),
        GraphNode(label="CWEContentRevision", node_id="CWE-89-rev", props={
            "canonical_id": "CWE-89", "source_release": "4.18",
            "retrieved_at": "2026-01-01T00:00:00+00:00",
        }),
    ], edges=[])
    hierarchy = GraphEdge(
        edge_id="child", edge_type="CHILD_OF", subject_id="CWE-89", object_id="CWE-74",
        props={"source_release": "4.18"},
    )
    membership = GraphEdge(
        edge_id="member", edge_type="HAS_MEMBER", subject_id="CWE-CATEGORY-1", object_id="CWE-74",
        props={"source_release": "4.18"},
    )
    catalog_anchor = GraphEdge(
        edge_id="catalog", edge_type="HAS_CANONICAL_REVISION", subject_id="CWE-CATALOG-4.18", object_id="CWE-74",
        props={"source_release": "4.18"},
    )
    assert canonical_edge_visible(repository, hierarchy) is False
    assert canonical_edge_visible(repository, membership) is False
    assert canonical_edge_visible(repository, catalog_anchor) is False


def test_non_catalog_and_unscoped_edges_keep_existing_visibility() -> None:
    from ckg.graph.canonical import canonical_edge_visible
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CWEContentRevision", node_id="CWE-89-rev", props={
            "canonical_id": "CWE-89", "source_release": "4.18",
            "retrieved_at": "2026-01-01T00:00:00+00:00",
        }),
    ], edges=[])
    non_catalog = GraphEdge(
        edge_id="example", edge_type="DESCRIBES", subject_id="SRC-1", object_id="CVE-1",
        props={"source_release": "1"},
    )
    unscoped = GraphEdge(
        edge_id="example-2", edge_type="CHILD_OF", subject_id="CWE-89", object_id="CWE-74",
    )
    assert canonical_edge_visible(repository, non_catalog) is True
    assert canonical_edge_visible(repository, unscoped) is True
    cross_domain = GraphEdge(
        edge_id="example-3", edge_type="MAPS_TO", subject_id="CVE-1", object_id="CWE-89",
        props={"source_release": "4.19"},
    )
    assert canonical_edge_visible(repository, cross_domain) is False


def test_capec_sidecar_lookup_and_malformed_revision_fail_closed(tmp_path) -> None:
    import sqlite3

    import pytest

    from ckg.graph.canonical import canonical_content_by_id
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode
    from ckg.provenance.compact_details import CompactDetailStore, export_compact_details

    repository = InMemoryGraphRepository()
    store = CompactDetailStore(tmp_path / "compact_details.sqlite3")
    revision = GraphNode(
        label="CAPECContentRevision", node_id="CAPEC-100-rev",
        props={"canonical_id": "CAPEC-100", "retrieved_at": "2026-01-01T00:00:00+00:00"},
    )
    export_compact_details([revision], [], store)
    repository.set_compact_detail_store(store)
    assert canonical_content_by_id(repository, "CAPEC") == {"CAPEC-100": revision}

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE compact_details SET payload_json = ? WHERE detail_id = ?",
            ('{"label":"CWEContentRevision","node_id":"CAPEC-100-rev","props":{}}', revision.node_id),
        )
    with pytest.raises(ValueError, match="invalid CAPEC content revisions"):
        canonical_content_by_id(repository, "CAPEC")


def test_catalog_client_extracts_a_single_xml_member_from_a_pinned_zip() -> None:
    from ckg.ingestion.cwe.client import extract_single_xml

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("cwec_v4.20.xml", CWE_XML)
        zip_file.writestr("README.txt", b"catalog")

    assert extract_single_xml(archive.getvalue()) == CWE_XML


def test_catalog_client_rejects_a_catalog_release_other_than_the_pinned_release() -> None:
    from ckg.ingestion.cwe.client import assert_release

    with __import__("pytest").raises(ValueError, match="expected 4.20"):
        assert_release(actual="4.18", expected="4.20", catalog="CWE")
