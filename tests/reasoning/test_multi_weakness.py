def _node(label, node_id, **props):
    from ckg.graph.models import GraphNode
    return GraphNode(label=label, node_id=node_id, props=props)


def _edge(edge_id, edge_type, source, target):
    from ckg.graph.models import GraphEdge
    return GraphEdge(edge_id=edge_id, edge_type=edge_type, subject_id=source, object_id=target)


def test_multi_weakness_is_independent_without_instance_composition_evidence() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.multi_weakness import MultiWeaknessKind, classify

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-79"),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-89"),
    ], edges=[])

    assert classify(repository, "CVE-2026-10001") == MultiWeaknessKind.INDEPENDENT


def test_multi_weakness_distinguishes_chain_from_explicit_composite() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.multi_weakness import MultiWeaknessKind, classify

    chained = InMemoryGraphRepository()
    chained.atomic_write(nodes=[
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-79"),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-89"),
    ], edges=[_edge("sequence", "ENABLES", "O1", "O2")])
    composite = InMemoryGraphRepository()
    composite.atomic_write(nodes=[
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-79"),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-89"),
        _node("CompositionGroup", "G", vulnerability_id="CVE-2026-10001", operator="ALL_OF", occurrence_ids=["O1", "O2"]),
    ], edges=[])

    assert classify(chained, "CVE-2026-10001") == MultiWeaknessKind.CHAINED
    assert classify(composite, "CVE-2026-10001") == MultiWeaknessKind.COMPOSITE


def test_catalog_partitions_independent_weakness_families() -> None:
    from ckg.scenario.catalog import ScenarioCatalog

    catalog = ScenarioCatalog(
        categories={
            "xss": {"cwe_ids": ["CWE-79"]},
            "sqli": {"cwe_ids": ["CWE-89"]},
        },
        surface_detectors={},
        tech_detectors={},
    )

    assert catalog.group_weaknesses({"CWE-79", "CWE-89"}) == {
        "xss": ("CWE-79",),
        "sqli": ("CWE-89",),
    }


def test_scenario_catalog_renders_text_from_yaml(tmp_path) -> None:
    from ckg.scenario.catalog import ScenarioCatalog

    catalog_path = tmp_path / "scenario_catalog.yaml"
    catalog_path.write_text(
        """
categories: {}
surface_detectors: {}
tech_detectors: {}
templates:
  title:
    param: "CUSTOM ⟦base_name⟧ ⟦param_list⟧"
""",
        encoding="utf-8",
    )
    catalog = ScenarioCatalog.get_default(catalog_path)

    assert catalog.render_title(
        None,
        {"name": "Scenario"},
        {"parameters": ["q"]},
    ) == "CUSTOM Scenario q"


def test_source_and_packaged_scenario_catalogs_are_synchronized() -> None:
    from pathlib import Path

    source = Path("registry/scenario_catalog.yaml").read_bytes()
    packaged = Path("src/ckg/registry/scenario_catalog.yaml").read_bytes()

    assert source == packaged
