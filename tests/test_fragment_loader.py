from pathlib import Path
import pytest

from db.sink import DryRunSink
from ingest.fragment_loader import (
    FragmentRegistryError,
    load_fragments,
    read_fragment_registry,
)


def test_read_real_fragment_registry():
    path = Path("registry/scenario_fragments.yaml")
    registry = read_fragment_registry(path)
    assert registry.schema_version == 1
    assert len(registry.fragments) >= 10
    ids = [f.fragment_id for f in registry.fragments]
    assert "FRAG-MUT-URL-QUERY-MARKER" in ids
    assert "FRAG-TRIG-UI-RENDER" in ids
    assert "FRAG-ORACLE-DOM-MARKER" in ids


def test_load_fragments_into_sink():
    sink = DryRunSink()
    counts = load_fragments(sink, "registry/scenario_fragments.yaml")

    assert counts["fragments"] >= 10
    assert counts["setup"] >= 2
    assert counts["input_mutation"] >= 3
    assert counts["trigger"] >= 3
    assert counts["oracle"] >= 3

    # Check node in sink
    node = sink.get_node("ScenarioFragment", "fragmentId", "FRAG-MUT-URL-QUERY-MARKER")
    assert node is not None
    assert node["kind"] == "input_mutation"
    assert "parameter_name" in node["requirements"]
    assert "{marker_value}" in node["actionTemplate"]


def test_fragment_registry_missing_file(tmp_path: Path):
    sink = DryRunSink()
    with pytest.raises(FragmentRegistryError, match="does not exist"):
        load_fragments(sink, tmp_path / "nonexistent.yaml")
