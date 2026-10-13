import subprocess
import shutil
from pathlib import Path


def test_wheel_contains_ckg_and_console_entrypoint(tmp_path) -> None:
    root = Path(__file__).resolve().parents[2]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    uv = shutil.which("uv")
    if uv is None:
        raise AssertionError("uv is required to validate the distributable wheel")
    result = subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(wheelhouse)],
        check=True,
        capture_output=True,
        text=True,
        cwd=root,
    )
    wheels = list(wheelhouse.glob("graph_knowledge-*.whl"))
    assert wheels, result.stdout + result.stderr
    # Inspecting the wheel is enough here; importing in the current process
    # could accidentally resolve the checkout via pytest's PYTHONPATH.
    import zipfile
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
    assert "ckg/__main__.py" in names
    assert "ckg/graph/neo4j/schema.cypher" in names
    assert "ckg/config/graph_budgets.yaml" in names
    assert "ckg/ui/v2/index.html" in names
    assert any(name.endswith(".dist-info/entry_points.txt") for name in names)
