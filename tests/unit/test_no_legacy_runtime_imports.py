from pathlib import Path


def test_canonical_runtime_entrypoints_do_not_import_legacy_graph_stack() -> None:
    entrypoints = (
        Path("build.py"),
        Path("ui/server.py"),
        Path("src/ckg/__main__.py"),
        Path("src/ckg/api/main.py"),
        Path("src/ckg/runtime.py"),
    )
    forbidden = (
        "from config",
        "import config",
        "from db.sink",
        "import db.sink",
        "from ui.routes",
        "import ui.routes",
    )
    for path in entrypoints:
        source = path.read_text(encoding="utf-8")
        assert not any(token in source for token in forbidden), path


def test_placeholder_api_route_package_is_gone() -> None:
    assert not any(Path("src/ckg/api/routes").glob("*.py"))
