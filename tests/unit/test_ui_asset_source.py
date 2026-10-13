from pathlib import Path


def test_source_ui_has_one_canonical_tree() -> None:
    canonical = Path("src/ckg/ui/v2")
    assert (canonical / "index.html").is_file()
    assert (canonical / "app.js").is_file()
    assert (canonical / "styles.css").is_file()
    assert (canonical / "favicon.svg").is_file()
    assert not any(Path("ui/v2").glob("*"))
    assert not any(Path("ui/assets").glob("**/*"))


def test_source_ui_uses_runtime_backend_and_semantic_scenario_copy() -> None:
    index = (Path("src/ckg/ui/v2") / "index.html").read_text(encoding="utf-8")
    app = (Path("src/ckg/ui/v2") / "app.js").read_text(encoding="utf-8")

    assert 'id="backend-status"' in index
    assert "Backend: checking" in index
    assert "Neo4j Live" not in index
    assert "Kịch Bản Kiểm Tra Ngữ Nghĩa" in index
    assert "function isSupportedCaseId(value)" in app
    assert "initialCase && isSupportedCaseId(initialCase)" in app
    assert 'data-cve="CVE-2023-28850"' in index
    assert 'data-cve="CVE-2024-21626"' not in index
    assert "updateBackendStatus" in app
    assert "Đã nạp thành công vào ${html(backendLabel())}" in app
