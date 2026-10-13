import json

from ckg import __main__
from ckg.graph.memory import InMemoryGraphRepository
from ckg.graph.models import GraphNode
from ckg.ingestion.patt.payload_index import PATTIndex


def test_ckg_ingest_patt_from_local_manifest(tmp_path, capsys, monkeypatch) -> None:
    source = tmp_path / "patt.json"
    source.write_text(json.dumps({"sources": [{
        "source_file": "README.md",
        "source_url": "https://example.test/xss",
        "source_revision": "a" * 40,
        "content": "## XSS\n```\n<img src=x onerror=alert(1)>\n```",
        "kind": "markdown",
    }]}), encoding="utf-8")
    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[GraphNode(label="CWE", node_id="CWE-79", props={})], edges=[])
    monkeypatch.setattr(__main__, "_get_repository", lambda args: repository)

    assert __main__.main([
        "ingest", "--patt-cwe", "CWE-79", "--file", str(source), "--memory",
        "--snapshot-root", str(tmp_path / "snapshots"),
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["payload_count"] == 1
    payloads = PATTIndex(tmp_path / "snapshots" / "patt_payloads.sqlite3").query()["payloads"]
    assert payloads[0]["validation_status"] == "untested"
    assert repository.nodes("Payload") == []


def test_ckg_ingest_patt_rejects_mixed_target_flags(tmp_path) -> None:
    manifest = tmp_path / "patt.json"
    manifest.write_text('{"sources": []}', encoding="utf-8")

    try:
        __main__.main(["ingest", "--patt-cwe", "CWE-79", "--cve", "CVE-2026-1", "--file", str(manifest), "--memory"])
    except ValueError as exc:
        assert "exactly one" in str(exc)
    else:
        raise AssertionError("mixed PATT and CVE targets must be rejected")
