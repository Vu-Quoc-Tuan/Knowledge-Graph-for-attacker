import json

import pytest

from scripts import bootstrap_patt


def test_bootstrap_local_source_emits_v2_manifest(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "xss.txt"
    source.write_text("<svg/onload=1>", encoding="utf-8")
    monkeypatch.setattr("sys.argv", [
        "bootstrap_patt.py", "--patt-cwe", "CWE-79", "--file", str(source),
        "--kind", "wordlist", "--commit", "a" * 40,
    ])

    assert bootstrap_patt.main() == 0
    manifest = json.loads(capsys.readouterr().out)
    assert manifest["sources"][0]["kind"] == "wordlist"
    assert manifest["sources"][0]["content"] == "<svg/onload=1>"


def test_bootstrap_rejects_branch_style_commit(tmp_path, monkeypatch) -> None:
    source = tmp_path / "xss.md"
    source.write_text("## XSS", encoding="utf-8")
    monkeypatch.setattr("sys.argv", [
        "bootstrap_patt.py", "--patt-cwe", "CWE-79", "--file", str(source),
        "--commit", "master",
    ])

    with pytest.raises(ValueError, match="immutable"):
        bootstrap_patt.main()
