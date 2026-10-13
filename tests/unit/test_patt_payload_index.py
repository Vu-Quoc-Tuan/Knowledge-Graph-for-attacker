from ckg.ingestion.patt.payload_index import PATTIndex


def _record(payload_id: str, family_key: str, value: str, technology: str | None = None) -> dict:
    return {
        "payload_id": payload_id,
        "cwe_id": "CWE-79",
        "family_key": family_key,
        "family_name": family_key.upper(),
        "technology": technology,
        "value": value,
        "source_file": "README.md",
        "source_url": "https://example.test/patt",
        "source_revision": "a" * 40,
        "source_kind": "markdown",
        "source_snapshot_digest": "sha256:" + "b" * 64,
        "section_heading": "XSS",
        "locator": "/sections/1",
        "extraction": "fenced_code",
    }


def test_index_upserts_and_pages_without_losing_family_summary(tmp_path) -> None:
    index = PATTIndex(tmp_path / "patt_payloads.sqlite3")
    assert index.put_many([
        _record("P-1", "xss.generic", "<svg/onload=1>"),
        _record("P-2", "xss.generic", "<img onerror=1>", "HTML"),
        _record("P-3", "xss.generic", "javascript:alert(1)", "HTML"),
    ]) == 3
    assert index.put_many([_record("P-2", "xss.generic", "<img onerror=2>", "HTML")]) == 1

    page = index.query(cwe_ids=("CWE-79",), limit=2, offset=1)
    assert page["total"] == 3
    assert page["offset"] == 1
    assert len(page["payloads"]) == 2
    assert page["truncated"] is False
    assert page["families"] == [{
        "family_key": "xss.generic",
        "family_name": "XSS.GENERIC",
        "payload_count": 3,
        "technologies": ["HTML"],
    }]
