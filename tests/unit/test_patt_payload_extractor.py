from ckg.ingestion.patt.payload_extractor import (
    extract_payload_candidates,
    extract_wordlist_candidates,
)
from ckg.ingestion.patt.slices import SLICES


def _slice(weakness_id: str):
    return next(item for item in SLICES if item.weakness_id == weakness_id)


def test_extracts_xss_and_rejects_console_output() -> None:
    report = extract_payload_candidates(
        _slice("CWE-79"),
        source_file="README.md",
        source_url="https://example.test/xss",
        markdown="## XSS\n```html\n<img src=x onerror=alert(1)>\nHTTP/1.1 500\n```",
    )

    assert [candidate.value for candidate in report.candidates] == [
        "<img src=x onerror=alert(1)>"
    ]


def test_keeps_csrf_form_as_one_multiline_payload() -> None:
    report = extract_payload_candidates(
        _slice("CWE-352"),
        source_file="README.md",
        source_url="https://example.test/csrf",
        markdown=(
            "## CSRF\n```html\n<form action='/transfer'>\n"
            "<input name='amount' value='1'>\n</form>\n```"
        ),
    )

    assert len(report.candidates) == 1
    assert "<form" in report.candidates[0].value
    assert "</form>" in report.candidates[0].value


def test_wordlist_ignores_comments_and_keeps_source_line_locator() -> None:
    report = extract_wordlist_candidates(
        _slice("CWE-79"),
        source_file="xss.txt",
        source_url="https://example.test/xss.txt",
        wordlist="# comment\n\n<svg/onload=alert(1)>\n// notes\n<img src=x onerror=1>",
    )

    assert [(item.value, item.family_key, item.locator, item.extraction) for item in report.candidates] == [
        ("<svg/onload=alert(1)>", "xss.generic", "/lines/3", "intruder_wordlist"),
        ("<img src=x onerror=1>", "xss.generic", "/lines/5", "intruder_wordlist"),
    ]


def test_wordlist_without_intruder_family_is_empty() -> None:
    report = extract_wordlist_candidates(
        _slice("CWE-918"),
        source_file="ssrf.txt",
        source_url="https://example.test/ssrf.txt",
        wordlist="http://127.0.0.1/",
    )

    assert report.candidates == ()
