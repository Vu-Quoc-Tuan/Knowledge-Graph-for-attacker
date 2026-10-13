import json
from datetime import datetime, timedelta

import pytest


@pytest.fixture(autouse=True)
def _disable_real_waits_during_client_tests(monkeypatch, request):
    from ckg.ingestion.cve import nvd_client

    if request.node.name != "test_nvd_rate_limiter_enforces_anonymous_and_keyed_quotas":
        monkeypatch.setattr(nvd_client, "_wait_for_nvd_rate_limit", lambda api_key: None)


def _response(payload):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    return Response()


def _cpe_response(*names, total=None):
    return {
        "totalResults": len(names) if total is None else total,
        "products": [
            {
                "cpe": {
                    "cpeName": name,
                    "deprecated": False,
                    "titles": [{"title": name, "lang": "en-US"}],
                }
            }
            for name in names
        ],
    }


def _cve_response(identifier, *, total=1):
    records = [] if identifier is None else [{"cve": {"id": identifier}}]
    return {"totalResults": total, "vulnerabilities": records}


def test_nvd_search_resolves_cpe_then_uses_cpe_family_across_bounded_windows(monkeypatch):
    from ckg.ingestion.cve.nvd_client import NVD_CPE_API_URL, NVD_CVE_API_URL, search_cves

    calls = []

    def fake_get(url, *, params, headers, timeout):
        calls.append((url, params, headers, timeout))
        if url == NVD_CPE_API_URL:
            return _response(_cpe_response(
                "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*",
            ))
        return _response(_cve_response(f"CVE-2026-{len(calls):04d}"))

    monkeypatch.setattr("ckg.ingestion.cve.nvd_client.requests.get", fake_get)

    raw, metadata = search_cves(
        "Widget", from_year=2026, to_year=2026, api_key="test-key", return_metadata=True
    )
    payload = json.loads(raw)
    cpe_calls = [call for call in calls if call[0] == NVD_CPE_API_URL]
    cve_calls = [call for call in calls if call[0] == NVD_CVE_API_URL]

    assert len(cpe_calls) == 1
    assert cpe_calls[0][1]["keywordSearch"] == "Widget"
    assert cpe_calls[0][2] == {"apiKey": "test-key"}
    assert len(cve_calls) == 4
    assert all(call[1]["virtualMatchString"] == "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*" for call in cve_calls)
    assert all("keywordSearch" not in call[1] for call in cve_calls)
    assert all(call[2] == {"apiKey": "test-key"} for call in cve_calls)
    for _, params, _, _ in cve_calls:
        window_start = datetime.fromisoformat(params["pubStartDate"].replace("Z", "+00:00"))
        window_end = datetime.fromisoformat(params["pubEndDate"].replace("Z", "+00:00"))
        assert window_end - window_start < timedelta(days=120)
    assert payload["totalResults"] == 4
    assert metadata == {
        "truncated": False,
        "upstream_total_known": True,
        "search_mode": "technology_cpe",
        "cpe_families": ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"],
        "cpe_candidates_truncated": False,
        "cpe_candidate_count": 1,
    }


def test_nvd_search_uses_exact_cpe_without_catalog_lookup(monkeypatch):
    from ckg.ingestion.cve.nvd_client import NVD_CPE_API_URL, NVD_CVE_API_URL, search_cves

    calls = []

    def fake_get(url, *, params, headers, timeout):
        calls.append((url, params))
        return _response(_cve_response(None, total=0))

    monkeypatch.setattr("ckg.ingestion.cve.nvd_client.requests.get", fake_get)

    raw, metadata = search_cves(
        None,
        cpe_name="cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
        from_year=2026,
        to_year=2026,
        return_metadata=True,
    )

    assert calls
    assert all(url == NVD_CVE_API_URL for url, _ in calls)
    assert all(params["cpeName"] == "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*" for _, params in calls)
    assert all("virtualMatchString" not in params for _, params in calls)
    assert all(url != NVD_CPE_API_URL for url, _ in calls)
    assert json.loads(raw)["totalResults"] == 0
    assert metadata["search_mode"] == "exact_cpe"
    assert metadata["cpe_families"] == ["cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"]


def test_nvd_search_deduplicates_cves_returned_for_multiple_cpe_families(monkeypatch):
    from ckg.ingestion.cve.nvd_client import NVD_CPE_API_URL, search_cves

    cpes = _cpe_response(
        "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:other:widget:1.0:*:*:*:*:*:*:*",
    )
    calls = []

    def fake_get(url, *, params, headers, timeout):
        calls.append((url, params))
        if url == NVD_CPE_API_URL:
            return _response(cpes)
        return _response(_cve_response("CVE-2026-1000"))

    monkeypatch.setattr("ckg.ingestion.cve.nvd_client.requests.get", fake_get)

    raw, metadata = search_cves("Widget", from_year=2026, to_year=2026, return_metadata=True)

    assert json.loads(raw)["totalResults"] == 1
    assert len(metadata["cpe_families"]) == 2
    assert len({item[1]["virtualMatchString"] for item in calls if "virtualMatchString" in item[1]}) == 2


def test_nvd_search_reports_cve_truncation(monkeypatch):
    from ckg.ingestion.cve.nvd_client import NVD_CPE_API_URL, search_cves

    def fake_get(url, *, params, headers, timeout):
        if url == NVD_CPE_API_URL:
            return _response(_cpe_response("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"))
        records = [
            {"cve": {"id": f"CVE-2026-{index:04d}"}}
            for index in range(params["resultsPerPage"])
        ]
        return _response({"totalResults": 100, "vulnerabilities": records})

    monkeypatch.setattr("ckg.ingestion.cve.nvd_client.requests.get", fake_get)

    raw, metadata = search_cves(
        "Widget", from_year=2026, to_year=2026, max_records=2, return_metadata=True
    )

    assert json.loads(raw)["totalResults"] == 2
    assert metadata["truncated"] is True
    assert metadata["upstream_total_known"] is True


def test_nvd_search_paginates_each_cpe_query_and_deduplicates_page_results(monkeypatch):
    from ckg.ingestion.cve.nvd_client import NVD_CPE_API_URL, search_cves

    pages = []

    def fake_get(url, *, params, headers, timeout):
        if url == NVD_CPE_API_URL:
            return _response(_cpe_response("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"))
        pages.append(params["startIndex"])
        if params["startIndex"] == 0:
            ids = ["CVE-2026-1000", "CVE-2026-1001"]
        else:
            ids = ["CVE-2026-1001", "CVE-2026-1002"]
        return _response({
            "totalResults": 4,
            "vulnerabilities": [{"cve": {"id": identifier}} for identifier in ids],
        })

    monkeypatch.setattr("ckg.ingestion.cve.nvd_client.requests.get", fake_get)

    raw, metadata = search_cves(
        "Widget", from_year=2026, to_year=2026, results_per_page=2, return_metadata=True
    )

    # Four date windows are queried; each uses two pages and dedupes the
    # overlapping CVE returned by the second page.
    assert pages == [0, 2] * 4
    assert json.loads(raw)["totalResults"] == 3
    assert metadata["truncated"] is False


def test_nvd_search_reports_candidate_cap_and_no_match(monkeypatch):
    from ckg.ingestion.cve.nvd_client import NVD_CPE_API_URL, search_cves

    monkeypatch.setattr(
        "ckg.ingestion.cve.nvd_client.MAX_CPE_FAMILIES",
        1,
    )
    cpe_response = _cpe_response(
        "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:other:widget:1.0:*:*:*:*:*:*:*",
    )
    calls = []

    def fake_get(url, *, params, headers, timeout):
        calls.append((url, params))
        if url == NVD_CPE_API_URL:
            return _response(cpe_response)
        return _response(_cve_response(None, total=0))

    monkeypatch.setattr("ckg.ingestion.cve.nvd_client.requests.get", fake_get)
    _, metadata = search_cves("Widget", from_year=2026, to_year=2026, return_metadata=True)

    assert len(metadata["cpe_families"]) == 1
    assert metadata["cpe_candidates_truncated"] is True
    assert metadata["cpe_candidate_count"] == 2

    def no_match(url, *, params, headers, timeout):
        assert url == NVD_CPE_API_URL
        return _response(_cpe_response())

    monkeypatch.setattr("ckg.ingestion.cve.nvd_client.requests.get", no_match)
    raw, no_match_metadata = search_cves("Unknown", from_year=2026, to_year=2026, return_metadata=True)
    assert json.loads(raw)["vulnerabilities"] == []
    assert no_match_metadata["search_mode"] == "no_cpe_match"


def test_nvd_search_requires_exactly_one_of_technology_or_cpe_name():
    from ckg.ingestion.cve.nvd_client import search_cves

    with pytest.raises(ValueError, match="exactly one"):
        search_cves(None, from_year=2026, to_year=2026)
    with pytest.raises(ValueError, match="exactly one"):
        search_cves("Widget", cpe_name="cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", from_year=2026, to_year=2026)


def test_nvd_rate_limit_response_is_explicit_and_preserves_retry_after(monkeypatch):
    from ckg.ingestion.cve.nvd_client import NVDRateLimitError, search_cves

    class RateLimitedResponse:
        status_code = 429
        headers = {"Retry-After": "23"}

        def raise_for_status(self):
            raise AssertionError("the rate limit must be mapped before raise_for_status")

    monkeypatch.setattr(
        "ckg.ingestion.cve.nvd_client.requests.get",
        lambda *args, **kwargs: RateLimitedResponse(),
    )

    with pytest.raises(NVDRateLimitError, match="retry the search later") as error:
        search_cves("Widget", from_year=2026, to_year=2026, return_metadata=True)

    assert error.value.retry_after_seconds == 23


def test_nvd_rate_limiter_enforces_anonymous_and_keyed_quotas(monkeypatch):
    from ckg.ingestion.cve import nvd_client

    clock = [0.0]
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(nvd_client, "_LAST_REQUEST_AT", {})
    monkeypatch.setattr(nvd_client.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(nvd_client.time, "sleep", fake_sleep)

    nvd_client._wait_for_nvd_rate_limit(None)
    nvd_client._wait_for_nvd_rate_limit(None)
    nvd_client._wait_for_nvd_rate_limit("test-key")
    nvd_client._wait_for_nvd_rate_limit("test-key")

    assert sleeps == pytest.approx([6.0, 0.6])
