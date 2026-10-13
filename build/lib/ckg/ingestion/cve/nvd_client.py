"""Small NVD API 2.0 client; callers snapshot returned bytes before parsing."""

from __future__ import annotations

import requests
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str, *, api_key: str | None = None, timeout: float = 30.0) -> bytes:
    headers = {"apiKey": api_key} if api_key else {}
    response = requests.get(NVD_CVE_API_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout)
    response.raise_for_status()
    return response.content


def _nvd_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def build_search_url(technology: str, *, from_year: int, to_year: int) -> str:
    """Return a reproducible description of an NVD keyword search."""
    query = urlencode({
        "keywordSearch": technology,
        "pubStartDate": f"{from_year:04d}-01-01T00:00:00.000Z",
        "pubEndDate": f"{to_year:04d}-12-31T23:59:59.999Z",
    })
    return f"{NVD_CVE_API_URL}?{query}"


def search_cves(
    technology: str,
    *,
    from_year: int,
    to_year: int,
    api_key: str | None = None,
    timeout: float = 30.0,
    results_per_page: int = 2000,
    max_records: int = 20_000,
    return_metadata: bool = False,
) -> bytes | tuple[bytes, dict[str, bool]]:
    """Fetch NVD keyword results across the API's 120-day date-window limit.

    The returned aggregate is valid NVD-like JSON and is snapshot-ready for the
    normal ingestion pipeline.  Each window is explicitly bounded so a
    multi-year request does not fail because NVD rejects an oversized range.
    """
    technology = " ".join(technology.split())
    if not technology:
        raise ValueError("technology must not be empty")
    if from_year > to_year:
        raise ValueError("from_year must be less than or equal to to_year")
    if results_per_page < 1 or results_per_page > 2_000:
        raise ValueError("results_per_page must be between 1 and 2000")
    if max_records < 1:
        raise ValueError("max_records must be at least 1")

    start = datetime(from_year, 1, 1, tzinfo=timezone.utc)
    end = datetime(to_year + 1, 1, 1, tzinfo=timezone.utc)
    headers = {"apiKey": api_key} if api_key else {}
    vulnerabilities: list[dict] = []
    truncated = False
    upstream_total_known = False
    while start < end and len(vulnerabilities) < max_records:
        window_end = min(start + timedelta(days=120), end)
        start_index = 0
        while start_index < max_records - len(vulnerabilities):
            params = {
                "keywordSearch": technology,
                "pubStartDate": _nvd_timestamp(start),
                "pubEndDate": _nvd_timestamp(window_end - timedelta(milliseconds=1)),
                "startIndex": start_index,
                "resultsPerPage": min(results_per_page, max_records - len(vulnerabilities)),
            }
            response = requests.get(NVD_CVE_API_URL, params=params, headers=headers, timeout=timeout)
            response.raise_for_status()
            payload = response.json()
            batch = payload.get("vulnerabilities", [])
            if not isinstance(batch, list) or not batch:
                break
            vulnerabilities.extend(item for item in batch if isinstance(item, dict))
            total = int(payload.get("totalResults", len(batch)))
            upstream_total_known = True
            start_index += len(batch)
            if len(vulnerabilities) >= max_records and (start_index < total or window_end < end):
                truncated = True
            if start_index >= total:
                break
        start = window_end

    raw = json.dumps(
        {
            "resultsPerPage": len(vulnerabilities),
            "startIndex": 0,
            "totalResults": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        },
        sort_keys=True,
    ).encode("utf-8")
    if return_metadata:
        return raw, {"truncated": truncated, "upstream_total_known": upstream_total_known}
    return raw
