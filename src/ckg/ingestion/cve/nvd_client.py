"""Small NVD API 2.0 client; callers snapshot returned bytes before parsing."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any

import requests


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_MAX_PAGE_SIZE = 2_000
MAX_CPE_RESULTS = 2_000
MAX_CPE_FAMILIES = 50
NVD_RATE_WINDOW_SECONDS = 30.0
NVD_REQUEST_LIMIT_WITHOUT_KEY = 5
NVD_REQUEST_LIMIT_WITH_KEY = 50

_RATE_LIMIT_LOCK = Lock()
_LAST_REQUEST_AT: dict[str, float] = {}


class NVDRateLimitError(RuntimeError):
    """NVD rejected a request because the caller exceeded its API quota."""

    def __init__(self, retry_after_seconds: int | None = None) -> None:
        self.retry_after_seconds = retry_after_seconds
        message = "NVD rate limit reached; retry the search later"
        if retry_after_seconds is not None:
            message += f" (Retry-After: {retry_after_seconds}s)"
        super().__init__(message)


def _wait_for_nvd_rate_limit(api_key: str | None) -> None:
    """Keep this process within NVD's published rolling-window request limits."""
    bucket = "with_api_key" if api_key else "without_api_key"
    request_limit = NVD_REQUEST_LIMIT_WITH_KEY if api_key else NVD_REQUEST_LIMIT_WITHOUT_KEY
    min_interval = NVD_RATE_WINDOW_SECONDS / request_limit
    with _RATE_LIMIT_LOCK:
        now = time.monotonic()
        previous = _LAST_REQUEST_AT.get(bucket)
        if previous is not None:
            wait_seconds = min_interval - (now - previous)
            if wait_seconds > 0:
                time.sleep(wait_seconds)
        _LAST_REQUEST_AT[bucket] = time.monotonic()


def _nvd_get(url: str, *, params: dict[str, Any], headers: dict[str, str], timeout: float):
    api_key = headers.get("apiKey")
    _wait_for_nvd_rate_limit(api_key)
    response = requests.get(url, params=params, headers=headers, timeout=timeout)
    if getattr(response, "status_code", None) == 429:
        retry_after = (getattr(response, "headers", {}) or {}).get("Retry-After")
        try:
            retry_after_seconds = int(retry_after) if retry_after is not None else None
        except (TypeError, ValueError):
            retry_after_seconds = None
        raise NVDRateLimitError(retry_after_seconds)
    response.raise_for_status()
    return response


def fetch_cve(cve_id: str, *, api_key: str | None = None, timeout: float = 30.0) -> bytes:
    headers = {"apiKey": api_key} if api_key else {}
    response = _nvd_get(NVD_CVE_API_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout)
    return response.content


def _nvd_timestamp(value: datetime) -> str:
    """Format UTC timestamps without losing the millisecond boundary."""
    utc_value = value.astimezone(timezone.utc)
    return utc_value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _split_cpe23(value: str) -> list[str] | None:
    """Split a CPE 2.3 URI while preserving escaped delimiters in components."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if character == ":" and not escaped:
            fields.append("".join(current))
            current.clear()
            continue
        current.append(character)
        if character == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    if escaped:
        return None
    fields.append("".join(current))
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        return None
    return fields


def _valid_cpe23(value: str) -> bool:
    fields = _split_cpe23(value)
    return bool(
        fields
        and all(fields[2:])
        and fields[2] in {"a", "o", "h"}
        and fields[3] not in {"", "*", "-"}
        and fields[4] not in {"", "*", "-"}
    )


def _cpe_family(value: str) -> str | None:
    fields = _split_cpe23(value)
    if not fields or not all(fields[2:]) or fields[2] not in {"a", "o", "h"}:
        return None
    if fields[3] in {"", "*", "-"} or fields[4] in {"", "*", "-"}:
        return None
    return ":".join((*fields[:5], *("*" for _ in range(8))))


def _resolve_cpe_families(
    technology: str,
    *,
    api_key: str | None,
    timeout: float,
) -> tuple[list[str], bool, int]:
    """Resolve a technology against one bounded page of NVD's CPE dictionary."""
    headers = {"apiKey": api_key} if api_key else {}
    response = _nvd_get(
        NVD_CPE_API_URL,
        params={"keywordSearch": technology, "startIndex": 0, "resultsPerPage": MAX_CPE_RESULTS},
        headers=headers,
        timeout=timeout,
    )
    payload = response.json()
    products = payload.get("products", [])
    if not isinstance(products, list):
        products = []

    families: set[str] = set()
    for product in products:
        if not isinstance(product, dict):
            continue
        cpe = product.get("cpe")
        if not isinstance(cpe, dict) or cpe.get("deprecated") is True:
            continue
        cpe_name = cpe.get("cpeName")
        if isinstance(cpe_name, str):
            family = _cpe_family(cpe_name)
            if family:
                families.add(family)

    ordered_families = sorted(families)
    try:
        total_results = int(payload.get("totalResults", len(products)))
    except (TypeError, ValueError):
        total_results = len(products)
    lookup_truncated = total_results > len(products)
    candidates_truncated = lookup_truncated or len(ordered_families) > MAX_CPE_FAMILIES
    return ordered_families[:MAX_CPE_FAMILIES], candidates_truncated, len(ordered_families)


def _date_windows(from_year: int, to_year: int) -> list[tuple[datetime, datetime]]:
    start = datetime(from_year, 1, 1, tzinfo=timezone.utc)
    end = datetime(to_year + 1, 1, 1, tzinfo=timezone.utc)
    windows: list[tuple[datetime, datetime]] = []
    while start < end:
        window_end = min(start + timedelta(days=120), end)
        windows.append((start, window_end))
        start = window_end
    return windows


def search_cves(
    technology: str | None,
    *,
    cpe_name: str | None = None,
    from_year: int,
    to_year: int,
    api_key: str | None = None,
    timeout: float = 30.0,
    results_per_page: int = NVD_MAX_PAGE_SIZE,
    max_records: int = 20_000,
    return_metadata: bool = False,
) -> bytes | tuple[bytes, dict[str, Any]]:
    """Fetch CVEs by resolving a technology to CPEs, or by an exact CPE name.

    Technology resolution uses NVD's CPE dictionary.  The resulting CPE product
    families are then used as CVE applicability criteria; CVE descriptions are
    never searched as a fallback.  Returned aggregate bytes are snapshot-ready
    for the structured ingestion pipeline.
    """
    normalized_technology = " ".join((technology or "").split())
    normalized_cpe = (cpe_name or "").strip()
    if bool(normalized_technology) == bool(normalized_cpe):
        raise ValueError("provide exactly one of technology or cpe_name")
    if normalized_cpe and not _valid_cpe23(normalized_cpe):
        raise ValueError("cpe_name must be a valid CPE 2.3 name with a concrete part, vendor, and product")
    if from_year > to_year:
        raise ValueError("from_year must be less than or equal to to_year")
    if results_per_page < 1 or results_per_page > NVD_MAX_PAGE_SIZE:
        raise ValueError(f"results_per_page must be between 1 and {NVD_MAX_PAGE_SIZE}")
    if max_records < 1:
        raise ValueError("max_records must be at least 1")

    candidates_truncated = False
    candidate_count = 1
    if normalized_cpe:
        search_mode = "exact_cpe"
        cpe_families = [normalized_cpe]
    else:
        cpe_families, candidates_truncated, candidate_count = _resolve_cpe_families(
            normalized_technology,
            api_key=api_key,
            timeout=timeout,
        )
        search_mode = "technology_cpe" if cpe_families else "no_cpe_match"

    headers = {"apiKey": api_key} if api_key else {}
    vulnerabilities_by_id: dict[str, dict[str, Any]] = {}
    truncated = False
    upstream_total_known = False
    cve_records_fetched = 0

    if cpe_families:
        selectors = [
            ({"cpeName": family} if search_mode == "exact_cpe" else {"virtualMatchString": family})
            for family in cpe_families
        ]
        windows = _date_windows(from_year, to_year)
        query_count = len(selectors) * len(windows)
        query_index = 0
        stop_search = False

        for selector in selectors:
            for window_start, window_end in windows:
                if cve_records_fetched >= max_records:
                    truncated = True
                    stop_search = True
                    break

                query_index += 1
                start_index = 0
                while True:
                    remaining = max_records - cve_records_fetched
                    if remaining <= 0:
                        truncated = True
                        stop_search = True
                        break
                    params = {
                        **selector,
                        "pubStartDate": _nvd_timestamp(window_start),
                        "pubEndDate": _nvd_timestamp(window_end - timedelta(milliseconds=1)),
                        "startIndex": start_index,
                        "resultsPerPage": min(results_per_page, remaining),
                    }
                    response = _nvd_get(
                        NVD_CVE_API_URL,
                        params=params,
                        headers=headers,
                        timeout=timeout,
                    )
                    payload = response.json()
                    batch = payload.get("vulnerabilities", [])
                    if not isinstance(batch, list):
                        batch = []
                    try:
                        total_results = int(payload.get("totalResults", len(batch)))
                    except (TypeError, ValueError):
                        total_results = len(batch)
                    upstream_total_known = True
                    if not batch:
                        break
                    cve_records_fetched += len(batch)

                    for item in batch:
                        if not isinstance(item, dict):
                            continue
                        cve = item.get("cve")
                        identifier = cve.get("id") if isinstance(cve, dict) else None
                        if not isinstance(identifier, str) or not identifier:
                            continue
                        if identifier in vulnerabilities_by_id:
                            continue
                        if len(vulnerabilities_by_id) >= max_records:
                            truncated = True
                            stop_search = True
                            break
                        vulnerabilities_by_id[identifier] = item

                    start_index += len(batch)
                    page_has_more = start_index < total_results
                    if stop_search:
                        break
                    if cve_records_fetched >= max_records:
                        if page_has_more or query_index < query_count:
                            truncated = True
                            stop_search = True
                        break
                    if not page_has_more:
                        break

                if stop_search:
                    break
            if stop_search:
                break

    vulnerabilities = list(vulnerabilities_by_id.values())
    raw = json.dumps(
        {
            "resultsPerPage": len(vulnerabilities),
            "startIndex": 0,
            "totalResults": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        },
        sort_keys=True,
    ).encode("utf-8")
    metadata: dict[str, Any] = {
        "truncated": truncated,
        "upstream_total_known": upstream_total_known,
        "search_mode": search_mode,
        "cpe_families": cpe_families,
        "cpe_candidates_truncated": candidates_truncated,
        "cpe_candidate_count": candidate_count,
    }
    if return_metadata:
        return raw, metadata
    return raw
