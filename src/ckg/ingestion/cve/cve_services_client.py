"""CVE Services record client with an overridable endpoint for deployments."""

from __future__ import annotations

import requests


CVE_SERVICES_RECORD_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"


def fetch_record(cve_id: str, *, url_template: str = CVE_SERVICES_RECORD_URL, timeout: float = 30.0) -> bytes:
    response = requests.get(url_template.format(cve_id=cve_id), timeout=timeout)
    response.raise_for_status()
    return response.content
