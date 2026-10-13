"""Minimal GitHub GraphQL client for one advisory; response bytes remain snapshot input."""

from __future__ import annotations

import json

import requests


GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
SECURITY_ADVISORY_QUERY = """
query Advisory($ghsaId: String!) {
  securityAdvisory(ghsaId: $ghsaId) {
    ghsaId summary description publishedAt updatedAt withdrawalsAt
    identifiers { type value }
    cwes(first: 100) { nodes { cweId name } }
    references { url }
    vulnerabilities(first: 100) {
      package { ecosystem name }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
""".strip()


def fetch_advisory(ghsa_id: str, *, token: str, timeout: float = 30.0) -> bytes:
    response = requests.post(
        GITHUB_GRAPHQL_URL,
        headers={"Authorization": f"bearer {token}"},
        json={"query": SECURITY_ADVISORY_QUERY, "variables": {"ghsaId": ghsa_id}},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.content


def parse_response_bytes(raw: bytes) -> dict:
    payload = json.loads(raw)
    if payload.get("errors"):
        raise ValueError(f"GitHub advisory query returned errors: {payload['errors']}")
    return payload
