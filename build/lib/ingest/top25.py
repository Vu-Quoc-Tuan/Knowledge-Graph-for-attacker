from __future__ import annotations

from dataclasses import dataclass

from utils.http import HttpClient
from db.sink import GraphSink
from ingest.cwe_loader import load_cwe


@dataclass(frozen=True)
class Top25Entry:
    rank: int
    cwe_id: str
    score: float
    kev_count: int


@dataclass(frozen=True)
class SupplementalEntry:
    cwe_id: str
    source: str
    reason: str


TOP25_YEAR = 2025
TOP25_SOURCE = "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"


TOP25_2025 = tuple(
    Top25Entry(rank, f"CWE-{cwe}", score, kev)
    for rank, cwe, score, kev in (
        (1, 79, 60.38, 7),
        (2, 89, 28.72, 4),
        (3, 352, 13.64, 0),
        (4, 862, 13.28, 0),
        (5, 787, 12.68, 12),
        (6, 22, 8.99, 10),
        (7, 416, 8.47, 14),
        (8, 125, 7.88, 3),
        (9, 78, 7.85, 20),
        (10, 94, 7.57, 7),
        (11, 120, 6.96, 0),
        (12, 434, 6.87, 4),
        (13, 476, 6.41, 0),
        (14, 121, 5.75, 4),
        (15, 502, 5.23, 11),
        (16, 122, 5.21, 6),
        (17, 863, 4.14, 4),
        (18, 20, 4.09, 2),
        (19, 284, 4.07, 1),
        (20, 200, 4.01, 1),
        (21, 306, 3.47, 11),
        (22, 918, 3.36, 0),
        (23, 77, 3.15, 2),
        (24, 639, 2.62, 0),
        (25, 770, 2.54, 0),
    )
)

TOP25_2024_SOURCE = (
    "https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html"
)
SUPPLEMENTAL_CWES = (
    SupplementalEntry(
        "CWE-269", TOP25_2024_SOURCE, "CWE Top 25 2024 legacy member"
    ),
    SupplementalEntry(
        "CWE-798", TOP25_2024_SOURCE, "CWE Top 25 2024 legacy member"
    ),
    SupplementalEntry(
        "CWE-190", TOP25_2024_SOURCE, "CWE Top 25 2024 legacy member"
    ),
    SupplementalEntry(
        "CWE-93",
        "https://cwe.mitre.org/data/definitions/93.html",
        "requested related weakness",
    ),
    SupplementalEntry(
        "CWE-116",
        "https://cwe.mitre.org/data/definitions/116.html",
        "requested related weakness",
    ),
)
TRACKED_CWE_IDS = frozenset(
    entry.cwe_id for entry in (*TOP25_2025, *SUPPLEMENTAL_CWES)
)


def load_top25(
    sink: GraphSink, http: HttpClient, cwe_api_base: str
) -> dict[str, int]:
    fetched: set[str] = set()
    child_of = 0
    for entry in TOP25_2025:
        result = load_cwe(
            sink,
            http,
            entry.cwe_id,
            cwe_api_base,
            extra_props={
                "top25Year": TOP25_YEAR,
                "top25Rank": entry.rank,
                "top25Score": entry.score,
                "kevCount": entry.kev_count,
                "top25Source": TOP25_SOURCE,
            },
            fetched=fetched,
        )
        child_of += result["child_of"]
    for entry in SUPPLEMENTAL_CWES:
        result = load_cwe(
            sink,
            http,
            entry.cwe_id,
            cwe_api_base,
            extra_props={
                "trackingSource": entry.source,
                "trackingReason": entry.reason,
            },
            fetched=fetched,
        )
        child_of += result["child_of"]
    return {
        "top25": len(TOP25_2025),
        "supplemental": len(SUPPLEMENTAL_CWES),
        "weaknesses_fetched": len(fetched),
        "child_of": child_of,
    }
