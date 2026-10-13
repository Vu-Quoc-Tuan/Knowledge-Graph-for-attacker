"""Legacy PATT loader backed by the canonical pure extraction API.

The legacy ``GraphSink`` schema remains a compatibility boundary. Parsing is
owned by :mod:`ckg.ingestion.patt.payload_extractor`, so legacy and v2 imports
cannot silently diverge on which upstream strings are reference payloads.
"""

from __future__ import annotations

from typing import Any

from ckg.ingestion.patt.payload_extractor import (
    PayloadCandidate,
    extract_payload_candidates,
    extract_wordlist_candidates,
)
from db.sink import GraphSink
from ingest.slices import FamilySpec, VulnSlice
from ingest.technology import normalize_patt_technology
from schema.models import DetectionSignal, Payload, PayloadFamily, Technology
from utils.http import HttpClient, SourceFetchError
from utils.payloads import payload_id


def _ensure_family(sink: GraphSink, family: FamilySpec) -> None:
    sink.merge_node(
        "PayloadFamily",
        "key",
        PayloadFamily(
            key=family.key,
            name=family.name,
            detectionSignal=family.detection_signal,
        ).to_props(),
    )
    if family.detection_signal:
        sink.merge_node(
            "DetectionSignal",
            "key",
            DetectionSignal(
                key=family.detection_signal,
                name=family.detection_signal.replace("_", " "),
            ).to_props(),
        )
        sink.merge_rel(
            "PayloadFamily", "key", family.key,
            "DETECTED_BY", "DetectionSignal", "key", family.detection_signal,
        )


def _family_specs(slice_: VulnSlice) -> dict[str, FamilySpec]:
    families = {family.key: family for family in slice_.families}
    if slice_.intruder_family is not None:
        families[slice_.intruder_family.key] = slice_.intruder_family
    return families


def _materialize_candidate(
    sink: GraphSink,
    candidate: PayloadCandidate,
    *,
    source_file: str,
    source_url: str,
) -> None:
    payload = Payload(
        payloadId=payload_id(candidate.family_key, candidate.value, candidate.technology),
        value=candidate.value,
        sourceFile=source_file,
        sourceUrl=source_url,
        section=candidate.section_heading,
        extraction=candidate.extraction,
    )
    sink.merge_node("Payload", "payloadId", payload.to_props())
    sink.merge_rel(
        "Payload", "payloadId", payload.payloadId,
        "IN_FAMILY", "PayloadFamily", "key", candidate.family_key,
    )
    if candidate.technology:
        sink.merge_rel(
            "Payload", "payloadId", payload.payloadId,
            "ON_TECH", "Technology", "name", candidate.technology,
            {"source": "PayloadsAllTheThings", "file": source_file},
        )


def load_patt(
    sink: GraphSink,
    http: HttpClient,
    slice_: VulnSlice,
    patt_contents_base: str,
    max_payloads_per_family: int = 10,
) -> dict[str, Any]:
    """Load one PATT slice into the legacy graph without owning parser rules."""
    listing_url = f"{patt_contents_base.rstrip('/')}/{_url_dir(slice_.patt_dir)}"
    listing = http.get_json(listing_url)
    if not isinstance(listing, list):
        raise SourceFetchError(
            f"PATT contents response for {slice_.patt_dir} is not a list"
        )
    markdown_files = sorted(
        (
            item for item in listing
            if isinstance(item, dict)
            and str(item.get("name", "")).lower().endswith(".md")
            and item.get("download_url")
        ),
        key=lambda item: (
            0 if str(item["name"]).lower() == "readme.md" else 1,
            str(item["name"]),
        ),
    )
    specs = _family_specs(slice_)
    declared_families = frozenset(family.key for family in slice_.families)
    families: set[str] = set()
    technologies: set[str] = set()
    payloads = 0
    skipped_over_cap = 0
    unclassified_table_spans = 0
    over_cap: list[str] = []
    unevidenced: list[str] = []

    for item in markdown_files:
        filename = str(item["name"])
        source_url = str(item.get("html_url") or item["download_url"])
        source = http.get_text(str(item["download_url"]))
        technology = (
            normalize_patt_technology(filename)
            if slice_.technology_from_filename
            else None
        )
        if technology:
            technologies.add(technology)
            sink.merge_node("Technology", "name", Technology(name=technology).to_props())
        report = extract_payload_candidates(
            slice_,
            source_file=filename,
            source_url=source_url,
            markdown=source,
            technology=technology,
            max_payloads_per_family=max_payloads_per_family,
        )
        for family_key in report.heading_families:
            _ensure_family(sink, specs[family_key])
        counts: dict[str, int] = {}
        for candidate in report.candidates:
            _ensure_family(sink, specs[candidate.family_key])
            _materialize_candidate(
                sink, candidate, source_file=filename, source_url=source_url
            )
            counts[candidate.family_key] = counts.get(candidate.family_key, 0) + 1
        families.update(report.heading_families)
        payloads += len(report.candidates)
        skipped_over_cap += report.skipped_over_cap
        unclassified_table_spans += report.unclassified_table_spans
        over_cap.extend(
            f"{family_key} in {filename}: {dropped} dropped at cap "
            f"{max_payloads_per_family}"
            for family_key, dropped in report.skipped_by_family
        )
        if technology:
            for family_key in sorted(set(report.heading_families) & declared_families):
                if counts.get(family_key, 0) == 0:
                    unevidenced.append(f"{family_key}->{technology} ({filename})")
                    continue
                sink.merge_rel(
                    "PayloadFamily", "key", family_key,
                    "APPLIES_TO", "Technology", "name", technology,
                    {
                        "source": "PayloadsAllTheThings",
                        "file": filename,
                        "payloadCount": counts[family_key],
                    },
                )

    intruder_payloads, intruder_capped = _load_intruder(
        sink, http, slice_, patt_contents_base, max_payloads_per_family
    )
    over_cap.extend(intruder_capped)
    return {
        "cwe": slice_.weakness_id,
        "families": len(families),
        "payloads": payloads,
        "intruder_payloads": intruder_payloads,
        "techs": len(technologies),
        "skipped_over_cap": skipped_over_cap,
        "unclassified_table_spans": unclassified_table_spans,
        "headings_without_payloads": len(unevidenced),
        "over_cap": over_cap,
        "unevidenced": unevidenced,
    }


def _load_intruder(
    sink: GraphSink,
    http: HttpClient,
    slice_: VulnSlice,
    patt_contents_base: str,
    max_payloads_per_family: int,
) -> tuple[int, list[str]]:
    """Load optional Burp Intruder wordlists through the shared extractor."""
    if not slice_.intruder_dir or slice_.intruder_family is None:
        return 0, []
    spec = slice_.intruder_family
    url = (
        f"{patt_contents_base.rstrip('/')}/"
        f"{_url_dir(slice_.patt_dir)}/{_url_dir(slice_.intruder_dir)}"
    )
    try:
        listing = http.get_json(url)
    except SourceFetchError as exc:
        if exc.status_code == 404:
            return 0, []
        raise
    if not isinstance(listing, list):
        raise SourceFetchError(
            f"PATT intruder listing for {slice_.patt_dir} is not a list"
        )
    _ensure_family(sink, spec)
    total = 0
    capped: list[str] = []
    for item in sorted(
        (
            entry for entry in listing
            if isinstance(entry, dict)
            and str(entry.get("name", "")).lower().endswith(".txt")
            and entry.get("download_url")
        ),
        key=lambda entry: str(entry["name"]),
    ):
        filename = str(item["name"])
        source_url = str(item.get("html_url") or item["download_url"])
        report = extract_wordlist_candidates(
            slice_,
            source_file=filename,
            source_url=source_url,
            wordlist=http.get_text(str(item["download_url"])),
            max_payloads_per_family=max_payloads_per_family,
        )
        for candidate in report.candidates:
            _materialize_candidate(
                sink, candidate, source_file=filename, source_url=source_url
            )
        total += len(report.candidates)
        capped.extend(
            f"{family_key} in {filename}: {dropped} dropped at cap "
            f"{max_payloads_per_family}"
            for family_key, dropped in report.skipped_by_family
        )
    return total, capped


def _url_dir(name: str) -> str:
    """GitHub contents path segment: spaces percent-encoded, slashes kept."""
    return name.replace(" ", "%20")
