from __future__ import annotations

import re
from typing import Any, Iterator

from utils.http import HttpClient, SourceFetchError
from db.sink import GraphSink
from schema.models import CRE, TestActivity


WSTG_STANDARD = "OWASP Web Security Testing Guide (WSTG)"
CWE_RE = re.compile(r"CWE[:\-](\d+)", re.IGNORECASE)
WSTG_RE = re.compile(r"WSTG-[A-Z]+-\d+(?:\.\d+)?", re.IGNORECASE)


def _walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _strings(value: Any) -> Iterator[str]:
    for item in _walk(value):
        if isinstance(item, str):
            yield item


def _cre_nodes(value: Any) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for item in _walk(value):
        if not isinstance(item, dict):
            continue
        if str(item.get("doctype", "")).upper() != "CRE":
            continue
        raw_id = item.get("id") or item.get("cre") or item.get("CRE")
        if raw_id is None:
            continue
        cre_id = str(raw_id).removeprefix("CRE:")
        name = str(item.get("name") or item.get("title") or "")
        found[cre_id] = name
    return sorted(found.items())


def load_opencre(
    sink: GraphSink,
    http: HttpClient,
    opencre_base: str,
    only_cwes: set[str],
) -> dict[str, int]:
    url = f"{opencre_base.rstrip('/')}/map_analysis"
    payload = http.get_json(
        url,
        params={"standard": ["CWE", WSTG_STANDARD], "format": "json"},
    )
    if not isinstance(payload, dict) or not isinstance(payload.get("result"), dict):
        raise SourceFetchError("OpenCRE response has no result object")

    tested_edges: set[tuple[str, str]] = set()
    cre_ids: set[str] = set()
    for root_key, mapping in payload["result"].items():
        cwe_matches = CWE_RE.findall(str(root_key))
        if not cwe_matches:
            cwe_matches = [
                match
                for text in _strings(mapping)
                for match in CWE_RE.findall(text)
            ]
        cwes = {f"CWE-{number}" for number in cwe_matches} & only_cwes
        if not cwes:
            continue
        paths = mapping.get("paths") if isinstance(mapping, dict) else None
        if not isinstance(paths, dict):
            continue
        for path_key, path_data in paths.items():
            wstg_ids = {
                match.upper()
                for text in [str(path_key), *_strings(path_data)]
                for match in WSTG_RE.findall(text)
            }
            if not wstg_ids:
                continue
            cres = _cre_nodes(path_data)
            for wstg_id in sorted(wstg_ids):
                # Id only. OpenCRE asserts the mapping, it does not author the
                # WSTG page, so `source` on the node is left for whoever fills
                # the content; the assertion itself rides on the TESTED_BY edge
                # below. Claiming it here overwrote the real content provenance
                # on every rerun, since this stage runs before the checklist.
                sink.merge_node(
                    "TestActivity", "wstgId", TestActivity(wstgId=wstg_id).to_props()
                )
                for cwe_id in sorted(cwes):
                    via = f"CRE:{cres[0][0]}" if cres else "OpenCRE"
                    sink.merge_rel(
                        "Weakness",
                        "weaknessId",
                        cwe_id,
                        "TESTED_BY",
                        "TestActivity",
                        "wstgId",
                        wstg_id,
                        {"via": via, "source": "OpenCRE"},
                    )
                    tested_edges.add((cwe_id, wstg_id))
                    for cre_id, cre_name in cres:
                        sink.merge_node(
                            "CRE",
                            "creId",
                            CRE(creId=cre_id, name=cre_name).to_props(),
                        )
                        sink.merge_rel(
                            "CRE",
                            "creId",
                            cre_id,
                            "MAPS_TO",
                            "Weakness",
                            "weaknessId",
                            cwe_id,
                        )
                        sink.merge_rel(
                            "CRE",
                            "creId",
                            cre_id,
                            "MAPS_TO",
                            "TestActivity",
                            "wstgId",
                            wstg_id,
                        )
                        cre_ids.add(cre_id)
    return {"tested_by": len(tested_edges), "cres": len(cre_ids)}
