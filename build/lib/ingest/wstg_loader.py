from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlparse

from utils.http import HttpClient, SourceFetchError
from utils.markdown_utils import parse_markdown
from utils.text import abridge
from db.sink import GraphSink
from ingest.technology import normalize_wstg_technology
from schema.models import MethodologyPage, Technology, TestActivity, is_bare_activity


FILE_RE = re.compile(r"^(\d+)(?:\.(\d+))?-(.+)\.md$", re.IGNORECASE)
WSTG_ID_RE = re.compile(r"WSTG-[A-Z]+-\d+(?:\.\d+)?", re.IGNORECASE)
WSTG_LATEST_MARKER = "/latest/"


def _file_sort(item: dict[str, Any]) -> tuple[int, int, str]:
    match = FILE_RE.match(str(item.get("name", "")))
    if not match:
        return (999, 999, str(item.get("name", "")))
    return (int(match.group(1)), int(match.group(2) or 0), match.group(3))


def _title(source: str, fallback: str) -> str:
    sections = parse_markdown(source)
    return next((section.heading for section in sections if section.level == 1), fallback)


def _document_path(reference: str) -> str | None:
    """Path below WSTG's `document/` root, derived from an official reference."""
    parsed = urlparse(reference)
    if parsed.netloc.lower() != "owasp.org" or WSTG_LATEST_MARKER not in parsed.path:
        return None
    path = unquote(parsed.path.split(WSTG_LATEST_MARKER, 1)[1]).strip("/")
    return path or None


def _raw_url(reference: str, raw_base: str) -> str | None:
    path = _document_path(reference)
    return f"{raw_base.rstrip('/')}/{path}.md" if path else None


def _contents_url(reference: str, contents_base: str) -> str | None:
    path = _document_path(reference)
    if not path or "/" not in path:
        return None
    return f"{contents_base.rstrip('/')}/{path.rsplit('/', 1)[0]}"


def _category_url(tests: list[dict[str, Any]]) -> str | None:
    references = [
        str(test.get("reference") or "").rstrip("/")
        for test in tests
        if test.get("reference")
    ]
    if not references:
        return None
    parents = {reference.rsplit("/", 1)[0] for reference in references}
    return next(iter(parents)) if len(parents) == 1 else None


def _checklist_indexes(
    data: Any,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, tuple[str, list[dict[str, Any]]]],
]:
    categories = data.get("categories") if isinstance(data, dict) else None
    if not isinstance(categories, dict):
        raise SourceFetchError("WSTG checklist has no categories object")

    by_test: dict[str, dict[str, Any]] = {}
    by_category: dict[str, tuple[str, list[dict[str, Any]]]] = {}
    for category_name, category in categories.items():
        if not isinstance(category, dict):
            continue
        category_id = str(category.get("id") or "").upper()
        if not category_id:
            continue
        tests: list[dict[str, Any]] = []
        for test in category.get("tests") or []:
            if not isinstance(test, dict):
                continue
            wstg_id = str(test.get("id") or "").upper()
            if not WSTG_ID_RE.fullmatch(wstg_id):
                continue
            normalized = {**test, "id": wstg_id}
            # Upstream has historically contained duplicate IDs. First wins so
            # one live ordering produces one deterministic assertion.
            if wstg_id not in by_test:
                by_test[wstg_id] = normalized
                tests.append(normalized)
        by_category[category_id] = (str(category_name), tests)
    return by_test, by_category


def _page_activity(
    http: HttpClient,
    test: dict[str, Any],
    raw_base: str,
) -> TestActivity:
    wstg_id = str(test["id"]).upper()
    reference = str(test.get("reference") or "")
    raw_url = _raw_url(reference, raw_base)
    if not raw_url:
        raise SourceFetchError(
            f"WSTG {wstg_id} has an unsupported reference URL: {reference}"
        )
    source = http.get_text(raw_url)
    objectives = [str(item) for item in test.get("objectives") or [] if item]
    return TestActivity(
        wstgId=wstg_id,
        name=_title(source, str(test.get("name") or "")) or None,
        summary=abridge("\n".join(source.splitlines()[:40]), 1000, boundary="\n")
        or None,
        objectives=objectives or None,
        source="OWASP WSTG",
        url=reference or None,
        sourcePage=raw_url,
    )


def load_wstg(
    sink: GraphSink,
    http: HttpClient,
    listing_url: str,
    section: int,
    parent_fallback: str,
) -> dict[str, int]:
    """Load one WSTG chapter's test tree.

    ``section`` is the ``NN`` prefix that selects the chapter (5 = SQL Injection
    inside Input Validation Testing); ``parent_fallback`` is the WSTG id used
    for the parent only when the main file does not state one. Both are passed
    in so a different chapter (a new CWE's methodology) is a call-site change,
    not an edit here.
    """
    listing = http.get_json(listing_url)
    if not isinstance(listing, list):
        raise SourceFetchError("WSTG GitHub contents response is not a list")
    candidates = []
    for item in listing:
        if not isinstance(item, dict):
            continue
        match = FILE_RE.match(str(item.get("name", "")))
        if match and int(match.group(1)) == section:
            candidates.append(item)
    candidates.sort(key=_file_sort)

    main = variants = related = 0
    parent_id = parent_fallback
    for item in candidates:
        name = str(item.get("name"))
        match = FILE_RE.match(name)
        if match is None:
            raise SourceFetchError(f"invalid WSTG entry filename: {name}")
        download_url = item.get("download_url")
        if not download_url:
            raise SourceFetchError(f"WSTG entry has no download_url: {name}")
        source = http.get_text(str(download_url))
        found_id = WSTG_ID_RE.search(source)
        variant_number = match.group(2)
        wstg_id = (
            found_id.group(0).upper()
            if found_id
            else parent_id + (f".{variant_number}" if variant_number else "")
        )
        activity = TestActivity(
            wstgId=wstg_id,
            # `or None` for the same reason the model defaults are None: an empty
            # H1 or an empty page must leave the property absent, not write "".
            name=_title(source, match.group(3).replace("_", " ")) or None,
            summary=abridge(
                "\n".join(source.splitlines()[:40]), 1000, boundary="\n"
            )
            or None,
            source="OWASP WSTG",
            url=str(item.get("html_url") or download_url),
        )
        sink.merge_node("TestActivity", "wstgId", activity.to_props())
        if variant_number is None:
            parent_id = wstg_id
            main += 1
            continue

        technology = normalize_wstg_technology(match.group(3))
        if technology:
            sink.merge_node(
                "Technology", "name", Technology(name=technology).to_props()
            )
            sink.merge_rel(
                "TestActivity",
                "wstgId",
                parent_id,
                "HAS_VARIANT",
                "TestActivity",
                "wstgId",
                wstg_id,
                {"source": "OWASP WSTG"},
            )
            sink.merge_rel(
                "TestActivity",
                "wstgId",
                wstg_id,
                "ON_TECH",
                "Technology",
                "name",
                technology,
            )
            variants += 1
        else:
            sink.merge_rel(
                "TestActivity",
                "wstgId",
                parent_id,
                "RELATED_TO",
                "TestActivity",
                "wstgId",
                wstg_id,
                {"source": "OWASP WSTG"},
            )
            related += 1
    return {"main": main, "variants": variants, "related": related}


def load_wstg_checklist(
    sink: GraphSink, http: HttpClient, checklist_url: str
) -> dict[str, Any]:
    """Fill methodology for WSTG activities that OpenCRE left as bare pointers.

    OpenCRE maps a CWE to a WSTG id but carries no page content, so every
    non-SQLi web CWE points at a TestActivity that has only its id. WSTG ships
    ``checklist.json`` -- id, name, canonical URL and objectives for every test
    -- so one fetch enriches all of them without scraping 140 pages or hardcoding
    which folder each id lives in.

    Only bare nodes are enriched -- see `is_bare_activity`, which wants both a
    name and a url -- so the richer per-DBMS pages already loaded from the source
    markdown are left untouched.
    """
    data = http.get_json(checklist_url)
    categories = data.get("categories") if isinstance(data, dict) else None
    if not isinstance(categories, dict):
        raise SourceFetchError("WSTG checklist has no categories object")

    bare = {
        node["wstgId"]
        for node in sink.nodes("TestActivity")
        if is_bare_activity(node)
    }
    filled: set[str] = set()
    for category in categories.values():
        if not isinstance(category, dict):
            continue
        for test in category.get("tests", []) or []:
            wstg_id = str(test.get("id", ""))
            if wstg_id not in bare:
                continue
            objectives = [str(item) for item in test.get("objectives") or [] if item]
            activity = TestActivity(
                wstgId=wstg_id,
                name=str(test.get("name") or "") or None,
                summary=abridge(" ".join(objectives), 1000) or None,
                objectives=objectives or None,
                source="OWASP WSTG checklist",
                url=str(test.get("reference") or "") or None,
            )
            sink.merge_node("TestActivity", "wstgId", activity.to_props())
            # Counted as filled only if it actually stopped being bare. A
            # checklist entry missing `reference` yields a name and no url, which
            # is still bare: claiming it here would drop it from `still_bare`
            # while `weakness_card` kept excluding it -- invisible in both.
            if not is_bare_activity(activity.to_props()):
                filled.add(wstg_id)
    # An id the checklist never lists stays a content-free pointer. Named, not
    # left as the difference between two counts, because a consumer asking for
    # that CWE's methodology would otherwise be handed an empty node.
    return {
        "bare_before": len(bare),
        "enriched": len(filled),
        "still_bare": sorted(bare - filled),
    }


def load_wstg_catalog(
    sink: GraphSink,
    http: HttpClient,
    checklist_url: str,
    contents_base: str,
    raw_base: str,
) -> dict[str, Any]:
    """Enrich and expand every WSTG root mapped by OpenCRE.

    `WSTG-<category>-00` roots expand to the tests in that exact checklist
    category. Every exact test then discovers numbered Markdown descendants
    (`NN.x-...md`) from its own official source directory. The traversal is
    driven by OpenCRE roots and WSTG metadata, never by a CWE-specific registry.
    """
    by_test, by_category = _checklist_indexes(http.get_json(checklist_url))
    roots = sorted(
        {
            rel["to_value"]
            for rel in sink.match_rels(
                "TESTED_BY",
                from_label="Weakness",
                to_label="TestActivity",
            )
        }
    )

    touched: set[str] = set(roots)
    enriched: set[str] = set()
    child_edges: set[tuple[str, str]] = set()
    variant_edges: set[tuple[str, str]] = set()
    related_children: set[tuple[str, str]] = set()
    expanded: set[str] = set()
    listing_cache: dict[str, list[dict[str, Any]]] = {}

    def enrich_test(test: dict[str, Any]) -> str:
        activity = _page_activity(http, test, raw_base)
        sink.merge_node(
            "TestActivity", "wstgId", activity.to_props()
        )
        touched.add(activity.wstgId)
        enriched.add(activity.wstgId)
        return activity.wstgId

    def listing_for(reference: str) -> list[dict[str, Any]]:
        url = _contents_url(reference, contents_base)
        if not url:
            raise SourceFetchError(
                f"cannot derive WSTG contents directory from {reference}"
            )
        if url not in listing_cache:
            listing = http.get_json(url)
            if not isinstance(listing, list):
                raise SourceFetchError(
                    f"WSTG GitHub contents response is not a list: {url}"
                )
            listing_cache[url] = [
                item for item in listing if isinstance(item, dict)
            ]
        return listing_cache[url]

    def expand_numbered(parent_id: str, test: dict[str, Any]) -> None:
        if parent_id in expanded:
            return
        expanded.add(parent_id)
        reference = str(test.get("reference") or "")
        number = parent_id.rsplit("-", 1)[-1]
        if not number.isdigit():
            return
        pattern = re.compile(
            rf"^{re.escape(number)}\.(\d+)-(.+)\.md$",
            re.IGNORECASE,
        )
        for item in sorted(listing_for(reference), key=_file_sort):
            filename = str(item.get("name") or "")
            match = pattern.match(filename)
            if not match:
                continue
            download_url = item.get("download_url")
            if not download_url:
                raise SourceFetchError(
                    f"WSTG child entry has no download_url: {filename}"
                )
            source = http.get_text(str(download_url))
            # Numbered files such as 05.1-Testing_for_Oracle.md are linked by
            # the parent WSTG test but are not standalone WSTG tests: upstream
            # gives them no WSTG ID. Keep their official source URL as identity
            # instead of inventing WSTG-INPV-05.1.
            found = WSTG_ID_RE.search(source)
            if found:
                raise SourceFetchError(
                    "numbered WSTG methodology page unexpectedly declares "
                    f"a standalone test ID {found.group(0).upper()}: {download_url}"
                )
            child_id = str(download_url)
            activity = MethodologyPage(
                sourcePage=child_id,
                name=_title(
                    source,
                    match.group(2).replace("_", " "),
                )
                or None,
                summary=abridge(
                    "\n".join(source.splitlines()[:40]),
                    1000,
                    boundary="\n",
                )
                or None,
                source="OWASP WSTG",
                url=str(item.get("html_url") or download_url),
            )
            sink.merge_node(
                "MethodologyPage", "sourcePage", activity.to_props()
            )
            sink.merge_rel(
                "TestActivity", "wstgId", parent_id,
                "HAS_CHILD", "MethodologyPage", "sourcePage", child_id,
                {"source": "OWASP WSTG"},
            )
            enriched.add(child_id)
            child_edges.add((parent_id, child_id))

            technology = normalize_wstg_technology(match.group(2))
            if technology:
                sink.merge_node(
                    "Technology", "name", Technology(name=technology).to_props()
                )
                sink.merge_rel(
                    "TestActivity", "wstgId", parent_id,
                    "HAS_VARIANT", "MethodologyPage", "sourcePage", child_id,
                    {"source": "OWASP WSTG"},
                )
                sink.merge_rel(
                    "MethodologyPage", "sourcePage", child_id,
                    "ON_TECH", "Technology", "name", technology,
                    {"source": "OWASP WSTG"},
                )
                variant_edges.add((parent_id, child_id))
            else:
                related_children.add((parent_id, child_id))

    for root_id in roots:
        if root_id.endswith("-00"):
            category_id = root_id[:-3]
            category = by_category.get(category_id)
            if not category:
                continue
            category_name, tests = category
            index_url = _category_url(tests)
            sink.merge_node(
                "TestActivity",
                "wstgId",
                TestActivity(
                    wstgId=root_id,
                    name=category_name or None,
                    summary=abridge(
                        "Official WSTG category containing: "
                        + ", ".join(str(test["id"]) for test in tests),
                        1000,
                    )
                    or None,
                    source="OWASP WSTG checklist",
                    url=index_url,
                ).to_props(),
            )
            enriched.add(root_id)
            for test in tests:
                child_id = enrich_test(test)
                sink.merge_rel(
                    "TestActivity", "wstgId", root_id,
                    "HAS_CHILD", "TestActivity", "wstgId", child_id,
                    {"source": "OWASP WSTG"},
                )
                child_edges.add((root_id, child_id))
                expand_numbered(child_id, test)
            continue

        test = by_test.get(root_id)
        if test:
            enrich_test(test)
            expand_numbered(root_id, test)
            continue

        # A directly mapped numbered variant may not appear in checklist.json.
        # Expand its checklist-backed parent so the source page can prove it.
        base, dot, _variant = root_id.rpartition(".")
        parent_test = by_test.get(base) if dot else None
        if parent_test:
            expand_numbered(base, parent_test)

    still_bare = sorted(
        wstg_id
        for wstg_id in touched
        if (
            (node := sink.get_node("TestActivity", "wstgId", wstg_id))
            is None
            or is_bare_activity(node)
        )
    )
    return {
        "roots": len(roots),
        "enriched": len(enriched),
        "children": len(child_edges),
        "variants": len(variant_edges),
        "related": len(related_children),
        "still_bare": still_bare,
    }
