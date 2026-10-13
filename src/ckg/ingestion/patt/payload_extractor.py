"""Pure extraction of reference payload candidates from PATT source files.

This module deliberately knows only source text and slice policy.  Persistence,
network access, and graph models stay in callers so the same extraction rules
are usable by the legacy importer and the canonical v2 pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .slices import FamilySpec, VulnSlice


_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
_TABLE_ROW_RE = re.compile(r"^\s*\|.*\|\s*$")
_TABLE_SEPARATOR_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_UNESCAPED_PIPE_RE = re.compile(r"(?<!\\)\|")
_PAYLOAD_COLUMN_TOKENS = ("payload", "query", "injection")
_PAYLOAD_COLUMN_NAMES = frozenset({"bypass", "sql", "sql example", "order by", "group by"})
_PIPE_ESCAPES = (("&#124;", "|"), ("&#x7c;", "|"), ("&#x7C;", "|"), ("\\|", "|"))


@dataclass
class MarkdownSection:
    """Minimal PATT parser state, kept in the packaged v2 ingestion plane."""

    heading: str
    level: int
    code_blocks: list[str] = field(default_factory=list)
    table_code: list[str] = field(default_factory=list)
    table_code_unclassified: list[str] = field(default_factory=list)


def _table_cells(row: str) -> list[str]:
    parts = _UNESCAPED_PIPE_RE.split(row.strip())
    if parts and not parts[0].strip():
        parts = parts[1:]
    if parts and not parts[-1].strip():
        parts = parts[:-1]
    return [part.strip() for part in parts]


def _is_payload_column(value: str) -> bool:
    normalized = re.sub(r"\s+", " ", value.strip().lower())
    return any(token in normalized for token in _PAYLOAD_COLUMN_TOKENS) or normalized in _PAYLOAD_COLUMN_NAMES


def _unescape_table_cell(value: str) -> str:
    for escaped, literal in _PIPE_ESCAPES:
        value = value.replace(escaped, literal)
    return value


def _parse_markdown(markdown: str) -> list[MarkdownSection]:
    """Parse only the fenced/table structures the PATT extractor needs."""
    sections: list[MarkdownSection] = []
    current = MarkdownSection(heading="", level=0)
    sections.append(current)
    fence_char: str | None = None
    fence_length = 0
    code_lines: list[str] = []
    payload_columns: list[int] | None = None
    table_row = 0
    for line in markdown.splitlines():
        if fence_char is not None:
            if line.lstrip().startswith(fence_char * fence_length):
                current.code_blocks.append("\n".join(code_lines).strip())
                code_lines, fence_char, fence_length = [], None, 0
            else:
                code_lines.append(line)
            continue
        fence = _FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            fence_char, fence_length = marker[0], len(marker)
            continue
        heading = _HEADING_RE.match(line)
        if heading:
            current = MarkdownSection(heading=heading.group(2).strip(), level=len(heading.group(1)))
            sections.append(current)
            payload_columns, table_row = None, 0
            continue
        if not _TABLE_ROW_RE.match(line):
            payload_columns, table_row = None, 0
            continue
        if _TABLE_SEPARATOR_RE.match(line):
            table_row += 1
            continue
        if table_row == 0:
            payload_columns = [index for index, value in enumerate(_table_cells(line)) if _is_payload_column(value)]
            table_row = 1
            continue
        table_row += 1
        for index, cell in enumerate(_table_cells(line)):
            for span in _INLINE_CODE_RE.findall(cell):
                span = _unescape_table_cell(span).strip()
                if not span:
                    continue
                if payload_columns and index in payload_columns:
                    current.table_code.append(span)
                elif not payload_columns:
                    current.table_code_unclassified.append(span)
    if fence_char is not None and code_lines:
        current.code_blocks.append("\n".join(code_lines).strip())
    return [section for section in sections if section.heading or section.code_blocks or section.table_code or section.table_code_unclassified]


EXCLUDED_HEADINGS = frozenset(
    {
        "summary",
        "references",
        "reference",
        "tools",
        "labs",
        "lab",
        "contributors",
        "credits",
        "external links",
        "further reading",
        "see also",
        "tips",
        "notes",
        "resources",
        "methodology and resources",
    }
)
COMMENT_LINE_RE = re.compile(r"^(--|//|#)(\s|$)")
OUTPUT_MARKERS = (
    "error:",
    "response:",
    "http/",
    "mariadb [",
    "mysql>",
    ">>>",
    "$ ",
    "[*]",
)


@dataclass(frozen=True)
class PayloadCandidate:
    value: str
    family_key: str
    family_name: str
    technology: str | None
    section_heading: str
    locator: str
    extraction: str


@dataclass(frozen=True)
class PayloadExtractionReport:
    candidates: tuple[PayloadCandidate, ...]
    heading_families: tuple[str, ...]
    skipped_over_cap: int
    unclassified_table_spans: int
    headings_without_payloads: tuple[str, ...]
    skipped_by_family: tuple[tuple[str, int], ...] = ()


def _is_excluded_heading(heading: str) -> bool:
    return heading.strip().lower() in EXCLUDED_HEADINGS


def _split_payload_block(block: str) -> list[str]:
    payloads: list[str] = []
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line or COMMENT_LINE_RE.match(line):
            continue
        if payloads and payloads[-1].count("(") > payloads[-1].count(")"):
            payloads[-1] = f"{payloads[-1]}\n{line}"
        else:
            payloads.append(line)
    return payloads


def _is_output_marker(value: str) -> bool:
    return value.strip().lower().startswith(OUTPUT_MARKERS)


def _is_result_table_line(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    if set(stripped) <= set("+-|"):
        return True
    return (
        stripped.startswith("|") and stripped.endswith("|") and " | " in stripped
    )


def _is_structural_fragment(value: str) -> bool:
    stripped = value.strip()
    return len(stripped) <= 3 and not any(char.isalnum() for char in stripped)


def _is_transcript_block(block: str) -> bool:
    lines = [line.strip() for line in block.splitlines() if line.strip()]
    return not lines or _is_output_marker(lines[0])


def _looks_like_payload(value: str) -> bool:
    return bool(value) and (any(ch.isspace() for ch in value) or len(value) > 12)


def _section_candidates(
    section: MarkdownSection, *, split: bool
) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for block in section.code_blocks:
        if _is_transcript_block(block):
            continue
        pieces = _split_payload_block(block) if split else [block.strip()]
        for payload in pieces:
            if (
                payload
                and not _is_output_marker(payload)
                and not _is_result_table_line(payload)
                and not _is_structural_fragment(payload)
            ):
                found.append((payload, "code_block"))
    for span in section.table_code:
        if (
            _looks_like_payload(span)
            and not _is_output_marker(span)
            and not _is_structural_fragment(span)
        ):
            found.append((span, "table_cell"))
    return found


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def extract_payload_candidates(
    slice_: VulnSlice,
    *,
    source_file: str,
    source_url: str,
    markdown: str,
    technology: str | None = None,
    max_payloads_per_family: int = 400,
) -> PayloadExtractionReport:
    """Extract reference candidates from one PATT Markdown source.

    ``source_file`` and ``source_url`` are intentionally supplied with every
    call even though this pure phase does not persist them.  They make the
    boundary explicit and keep callers from reconstructing attribution later.
    """
    del source_file, source_url
    if max_payloads_per_family < 0:
        raise ValueError("max_payloads_per_family must be non-negative")

    heading_families: list[str] = []
    headings_without_payloads: list[str] = []
    candidates: list[PayloadCandidate] = []
    counts: dict[str, int] = {}
    active: FamilySpec | None = None
    active_level = 0
    skipped_over_cap = 0
    skipped_by_family: dict[str, int] = {}
    sections = _parse_markdown(markdown)

    for section_index, section in enumerate(sections):
        found = slice_.family_for(section.heading)
        if found is not None and found.is_catch_all and _is_excluded_heading(
            section.heading
        ):
            active, active_level = None, section.level
        elif found is not None:
            active = found
            active_level = section.level
            _append_unique(heading_families, found.key)
        elif active is not None and section.level <= active_level:
            active = None
        if active is None:
            continue

        accepted = 0
        for value, extraction in _section_candidates(section, split=slice_.split_payloads):
            if not slice_.accepts_payload(value):
                continue
            if counts.get(active.key, 0) >= max_payloads_per_family:
                skipped_over_cap += 1
                skipped_by_family[active.key] = skipped_by_family.get(active.key, 0) + 1
                continue
            candidates.append(
                PayloadCandidate(
                    value=value,
                    family_key=active.key,
                    family_name=active.name,
                    technology=technology,
                    section_heading=section.heading,
                    locator=f"/sections/{section_index}",
                    extraction=extraction,
                )
            )
            counts[active.key] = counts.get(active.key, 0) + 1
            accepted += 1
        if accepted == 0:
            _append_unique(headings_without_payloads, section.heading)

    return PayloadExtractionReport(
        candidates=tuple(candidates),
        heading_families=tuple(heading_families),
        skipped_over_cap=skipped_over_cap,
        unclassified_table_spans=sum(
            len(section.table_code_unclassified) for section in sections
        ),
        headings_without_payloads=tuple(headings_without_payloads),
        skipped_by_family=tuple(sorted(skipped_by_family.items())),
    )


def extract_wordlist_candidates(
    slice_: VulnSlice,
    *,
    source_file: str,
    source_url: str,
    wordlist: str,
    technology: str | None = None,
    max_payloads_per_family: int = 400,
) -> PayloadExtractionReport:
    """Extract one technology-optional reference candidate per Intruder line.

    Wordlists are not Markdown: only blank and full-line comments are filtered.
    A slice without a dedicated Intruder family intentionally produces no data,
    rather than attributing wordlist values to an unrelated Markdown family.
    """
    del source_url
    if max_payloads_per_family < 0:
        raise ValueError("max_payloads_per_family must be non-negative")
    family = slice_.intruder_family
    if family is None:
        return PayloadExtractionReport((), (), 0, 0, ())

    candidates: list[PayloadCandidate] = []
    skipped_over_cap = 0
    section_heading = source_file.rsplit(".", 1)[0]
    for line_number, raw_line in enumerate(wordlist.splitlines(), start=1):
        value = raw_line.strip()
        if not value or COMMENT_LINE_RE.match(value):
            continue
        if len(candidates) >= max_payloads_per_family:
            skipped_over_cap += 1
            continue
        candidates.append(
            PayloadCandidate(
                value=value,
                family_key=family.key,
                family_name=family.name,
                technology=technology,
                section_heading=section_heading,
                locator=f"/lines/{line_number}",
                extraction="intruder_wordlist",
            )
        )
    return PayloadExtractionReport(
        candidates=tuple(candidates),
        heading_families=(family.key,) if candidates else (),
        skipped_over_cap=skipped_over_cap,
        unclassified_table_spans=0,
        headings_without_payloads=(),
        skipped_by_family=((family.key, skipped_over_cap),) if skipped_over_cap else (),
    )


__all__ = [
    "PayloadCandidate",
    "PayloadExtractionReport",
    "extract_payload_candidates",
    "extract_wordlist_candidates",
]
