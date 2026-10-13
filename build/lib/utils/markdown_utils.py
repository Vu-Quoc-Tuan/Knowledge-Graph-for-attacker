import re
from dataclasses import dataclass, field

HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
# detect type of code block
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
TABLE_ROW_RE = re.compile(r"^\s*\|.*\|\s*$")
# detect table separator row, which support to choose without label
TABLE_SEPARATOR_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")
# detect inline code
INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")

# detect payload for long and short name label
PAYLOAD_COLUMN_TOKENS = ("payload", "query", "injection")
PAYLOAD_COLUMN_NAMES = frozenset(
    {"bypass", "sql", "sql example", "order by", "group by"}
)

PIPE_ESCAPES = (("&#124;", "|"), ("&#x7c;", "|"), ("&#x7C;", "|"), ("\\|", "|"))
_UNESCAPED_PIPE_RE = re.compile(r"(?<!\\)\|")


def table_cells(row: str) -> list[str]:
    """The cells of a table row, split on unescaped delimiters only."""
    parts = _UNESCAPED_PIPE_RE.split(row.strip())
    # A row is delimited on both sides, so the split brackets it with empties.
    if parts and not parts[0].strip():
        parts = parts[1:]
    if parts and not parts[-1].strip():
        parts = parts[:-1]
    return [cell.strip() for cell in parts]


def is_payload_column(header_cell: str) -> bool:
    name = re.sub(r"\s+", " ", header_cell.strip().lower())
    return (
        any(token in name for token in PAYLOAD_COLUMN_TOKENS)
        or name in PAYLOAD_COLUMN_NAMES
    )

def unescape_table_cell(value: str) -> str:
    for escaped, literal in PIPE_ESCAPES:
        value = value.replace(escaped, literal)
    return value

@dataclass
class MarkdownSection:
    heading: str
    level: int
    text: list[str] = field(default_factory=list)
    code_blocks: list[str] = field(default_factory=list)
    # payload in verify collumn
    table_code: list[str] = field(default_factory=list)
    # payload in unclassified collumn
    table_code_unclassified: list[str] = field(default_factory=list)

def parse_markdown(source: str) -> list[MarkdownSection]:
    sections: list[MarkdownSection] = []
    current = MarkdownSection(heading="", level=0)
    sections.append(current)
    fence_char: str | None = None
    fence_len = 0
    code_lines: list[str] = []
    payload_columns: list[int] | None = None
    table_row = 0

    for line in source.splitlines():
        if fence_char is not None:
            stripped = line.lstrip()
            if stripped.startswith(fence_char * fence_len):
                current.code_blocks.append("\n".join(code_lines).strip())
                code_lines = []
                fence_char = None
                fence_len = 0
            else:
                code_lines.append(line)
            continue

        fence = FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            fence_char = marker[0]
            fence_len = len(marker)
            continue

        heading = HEADING_RE.match(line)
        if heading:
            current = MarkdownSection(
                heading=heading.group(2).strip(), level=len(heading.group(1))
            )
            sections.append(current)
            payload_columns, table_row = None, 0
        else:
            current.text.append(line)
            if not TABLE_ROW_RE.match(line):
                payload_columns, table_row = None, 0
                continue
            if TABLE_SEPARATOR_RE.match(line):
                table_row += 1
                continue
            if table_row == 0:
                # The header names the columns; it is not data.
                payload_columns = [
                    index
                    for index, cell in enumerate(table_cells(line))
                    if is_payload_column(cell)
                ]
                table_row = 1
                continue
            table_row += 1
            for index, cell in enumerate(table_cells(line)):
                for span in INLINE_CODE_RE.findall(cell):
                    span = unescape_table_cell(span).strip()
                    if not span:
                        continue
                    if payload_columns and index in payload_columns:
                        current.table_code.append(span)
                    elif not payload_columns:
                        # No header identified a payload column, so which cell
                        # holds one is unknown -- guessing is what admitted the
                        # error-message column as payloads.
                        current.table_code_unclassified.append(span)
                    # Otherwise the header named a payload column and this is not
                    # it (an error, output, or prose neighbour): correctly not a
                    # payload, so not a gap either.

    if fence_char is not None and code_lines:
        current.code_blocks.append("\n".join(code_lines).strip())
    return [
        section
        for section in sections
        if section.heading
        or section.code_blocks
        or section.table_code
        or section.table_code_unclassified
    ]