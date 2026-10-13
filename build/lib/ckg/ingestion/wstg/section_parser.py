"""Heading-tree parser that retains exact section paths for evidence spans."""

from __future__ import annotations

from dataclasses import dataclass
import re


HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")


@dataclass(frozen=True)
class WSTGSection:
    index: int
    level: int
    heading: str
    path: tuple[str, ...]
    text: str


def parse_sections(markdown: str) -> tuple[WSTGSection, ...]:
    stack: list[tuple[int, str]] = []
    sections: list[WSTGSection] = []
    text: list[str] = []

    def flush() -> None:
        if not sections:
            return
        previous = sections[-1]
        sections[-1] = WSTGSection(previous.index, previous.level, previous.heading, previous.path, "\n".join(text).strip())
        text.clear()

    for line in markdown.splitlines():
        match = HEADING.match(line)
        if not match:
            text.append(line)
            continue
        flush()
        level = len(match.group(1))
        heading = match.group(2).strip()
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, heading))
        sections.append(WSTGSection(len(sections), level, heading, tuple(item[1] for item in stack), ""))
    flush()
    return tuple(sections)
