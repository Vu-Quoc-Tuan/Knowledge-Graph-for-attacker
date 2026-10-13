"""Heading-grounded PATT technique classification, never raw payload extraction."""

from __future__ import annotations

from pathlib import Path

from ckg.ingestion.wstg.semantic_normalizer import normalize_section
from ckg.ingestion.wstg.section_parser import WSTGSection


def extract_techniques(section: WSTGSection, *, mapping_path: str | Path):
    # PATT fenced blocks are empirical payload examples.  They must not create
    # ontology links merely because a string inside a payload resembles a term.
    techniques, channels, _oracles, _inputs = normalize_section(
        WSTGSection(section.index, section.level, section.heading, section.path, ""),
        mapping_path=mapping_path,
    )
    return techniques, channels
