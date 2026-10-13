"""Preserve PATT heading tree without treating fenced code as graph payloads."""

from ckg.ingestion.wstg.section_parser import WSTGSection as PATTSection
from ckg.ingestion.wstg.section_parser import parse_sections as parse_patt_sections

__all__ = ["PATTSection", "parse_patt_sections"]
