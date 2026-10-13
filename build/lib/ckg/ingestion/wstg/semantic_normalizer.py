"""Conservative normalizer: a term must occur in that section, never nearby."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ckg.ingestion.wstg.section_parser import WSTGSection


@dataclass(frozen=True)
class SemanticTechniqueMention:
    technique_id: str
    locator: str


@dataclass(frozen=True)
class SemanticChannelMention:
    channel_id: str
    locator: str


@dataclass(frozen=True)
class SemanticOracleMention:
    oracle_id: str
    locator: str


@dataclass(frozen=True)
class SemanticInputSurfaceMention:
    input_surface_id: str
    locator: str


def _aliases(mapping_path: str | Path) -> dict[str, dict[str, list[str] | str]]:
    loaded = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8"))
    return {kind: dict(loaded.get(kind, {})) for kind in ("techniques", "channels", "oracles", "input_surfaces")}


def alias_conflicts(mapping_path: str | Path) -> tuple[str, ...]:
    """Report ambiguous aliases; callers must resolve configuration, not guess."""
    aliases = _aliases(mapping_path)
    conflicts: list[str] = []
    for kind, definitions in aliases.items():
        owners: dict[str, list[str]] = {}
        for identifier, item in definitions.items():
            for alias in item.get("aliases", []):
                owners.setdefault(str(alias).lower(), []).append(identifier)
        conflicts.extend(
            f"{kind}:{alias}:{','.join(sorted(ids))}"
            for alias, ids in owners.items()
            if len(ids) > 1
        )
    return tuple(sorted(conflicts))


def normalize_section(section: WSTGSection, *, mapping_path: str | Path) -> tuple[tuple[SemanticTechniqueMention, ...], tuple[SemanticChannelMention, ...], tuple[SemanticOracleMention, ...], tuple[SemanticInputSurfaceMention, ...]]:
    """Return semantic labels grounded in the exact section heading/body."""
    conflicts = alias_conflicts(mapping_path)
    if conflicts:
        raise ValueError(f"ambiguous technique aliases: {conflicts}")
    aliases = _aliases(mapping_path)
    haystack = f"{section.heading}\n{section.text}".lower()
    locator = f"/sections/{section.index}"
    techniques = tuple(
        SemanticTechniqueMention(identifier, locator)
        for identifier, item in aliases["techniques"].items()
        if any(str(alias).lower() in haystack for alias in item.get("aliases", []))
    )
    channels = tuple(
        SemanticChannelMention(identifier, locator)
        for identifier, item in aliases["channels"].items()
        if any(str(alias).lower() in haystack for alias in item.get("aliases", []))
    )
    oracles = tuple(
        SemanticOracleMention(identifier, locator)
        for identifier, item in aliases["oracles"].items()
        if any(str(alias).lower() in haystack for alias in item.get("aliases", []))
    )
    input_surfaces = tuple(
        SemanticInputSurfaceMention(identifier, locator)
        for identifier, item in aliases["input_surfaces"].items()
        if any(str(alias).lower() in haystack for alias in item.get("aliases", []))
    )
    return techniques, channels, oracles, input_surfaces
