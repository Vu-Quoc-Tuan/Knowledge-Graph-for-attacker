"""Canonical PATT vulnerability slices shared by v2 and legacy ingestion."""

import re
from dataclasses import dataclass, field


_HEADING_NORM = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class FamilySpec:
    """A payload family and its evidence signal."""

    key: str
    name: str
    detection_signal: str | None
    headings: tuple[str, ...] = ()

    @property
    def is_catch_all(self) -> bool:
        return not self.headings


@dataclass(frozen=True)
class VulnSlice:
    """PATT source and extraction policy for one CWE."""

    weakness_id: str
    patt_dir: str
    families: tuple[FamilySpec, ...]
    technology_from_filename: bool = False
    split_payloads: bool = True
    intruder_dir: str | None = None
    intruder_family: FamilySpec | None = None
    payload_markers: tuple[str, ...] = ()
    families_ordered: tuple[FamilySpec, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "families_ordered",
            tuple(sorted(self.families, key=lambda spec: spec.is_catch_all)),
        )

    def family_for(self, heading: str) -> FamilySpec | None:
        normalized = _HEADING_NORM.sub(" ", heading.lower()).strip()
        for spec in self.families_ordered:
            if spec.is_catch_all:
                return spec
            if any(pattern in normalized for pattern in spec.headings):
                return spec
        return None

    def accepts_payload(self, value: str) -> bool:
        if not self.payload_markers:
            return True
        normalized = value.casefold()
        return any(marker.casefold() in normalized for marker in self.payload_markers)


_SQLI = VulnSlice(
    weakness_id="CWE-89",
    patt_dir="SQL Injection",
    technology_from_filename=True,
    intruder_dir="Intruder",
    intruder_family=FamilySpec("sqli.generic", "Generic SQLi wordlist", "content_diff"),
    families=(
        FamilySpec("sqli.union", "UNION-based", "content_diff", ("union based",)),
        FamilySpec("sqli.error", "Error-based", "error_signature", ("error based",)),
        FamilySpec("sqli.time_blind", "Time-based blind", "time_delta", ("time based",)),
        FamilySpec("sqli.bool_blind", "Boolean-based blind", "boolean_diff", ("boolean based", "blind")),
        FamilySpec("sqli.oob", "Out-of-band", "oob_dns", ("out of band", "oast")),
        FamilySpec("sqli.stacked", "Stacked queries", "stacked_effect", ("stacked",)),
    ),
)

_XSS_FAMILY = FamilySpec("xss.generic", "Cross-site scripting", "script_execution")
_XSS = VulnSlice(
    weakness_id="CWE-79",
    patt_dir="XSS Injection",
    intruder_dir="Intruders",
    intruder_family=_XSS_FAMILY,
    families=(_XSS_FAMILY,),
)
_CMDI_FAMILY = FamilySpec("cmdi.generic", "OS command injection", "command_output")
_CMDI = VulnSlice(
    weakness_id="CWE-78",
    patt_dir="Command Injection",
    intruder_dir="Intruder",
    intruder_family=_CMDI_FAMILY,
    families=(_CMDI_FAMILY,),
)
_SSRF = VulnSlice(
    weakness_id="CWE-918",
    patt_dir="Server Side Request Forgery",
    families=(FamilySpec("ssrf.generic", "Server-side request forgery", "oob_interaction"),),
)
_PATH_FAMILY = FamilySpec("pathtrav.generic", "Path traversal", "file_content")
_PATH = VulnSlice(
    weakness_id="CWE-22",
    patt_dir="Directory Traversal",
    intruder_dir="Intruder",
    intruder_family=_PATH_FAMILY,
    families=(_PATH_FAMILY,),
)
_UPLOAD = VulnSlice(
    weakness_id="CWE-434",
    patt_dir="Upload Insecure Files",
    split_payloads=False,
    families=(FamilySpec("upload.generic", "Unrestricted file upload", "file_execution"),),
)
_CSRF = VulnSlice(
    weakness_id="CWE-352",
    patt_dir="Cross-Site Request Forgery",
    split_payloads=False,
    families=(FamilySpec("csrf.generic", "Cross-site request forgery", "state_change"),),
)
_SSTI = VulnSlice(
    weakness_id="CWE-94",
    patt_dir="Server Side Template Injection",
    technology_from_filename=True,
    families=(FamilySpec("ssti.generic", "Server-side template injection", "template_eval"),),
)
_DESER = VulnSlice(
    weakness_id="CWE-502",
    patt_dir="Insecure Deserialization",
    technology_from_filename=True,
    families=(FamilySpec("deser.generic", "Insecure deserialization", "code_exec"),),
)
_CRLF = VulnSlice(
    weakness_id="CWE-93",
    patt_dir="CRLF Injection",
    families=(FamilySpec("crlf.generic", "CRLF injection", "response_header_injection"),),
    payload_markers=("%0d", "%0a", "%e5%98%8a", "%e5%98%8d", "嘊", "嘍"),
)


SLICES: tuple[VulnSlice, ...] = (
    _SQLI,
    _XSS,
    _CMDI,
    _SSRF,
    _PATH,
    _UPLOAD,
    _CSRF,
    _SSTI,
    _DESER,
    _CRLF,
)


__all__ = ["FamilySpec", "SLICES", "VulnSlice"]
